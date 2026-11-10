package com.securetest.autoconfigure.service;

import com.securetest.autoconfigure.SecureTestProperties;
import com.securetest.autoconfigure.support.Extensions.HealthSource;
import com.securetest.autoconfigure.support.Extensions.MeterSource;
import com.securetest.core.model.ModuleCatalog;

import java.lang.management.ClassLoadingMXBean;
import java.lang.management.GarbageCollectorMXBean;
import java.lang.management.ManagementFactory;
import java.lang.management.MemoryMXBean;
import java.lang.management.MemoryPoolMXBean;
import java.lang.management.MemoryUsage;
import java.lang.management.OperatingSystemMXBean;
import java.lang.management.RuntimeMXBean;
import java.lang.management.ThreadMXBean;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Deque;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Runtime health and observability (SRS 5.3) from JVM MXBeans, Actuator health (status only) and Micrometer.
 * The low-frequency history sampler only runs while the Metrics module is enabled.
 */
public class TelemetryService {

    private final SecureTestProperties props;
    private final ModuleService modules;
    private final NotificationService notifications;
    private final AuditService audit;
    private final HealthSource health;
    private final MeterSource meters;
    private final HttpStats http = new HttpStats();
    private final Deque<Map<String, Object>> history = new ArrayDeque<>();
    private final Deque<Map<String, Object>> alerts = new ArrayDeque<>();
    private final ScheduledExecutorService sampler = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread t = new Thread(r, "securetest-metrics");
        t.setDaemon(true);
        t.setPriority(Thread.MIN_PRIORITY);
        return t;
    });
    private ScheduledFuture<?> task;
    private final Map<String, Instant> lastAlert = new LinkedHashMap<>();

    public TelemetryService(SecureTestProperties props, ModuleService modules, NotificationService notifications, AuditService audit,
                            HealthSource health, MeterSource meters) {
        this.props = props;
        this.modules = modules;
        this.notifications = notifications;
        this.audit = audit;
        this.health = health;
        this.meters = meters;
        reconcile();
    }

    /** Starts/stops the sampler to match the Metrics module toggle. */
    public synchronized void reconcile() {
        boolean on = modules.isEnabled(ModuleCatalog.METRICS);
        if (on && task == null) {
            long ms = Math.max(5000, props.getTelemetry().getSampleInterval().toMillis());
            task = sampler.scheduleAtFixedRate(this::sample, 1000, ms, TimeUnit.MILLISECONDS);
        } else if (!on && task != null) {
            task.cancel(false);
            task = null;
        }
    }

    /** True while the background metrics sampler is scheduled (only when the Runtime Metrics module is on). */
    public synchronized boolean sampling() {
        return task != null;
    }

    public boolean httpRecording() {
        return modules.isEnabled(ModuleCatalog.METRICS);
    }

    public HttpStats http() { return http; }

    private void sample() {
        try {
            Map<String, Object> s = snapshot(false);
            Map<String, Object> point = new LinkedHashMap<>();
            point.put("t", Instant.now().toString());
            @SuppressWarnings("unchecked") Map<String, Object> cpu = (Map<String, Object>) s.get("cpu");
            @SuppressWarnings("unchecked") Map<String, Object> mem = (Map<String, Object>) s.get("memory");
            @SuppressWarnings("unchecked") Map<String, Object> th = (Map<String, Object>) s.get("threads");
            @SuppressWarnings("unchecked") Map<String, Object> h = (Map<String, Object>) s.get("http");
            point.put("processCpu", cpu.get("processPercent"));
            point.put("systemCpu", cpu.get("systemPercent"));
            point.put("heapUsedMb", mem.get("heapUsedMb"));
            point.put("heapPercent", mem.get("heapPercent"));
            point.put("nonHeapUsedMb", mem.get("nonHeapUsedMb"));
            point.put("threads", th.get("live"));
            point.put("rps", h.get("ratePerSecond"));
            point.put("errorRate", h.get("errorRatePercent"));
            point.put("p95", h.get("p95Ms"));
            synchronized (history) {
                history.addLast(point);
                while (history.size() > props.getTelemetry().getHistorySize()) history.removeFirst();
            }
            threshold("cpu", num(cpu.get("processPercent")), props.getTelemetry().getCpuAlertThreshold(), "Process CPU");
            threshold("heap", num(mem.get("heapPercent")), props.getTelemetry().getHeapAlertThreshold(), "Heap usage");
            threshold("errors", num(h.get("errorRatePercent")), props.getTelemetry().getErrorRateAlertThreshold(), "HTTP 5xx error rate");
        } catch (RuntimeException ignored) {
            // never let sampling disturb the host
        }
    }

    private void threshold(String key, double value, double limit, String label) {
        if (value < limit) return;
        Instant last = lastAlert.get(key);
        if (last != null && last.isAfter(Instant.now().minusSeconds(600))) return; // 10 min cool-down
        lastAlert.put(key, Instant.now());
        String msg = String.format("%s at %.1f%% exceeds threshold %.0f%%", label, value, limit);
        Map<String, Object> a = new LinkedHashMap<>();
        a.put("at", Instant.now().toString());
        a.put("metric", key);
        a.put("message", msg);
        synchronized (alerts) {
            alerts.addFirst(a);
            while (alerts.size() > 50) alerts.removeLast();
        }
        notifications.publish("alert.threshold", msg, Map.of("metric", key));
        audit.record("system", null, "telemetry.alert", key, "ALERT", Map.of("message", msg));
    }

    private static double num(Object o) {
        return o instanceof Number n ? n.doubleValue() : -1;
    }

    public List<Map<String, Object>> history() {
        synchronized (history) {
            return new ArrayList<>(history);
        }
    }

    public List<Map<String, Object>> alerts() {
        synchronized (alerts) {
            return new ArrayList<>(alerts);
        }
    }

    public Map<String, Object> health() {
        Map<String, Object> m = new LinkedHashMap<>();
        if (health != null) {
            m.putAll(health.health());
            m.put("source", "Spring Boot Actuator");
        } else {
            m.put("status", "UP");
            m.put("source", "JVM (Actuator not present)");
        }
        return m;
    }

    public Map<String, Object> snapshot(boolean includeDetails) {
        Map<String, Object> out = new LinkedHashMap<>();
        RuntimeMXBean rt = ManagementFactory.getRuntimeMXBean();
        OperatingSystemMXBean os = ManagementFactory.getOperatingSystemMXBean();
        MemoryMXBean mem = ManagementFactory.getMemoryMXBean();
        ThreadMXBean threads = ManagementFactory.getThreadMXBean();
        ClassLoadingMXBean cl = ManagementFactory.getClassLoadingMXBean();

        out.put("timestamp", Instant.now().toString());
        out.put("uptimeSeconds", rt.getUptime() / 1000);
        out.put("startTime", Instant.ofEpochMilli(rt.getStartTime()).toString());

        Map<String, Object> cpu = new LinkedHashMap<>();
        cpu.put("availableProcessors", os.getAvailableProcessors());
        cpu.put("systemLoadAverage", os.getSystemLoadAverage() < 0 ? null : round(os.getSystemLoadAverage()));
        if (os instanceof com.sun.management.OperatingSystemMXBean sun) {
            cpu.put("processPercent", sun.getProcessCpuLoad() < 0 ? null : round(sun.getProcessCpuLoad() * 100));
            cpu.put("systemPercent", sun.getCpuLoad() < 0 ? null : round(sun.getCpuLoad() * 100));
            cpu.put("totalMemoryMb", sun.getTotalMemorySize() / 1048576);
            cpu.put("freeMemoryMb", sun.getFreeMemorySize() / 1048576);
        }
        if (os instanceof com.sun.management.UnixOperatingSystemMXBean unix) {
            cpu.put("openFileDescriptors", unix.getOpenFileDescriptorCount());
            cpu.put("maxFileDescriptors", unix.getMaxFileDescriptorCount());
        }
        out.put("cpu", cpu);

        Map<String, Object> m = new LinkedHashMap<>();
        MemoryUsage heap = mem.getHeapMemoryUsage();
        MemoryUsage nonHeap = mem.getNonHeapMemoryUsage();
        m.put("heapUsedMb", heap.getUsed() / 1048576);
        m.put("heapCommittedMb", heap.getCommitted() / 1048576);
        m.put("heapMaxMb", heap.getMax() < 0 ? null : heap.getMax() / 1048576);
        m.put("heapPercent", heap.getMax() > 0 ? round(100.0 * heap.getUsed() / heap.getMax()) : null);
        m.put("nonHeapUsedMb", nonHeap.getUsed() / 1048576);
        m.put("nonHeapCommittedMb", nonHeap.getCommitted() / 1048576);
        if (includeDetails) {
            List<Map<String, Object>> pools = new ArrayList<>();
            for (MemoryPoolMXBean p : ManagementFactory.getMemoryPoolMXBeans()) {
                MemoryUsage u = p.getUsage();
                Map<String, Object> pm = new LinkedHashMap<>();
                pm.put("name", p.getName());
                pm.put("type", p.getType().name());
                pm.put("usedMb", round(u.getUsed() / 1048576.0));
                pm.put("maxMb", u.getMax() < 0 ? null : round(u.getMax() / 1048576.0));
                pools.add(pm);
            }
            m.put("pools", pools);
        }
        out.put("memory", m);

        List<Map<String, Object>> gcs = new ArrayList<>();
        long gcCount = 0;
        long gcTime = 0;
        for (GarbageCollectorMXBean gc : ManagementFactory.getGarbageCollectorMXBeans()) {
            gcs.add(Map.of("name", gc.getName(), "count", gc.getCollectionCount(), "timeMs", gc.getCollectionTime()));
            gcCount += Math.max(0, gc.getCollectionCount());
            gcTime += Math.max(0, gc.getCollectionTime());
        }
        out.put("gc", Map.of("collectors", gcs, "totalCount", gcCount, "totalTimeMs", gcTime));

        Map<String, Object> t = new LinkedHashMap<>();
        t.put("live", threads.getThreadCount());
        t.put("daemon", threads.getDaemonThreadCount());
        t.put("peak", threads.getPeakThreadCount());
        long[] deadlocked = threads.findDeadlockedThreads();
        t.put("deadlocked", deadlocked == null ? 0 : deadlocked.length);
        out.put("threads", t);
        out.put("classes", Map.of("loaded", cl.getLoadedClassCount(), "totalLoaded", cl.getTotalLoadedClassCount(), "unloaded", cl.getUnloadedClassCount()));

        Map<String, Object> h = http.stats();
        h.put("recording", httpRecording());
        if (meters != null) h.put("micrometer", meters.httpServerRequests());
        out.put("http", h);
        if (includeDetails && meters != null) out.put("customMeters", meters.customMeters());
        out.put("health", health());
        return out;
    }

    /** Prometheus text exposition of the snapshot (behind dashboard authentication). */
    public String prometheus() {
        Map<String, Object> s = snapshot(false);
        StringBuilder sb = new StringBuilder();
        flatten("securetest", s, sb);
        return sb.toString();
    }

    @SuppressWarnings("unchecked")
    private static void flatten(String prefix, Map<String, Object> m, StringBuilder sb) {
        for (Map.Entry<String, Object> e : m.entrySet()) {
            String key = prefix + "_" + e.getKey().replaceAll("([a-z])([A-Z])", "$1_$2").toLowerCase();
            if (e.getValue() instanceof Number n) sb.append(key).append(' ').append(n).append('\n');
            else if (e.getValue() instanceof Map<?, ?> sub) flatten(key, (Map<String, Object>) sub, sb);
        }
    }

    private static double round(double d) {
        return Math.round(d * 10) / 10.0;
    }

    public void shutdown() { sampler.shutdownNow(); }

    // ------------------------------------------------------------------ HTTP metrics

    /** Lock-light ring buffer of recent request timings. */
    public static final class HttpStats {
        private static final int SIZE = 2048;
        private final long[] at = new long[SIZE];
        private final int[] ms = new int[SIZE];
        private final short[] status = new short[SIZE];
        private final AtomicInteger idx = new AtomicInteger();
        private final AtomicLong total = new AtomicLong();
        private final AtomicLong errors = new AtomicLong();

        public void record(long durationMs, int code) {
            int i = Math.floorMod(idx.getAndIncrement(), SIZE);
            at[i] = System.currentTimeMillis();
            ms[i] = (int) Math.min(Integer.MAX_VALUE, durationMs);
            status[i] = (short) code;
            total.incrementAndGet();
            if (code >= 500) errors.incrementAndGet();
        }

        public Map<String, Object> stats() {
            long now = System.currentTimeMillis();
            List<Integer> window = new ArrayList<>();
            int errs = 0;
            for (int i = 0; i < SIZE; i++) {
                if (at[i] > 0 && now - at[i] <= 60_000) {
                    window.add(ms[i]);
                    if (status[i] >= 500) errs++;
                }
            }
            int[] sorted = window.stream().mapToInt(Integer::intValue).sorted().toArray();
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("totalRequests", total.get());
            m.put("totalErrors", errors.get());
            m.put("windowSeconds", 60);
            m.put("ratePerSecond", Math.round(sorted.length / 60.0 * 100) / 100.0);
            m.put("errorRatePercent", sorted.length == 0 ? 0.0 : Math.round(1000.0 * errs / sorted.length) / 10.0);
            m.put("p50Ms", p(sorted, 50));
            m.put("p95Ms", p(sorted, 95));
            m.put("p99Ms", p(sorted, 99));
            m.put("maxMs", sorted.length == 0 ? 0 : sorted[sorted.length - 1]);
            return m;
        }

        private static int p(int[] s, int pct) {
            if (s.length == 0) return 0;
            return s[Math.max(0, Math.min(s.length - 1, (int) Math.ceil(pct / 100.0 * s.length) - 1))];
        }
    }

    static List<String> standardMeterPrefixes() {
        return Arrays.asList("jvm.", "process.", "system.", "http.", "tomcat.", "executor.", "disk.", "application.", "logback.",
                "hikaricp.", "jdbc.", "spring.", "tasks.", "cache.");
    }
}
