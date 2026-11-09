package com.securetest.adapters.builtin;

import com.securetest.core.model.Enums.Confidence;
import com.securetest.core.model.Enums.FieldType;
import com.securetest.core.model.Enums.ScanMode;
import com.securetest.core.model.Finding;
import com.securetest.core.model.ModuleCatalog;
import com.securetest.core.model.Severity;
import com.securetest.core.spi.FieldSpec;
import com.securetest.core.spi.PreflightCheck;
import com.securetest.core.spi.ScanContext;
import com.securetest.core.spi.Scanner;
import com.securetest.core.spi.ScannerDescriptor;

import java.lang.management.ManagementFactory;
import java.lang.management.MemoryMXBean;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Bounded HTTP load test (SRS 5.8). Blocked unless
 * {@code securetest.modules.performance.allow-embedded-load-generation=true}, because generating load
 * from inside the application JVM competes with the application itself. Prefer the JMeter adapter
 * or a remote worker for real load tests.
 */
public class LoadTestScanner implements Scanner {

    public static final String ID = "builtin-load-test";
    private static final int MAX_SAMPLES = 300_000;

    @Override
    public ScannerDescriptor descriptor() {
        return ScannerDescriptor.builder(ID, ModuleCatalog.PERFORMANCE, "HTTP load test")
                .purpose("Generates concurrent HTTP traffic against one endpoint for a fixed duration and reports throughput, latency "
                        + "percentiles, error rate and CPU/heap correlation, with pass/fail thresholds and baseline comparison.")
                .access("Sends repeated requests to the allowlisted target URL.")
                .mode(ScanMode.RESOURCE_INTENSIVE).requiresTarget()
                .duration("Configured duration + ramp-up").resources("Up to the configured concurrency of threads and connections")
                .prerequisite("securetest.modules.performance.allow-embedded-load-generation=true (load is generated inside this JVM)")
                .prerequisite("Target environment owner has approved the test window")
                .field(FieldSpec.required("targetUrl", "Target URL", FieldType.URL, "self:/actuator/health", "Use 'self:/path' for this app."))
                .field(FieldSpec.select("method", "HTTP method", "GET", List.of("GET", "HEAD"), "Only safe methods are supported."))
                .field(FieldSpec.number("durationSeconds", "Duration (seconds)", 30, 5, 600, ""))
                .field(FieldSpec.number("concurrency", "Concurrent users", 5, 1, 200, "Capped by securetest.modules.performance.max-concurrency."))
                .field(FieldSpec.number("rampUpSeconds", "Ramp-up (seconds)", 5, 0, 300, ""))
                .field(FieldSpec.number("thinkTimeMs", "Think time (ms)", 0, 0, 60000, "Pause between requests per user."))
                .field(FieldSpec.number("targetRps", "Throughput cap (req/s)", 0, 0, 100000, "0 = unlimited."))
                .field(FieldSpec.number("p95ThresholdMs", "p95 latency threshold (ms)", 1000, 1, 600000, "Gate fails above this."))
                .field(FieldSpec.number("maxErrorRatePct", "Max error rate (%)", 1, 0, 100, "Gate fails above this."))
                .field(FieldSpec.secret("authorization", "Authorization header value", false, "Optional secret reference."))
                .build();
    }

    @Override
    public List<PreflightCheck> preflight(ScanContext ctx) {
        List<PreflightCheck> out = new ArrayList<>();
        out.add(ctx.boolOption("_allowEmbeddedLoad", false)
                ? PreflightCheck.warn("Embedded load generation", "Allowed by policy. Load is generated inside this JVM and competes with the application.")
                : PreflightCheck.error("Embedded load generation", "Disabled by default (SRS 5.8). Set securetest.modules.performance.allow-embedded-load-generation=true "
                + "or use the JMeter adapter / a remote worker."));
        try {
            out.add(PreflightCheck.ok("Target allowlist", ctx.targets().requireAllowedUrl(url(ctx)).toString()));
        } catch (Exception e) {
            out.add(PreflightCheck.error("Target allowlist", e.getMessage()));
        }
        int maxC = ctx.intOption("_maxConcurrency", 50, 1, 1000);
        int c = ctx.intOption("concurrency", 5, 1, 200);
        if (c > maxC) out.add(PreflightCheck.error("Resource budget", "Concurrency " + c + " exceeds the configured budget of " + maxC + "."));
        else out.add(PreflightCheck.ok("Resource budget", c + " users × " + ctx.intOption("durationSeconds", 30, 5, 600) + " s"));
        return out;
    }

    private static String url(ScanContext ctx) {
        String u = ctx.option("targetUrl", "self:/actuator/health");
        if (u.startsWith("self:")) u = ctx.targets().selfBaseUrl() + u.substring(5);
        return u;
    }

    @Override
    public void scan(ScanContext ctx) throws Exception {
        if (!ctx.boolOption("_allowEmbeddedLoad", false)) throw new IllegalStateException("Embedded load generation is disabled by policy.");
        URI target = ctx.targets().requireAllowedUrl(url(ctx));
        int duration = ctx.intOption("durationSeconds", 30, 5, 600);
        int concurrency = Math.min(ctx.intOption("concurrency", 5, 1, 200), ctx.intOption("_maxConcurrency", 50, 1, 1000));
        int ramp = ctx.intOption("rampUpSeconds", 5, 0, 300);
        int think = ctx.intOption("thinkTimeMs", 0, 0, 60000);
        int rps = ctx.intOption("targetRps", 0, 0, 100000);
        String method = ctx.option("method", "GET").equals("HEAD") ? "HEAD" : "GET";
        String auth = ctx.secret("authorization");

        HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).followRedirects(HttpClient.Redirect.NEVER).build();
        HttpRequest.Builder rb = HttpRequest.newBuilder(target).timeout(Duration.ofSeconds(30)).method(method, HttpRequest.BodyPublishers.noBody())
                .header("User-Agent", "SecureTest-Load/1.0");
        if (auth != null && !auth.isBlank()) rb.header("Authorization", auth);
        HttpRequest request = rb.build();

        long start = System.nanoTime();
        long end = start + TimeUnit.SECONDS.toNanos(duration + ramp);
        ConcurrentLinkedQueue<long[]> samples = new ConcurrentLinkedQueue<>(); // {offsetMs, latencyMs, status}
        AtomicInteger sampleCount = new AtomicInteger();
        AtomicLong nextSlot = new AtomicLong(start);
        long slotNanos = rps > 0 ? 1_000_000_000L / rps : 0;
        ExecutorService pool = Executors.newFixedThreadPool(concurrency, r -> {
            Thread t = new Thread(r, "securetest-load");
            t.setDaemon(true);
            t.setPriority(Thread.MIN_PRIORITY);
            return t;
        });
        CountDownLatch done = new CountDownLatch(concurrency);
        for (int u = 0; u < concurrency; u++) {
            long delayNanos = concurrency <= 1 ? 0 : TimeUnit.SECONDS.toNanos(ramp) * u / concurrency;
            pool.submit(() -> {
                try {
                    long begin = start + delayNanos;
                    while (System.nanoTime() < begin) Thread.sleep(10);
                    while (System.nanoTime() < end && !ctx.cancelled()) {
                        if (slotNanos > 0) {
                            long slot = nextSlot.getAndAdd(slotNanos);
                            long wait = slot - System.nanoTime();
                            if (wait > 0) TimeUnit.NANOSECONDS.sleep(wait);
                        }
                        long t0 = System.nanoTime();
                        int status;
                        try {
                            status = client.send(request, HttpResponse.BodyHandlers.discarding()).statusCode();
                        } catch (java.io.IOException e) {
                            status = 0;
                        }
                        long t1 = System.nanoTime();
                        if (sampleCount.incrementAndGet() <= MAX_SAMPLES) {
                            samples.add(new long[] {(t0 - start) / 1_000_000, (t1 - t0) / 1_000_000, status});
                        }
                        if (think > 0) Thread.sleep(think);
                    }
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                } finally {
                    done.countDown();
                }
            });
        }
        // resource correlation sampler (this thread)
        List<double[]> resources = new ArrayList<>(); // {second, processCpu%, heapMb}
        MemoryMXBean mem = ManagementFactory.getMemoryMXBean();
        java.lang.management.OperatingSystemMXBean os = ManagementFactory.getOperatingSystemMXBean();
        int sec = 0;
        while (!done.await(1, TimeUnit.SECONDS)) {
            sec++;
            double cpu = os instanceof com.sun.management.OperatingSystemMXBean sun ? Math.max(0, sun.getProcessCpuLoad() * 100) : -1;
            resources.add(new double[] {sec, cpu, mem.getHeapMemoryUsage().getUsed() / 1048576.0});
            ctx.progress(Math.min(95, 100 * sec / Math.max(1, duration + ramp)), sampleCount.get() + " requests sent");
            if (ctx.cancelled()) pool.shutdownNow();
        }
        pool.shutdownNow();
        analyze(ctx, target.toString(), new ArrayList<>(samples), resources, duration + ramp);
    }

    private void analyze(ScanContext ctx, String target, List<long[]> samples, List<double[]> resources, int seconds) {
        int n = samples.size();
        long[] lat = samples.stream().mapToLong(s -> s[1]).sorted().toArray();
        long errors = samples.stream().filter(s -> s[2] == 0 || s[2] >= 500).count();
        long clientErrors = samples.stream().filter(s -> s[2] >= 400 && s[2] < 500).count();
        Map<String, Object> summary = new LinkedHashMap<>();
        summary.put("target", target);
        summary.put("requests", n);
        summary.put("errors", errors);
        summary.put("clientErrors4xx", clientErrors);
        summary.put("errorRatePct", n == 0 ? 0 : Math.round(10000.0 * errors / n) / 100.0);
        summary.put("throughputRps", Math.round(10.0 * n / Math.max(1, seconds)) / 10.0);
        summary.put("minMs", n == 0 ? 0 : lat[0]);
        summary.put("avgMs", n == 0 ? 0 : Math.round(Arrays.stream(lat).average().orElse(0)));
        summary.put("p50Ms", pct(lat, 50));
        summary.put("p90Ms", pct(lat, 90));
        summary.put("p95Ms", pct(lat, 95));
        summary.put("p99Ms", pct(lat, 99));
        summary.put("maxMs", n == 0 ? 0 : lat[n - 1]);
        int p95Threshold = ctx.intOption("p95ThresholdMs", 1000, 1, 600000);
        int maxErr = ctx.intOption("maxErrorRatePct", 1, 0, 100);
        boolean latencyOk = pct(lat, 95) <= p95Threshold;
        boolean errorsOk = (double) summary.get("errorRatePct") <= maxErr;
        summary.put("gate", latencyOk && errorsOk ? "PASS" : "FAIL");
        summary.put("thresholds", Map.of("p95Ms", p95Threshold, "maxErrorRatePct", maxErr));
        ctx.putResult("loadSummary", summary);

        // per-second timeline
        Map<Long, List<long[]>> bySecond = new java.util.TreeMap<>();
        for (long[] s : samples) bySecond.computeIfAbsent(s[0] / 1000, k -> new ArrayList<>()).add(s);
        List<Map<String, Object>> timeline = new ArrayList<>();
        for (Map.Entry<Long, List<long[]>> e : bySecond.entrySet()) {
            long[] l = e.getValue().stream().mapToLong(s -> s[1]).sorted().toArray();
            Map<String, Object> pt = new LinkedHashMap<>();
            pt.put("t", e.getKey());
            pt.put("rps", l.length);
            pt.put("errors", e.getValue().stream().filter(s -> s[2] == 0 || s[2] >= 500).count());
            pt.put("p95", pct(l, 95));
            int idx = (int) Math.min(resources.size() - 1, Math.max(0, e.getKey()));
            if (!resources.isEmpty()) {
                pt.put("cpu", Math.round(resources.get(idx)[1] * 10) / 10.0);
                pt.put("heapMb", Math.round(resources.get(idx)[2]));
            }
            timeline.add(pt);
        }
        ctx.putResult("loadTimeline", timeline);

        if (!latencyOk) {
            ctx.report(Finding.of(ModuleCatalog.PERFORMANCE, ID, "PERF-P95", "p95 latency " + pct(lat, 95) + " ms exceeds " + p95Threshold + " ms", Severity.MEDIUM)
                    .description("Under the configured load the 95th percentile response time exceeded the threshold.")
                    .evidence(summary.toString()).asset(target).category("Performance").confidence(Confidence.HIGH)
                    .remediation("Profile the endpoint (database queries, N+1, blocking I/O, pool sizes) and compare with the baseline run."));
        }
        if (!errorsOk) {
            ctx.report(Finding.of(ModuleCatalog.PERFORMANCE, ID, "PERF-ERRORS", "Error rate " + summary.get("errorRatePct") + "% exceeds " + maxErr + "%", Severity.HIGH)
                    .description(errors + " of " + n + " requests failed (5xx or connection errors) under load.")
                    .evidence(summary.toString()).asset(target).category("Performance").confidence(Confidence.HIGH)
                    .remediation("Check application logs for saturation (thread/connection pools, timeouts, OOM) at the failure time."));
        }
    }

    static long pct(long[] sorted, int p) {
        if (sorted.length == 0) return 0;
        int idx = (int) Math.ceil(p / 100.0 * sorted.length) - 1;
        return sorted[Math.max(0, Math.min(sorted.length - 1, idx))];
    }
}
