package com.securetest.worker;

import com.securetest.core.spi.Scanner;
import com.securetest.worker.sandbox.Sandbox;
import com.securetest.worker.sandbox.SandboxProtocol;
import com.securetest.worker.sandbox.SandboxProtocol.Request;
import com.securetest.worker.sandbox.SandboxProtocol.Result;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.SmartLifecycle;
import org.springframework.stereotype.Component;

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Pull loop: register with the control plane, claim jobs for the scanners this worker serves, run each in the
 * sandbox while sending lease heartbeats, then post the normalized findings back.
 */
@Component
public class JobRunner implements SmartLifecycle {

    private static final Logger log = LoggerFactory.getLogger(JobRunner.class);
    public static final String VERSION = "1.0.1";

    private final WorkerProperties props;
    private final WorkerScanners.Catalog catalog;
    private final ControlPlaneClient client;
    private final Sandbox sandbox;
    private final String workerId;
    private final Semaphore slots;
    private final AtomicBoolean running = new AtomicBoolean();
    private final AtomicInteger completed = new AtomicInteger();
    private volatile boolean registered;
    private ScheduledExecutorService scheduler;
    private ExecutorService pool;

    public JobRunner(WorkerProperties props, WorkerScanners.Catalog catalog) {
        this.props = props;
        this.catalog = catalog;
        this.client = new ControlPlaneClient(props.getControlPlaneUrl(), props.getToken());
        this.sandbox = Sandbox.create(props.getSandbox());
        this.workerId = props.getId() != null && !props.getId().isBlank() ? props.getId() : defaultId();
        this.slots = new Semaphore(Math.max(1, props.getConcurrency()));
        if (props.getAllowedTargets().isEmpty()) {
            log.warn("securetest.worker.allowed-targets is empty: every scan will be rejected by the sandbox target guard.");
        }
    }

    private static String defaultId() {
        String host;
        try {
            host = InetAddress.getLocalHost().getHostName();
        } catch (Exception e) {
            host = "worker";
        }
        return (host.replaceAll("[^\\w.-]", "-") + "-" + UUID.randomUUID().toString().substring(0, 8));
    }

    public String workerId() { return workerId; }
    public int completedJobs() { return completed.get(); }

    @Override
    public void start() {
        if (!running.compareAndSet(false, true)) return;
        scheduler = Executors.newScheduledThreadPool(2, r -> daemon(r, "securetest-worker-poll"));
        pool = Executors.newFixedThreadPool(Math.max(1, props.getConcurrency()), r -> daemon(r, "securetest-worker-job"));
        scheduler.scheduleWithFixedDelay(this::registerQuietly, 0, 60, TimeUnit.SECONDS);
        scheduler.scheduleWithFixedDelay(this::poll, 1000, Math.max(200, props.getPollInterval().toMillis()), TimeUnit.MILLISECONDS);
        log.info("SecureTest worker {} started: sandbox={}, scanners={}", workerId, sandbox.mode(), catalog.scanners().keySet());
    }

    private static Thread daemon(Runnable r, String name) {
        Thread t = new Thread(r, name);
        t.setDaemon(true);
        return t;
    }

    private void registerQuietly() {
        try {
            List<Map<String, Object>> scanners = new ArrayList<>();
            for (Scanner s : catalog.scanners().values()) {
                var d = s.descriptor();
                scanners.add(Map.of("id", d.getId(), "moduleId", d.getModuleId(), "name", d.getName(), "mode", d.getMode().name()));
            }
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("workerId", workerId);
            body.put("name", props.getName() == null ? workerId : props.getName());
            body.put("version", VERSION);
            body.put("sandbox", sandbox.mode());
            body.put("scanners", scanners);
            client.register(body);
            if (!registered) log.info("Registered with control plane {}", props.getControlPlaneUrl());
            registered = true;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } catch (Exception e) {
            log.warn("Worker registration failed: {}", e.getMessage());
        }
    }

    void poll() {
        if (!registered || !running.get()) return;
        while (slots.tryAcquire()) {
            Map<String, Object> job;
            try {
                job = client.claim(Map.of("workerId", workerId, "scanners", new ArrayList<>(catalog.scanners().keySet()))).orElse(null);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                slots.release();
                return;
            } catch (Exception e) {
                log.warn("Claiming a job failed: {}", e.getMessage());
                slots.release();
                return;
            }
            if (job == null) {
                slots.release();
                return;
            }
            pool.submit(() -> {
                try {
                    execute(job);
                } finally {
                    slots.release();
                }
            });
        }
    }

    @SuppressWarnings("unchecked")
    private void execute(Map<String, Object> job) {
        String jobId = (String) job.get("jobId");
        String scannerId = (String) job.get("scannerId");
        log.info("Running job {} ({}) against {}", jobId, scannerId, job.get("targetUrl"));
        Scanner scanner = catalog.get(scannerId);
        Result result;
        AtomicBoolean cancel = new AtomicBoolean();
        AtomicReference<String> progress = new AtomicReference<>("0\tStarting sandbox");
        var beat = scheduler.scheduleWithFixedDelay(() -> heartbeat(jobId, progress.get(), cancel),
                0, Math.max(1, props.getHeartbeatInterval().toSeconds()), TimeUnit.SECONDS);
        try {
            if (scanner == null) {
                result = Result.failed("Scanner " + scannerId + " is not available on worker " + workerId);
            } else {
                Map<String, Object> app = (Map<String, Object>) job.getOrDefault("application", Map.of());
                Map<String, String> options = new LinkedHashMap<>();
                Object rawOptions = job.get("options");
                if (rawOptions instanceof Map<?, ?> m) m.forEach((k, v) -> options.put(String.valueOf(k), v == null ? "" : String.valueOf(v)));
                Request request = new Request(jobId, scannerId, scanner.getClass().getName(), (String) job.get("targetUrl"), options,
                        props.getAllowedTargets(), props.getAllowedCommands(), props.getMaxRequestsPerSecond(),
                        new SandboxProtocol.App((String) app.get("serviceId"), (String) app.get("name"), (String) app.get("environment")));
                result = sandbox.run(request, (p, msg) -> progress.set(p + "\t" + msg), cancel::get);
            }
        } catch (Exception e) {
            result = Result.failed("Worker error: " + e.getMessage());
        } finally {
            beat.cancel(false);
        }
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("workerId", workerId);
        body.put("status", result.status);
        body.put("error", result.error);
        body.put("findings", result.findings);
        Map<String, Object> results = new LinkedHashMap<>(result.results);
        results.put("durationMs", result.durationMs);
        results.put("sandbox", sandbox.mode());
        body.put("results", results);
        body.put("log", result.log);
        for (int attempt = 1; attempt <= 3; attempt++) {
            try {
                client.complete(jobId, body);
                completed.incrementAndGet();
                log.info("Job {} finished: {} ({} findings)", jobId, result.status, result.findings.size());
                return;
            } catch (ControlPlaneClient.ControlPlaneException e) {
                log.warn("Control plane rejected the result of job {}: {}", jobId, e.getMessage());
                return; // lease lost or job cancelled; retrying will not help
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            } catch (Exception e) {
                log.warn("Posting result of job {} failed (attempt {}): {}", jobId, attempt, e.getMessage());
                try {
                    Thread.sleep(2000L * attempt);
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    return;
                }
            }
        }
    }

    private void heartbeat(String jobId, String progress, AtomicBoolean cancel) {
        try {
            String[] parts = progress.split("\t", 2);
            Map<String, Object> r = client.heartbeat(jobId, Map.of("workerId", workerId,
                    "progress", Integer.parseInt(parts[0]), "message", parts.length > 1 ? parts[1] : ""));
            if (Boolean.TRUE.equals(r.get("cancelRequested"))) cancel.set(true);
        } catch (ControlPlaneClient.ControlPlaneException e) {
            if (e.status == 409 || e.status == 404) cancel.set(true); // lease lost: stop wasting work
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } catch (Exception e) {
            log.debug("Heartbeat for job {} failed: {}", jobId, e.getMessage());
        }
    }

    @Override
    public void stop() {
        if (!running.compareAndSet(true, false)) return;
        scheduler.shutdownNow();
        pool.shutdown();
        try {
            if (!pool.awaitTermination(30, TimeUnit.SECONDS)) pool.shutdownNow();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            pool.shutdownNow();
        }
    }

    @Override public boolean isRunning() { return running.get(); }
}
