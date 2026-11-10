package com.securetest.autoconfigure.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.securetest.autoconfigure.SecureTestProperties;
import com.securetest.autoconfigure.security.ApiException;
import com.securetest.autoconfigure.security.Rbac.Permission;
import com.securetest.autoconfigure.security.SecureTestPrincipal;
import com.securetest.autoconfigure.support.AppContext;
import com.securetest.autoconfigure.support.LocalStore;
import com.securetest.autoconfigure.support.SecretResolver;
import com.securetest.core.model.Enums.FieldType;
import com.securetest.core.model.Enums.JobStatus;
import com.securetest.core.model.Enums.ScanMode;
import com.securetest.core.model.Finding;
import com.securetest.core.model.ModuleCatalog;
import com.securetest.core.model.ScanJob;
import com.securetest.core.model.Severity;
import com.securetest.core.spi.FieldSpec;
import com.securetest.core.spi.PreflightCheck;
import com.securetest.core.spi.ScanRejectedException;
import com.securetest.core.spi.Scanner;
import com.securetest.core.spi.ScannerDescriptor;
import com.securetest.core.spi.TargetGuard;
import com.securetest.core.util.AllowlistCommandRunner;
import com.securetest.core.util.AllowlistTargetGuard;
import com.securetest.core.util.GuardedHttpProbe;
import com.securetest.core.util.Redactor;
import com.securetest.migration.GitWorkspace;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Asynchronous scan orchestration (SRS 4.3, 15): validation, scope authorization, preflight, confirmation,
 * approval, bounded execution off the request threads, timeout, cancellation, durable terminal states and
 * idempotency keys.
 */
public class JobService {

    private static final Logger log = LoggerFactory.getLogger(JobService.class);

    public record SubmitRequest(String scannerId, Map<String, String> options, boolean confirmed, String profileName, String idempotencyKey) { }

    private record Validated(Map<String, String> options, Map<String, String> displayOptions, Map<String, String> secrets) { }

    private final SecureTestProperties props;
    private final ScannerRegistry registry;
    private final ModuleService modules;
    private final FindingService findings;
    private final AuditService audit;
    private final NotificationService notifications;
    private final AppContext app;
    private final SecretResolver secrets;
    private final LocalStore store;
    private final GitWorkspace git;
    private final Map<String, ScanJob> jobs = new ConcurrentHashMap<>();
    private final Map<String, Future<?>> futures = new ConcurrentHashMap<>();
    private final Map<String, RuntimeScanContext> contexts = new ConcurrentHashMap<>();
    private final Map<String, String> idempotency = new ConcurrentHashMap<>();
    private final ThreadPoolExecutor executor;
    private final ScheduledExecutorService watchdog;
    private final AtomicInteger seq = new AtomicInteger();

    public JobService(SecureTestProperties props, ScannerRegistry registry, ModuleService modules, FindingService findings,
                      AuditService audit, NotificationService notifications, AppContext app, SecretResolver secrets,
                      LocalStore store, GitWorkspace git) {
        this.props = props;
        this.registry = registry;
        this.modules = modules;
        this.findings = findings;
        this.audit = audit;
        this.notifications = notifications;
        this.app = app;
        this.secrets = secrets;
        this.store = store;
        this.git = git;
        int threads = Math.max(1, props.getExecution().getMaxConcurrentJobs());
        this.executor = new ThreadPoolExecutor(threads, threads, 60, TimeUnit.SECONDS, new LinkedBlockingQueue<>(), r -> {
            Thread t = new Thread(r, "securetest-job-" + seq.incrementAndGet());
            t.setDaemon(true);
            t.setPriority(Thread.NORM_PRIORITY - 1);
            return t;
        });
        this.executor.allowCoreThreadTimeOut(true);
        this.watchdog = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "securetest-watchdog");
            t.setDaemon(true);
            return t;
        });
        for (ScanJob j : store.load("jobs", new TypeReference<List<ScanJob>>() { }, ArrayList::new)) {
            if (!j.status.terminal()) {
                j.status = JobStatus.FAILED;
                j.error = "Interrupted by application restart";
                j.endedAt = Instant.now();
            }
            jobs.put(j.id, j);
        }
        store.register("jobs", () -> jobs.values().stream().sorted(Comparator.comparing((ScanJob j) -> j.createdAt).reversed()).limit(1000).toList());
    }

    // ------------------------------------------------------------------ validation & preflight

    TargetGuard guard() {
        return new AllowlistTargetGuard(props.getSecurity().getTargetAllowlist(), app.selfBaseUrl(), props.getSecurity().isEnforceTargetAllowlist());
    }

    private Validated validate(ScannerDescriptor d, Map<String, String> input) {
        Map<String, String> in = input == null ? Map.of() : input;
        Map<String, String> options = new LinkedHashMap<>();
        Map<String, String> display = new LinkedHashMap<>();
        Map<String, String> secretValues = new LinkedHashMap<>();
        List<String> errors = new ArrayList<>();
        TargetGuard guard = guard();
        for (FieldSpec f : d.getFields()) {
            String raw = in.get(f.key());
            if (raw != null && raw.length() > 5000) { errors.add(f.label() + " is too long"); continue; }
            if (f.type() == FieldType.SECRET) {
                if (raw == null || raw.isBlank()) {
                    if (f.required()) errors.add(f.label() + " is required");
                    continue;
                }
                if (Redactor.isReference(raw) && !secrets.isResolvable(raw)) errors.add(f.label() + ": secret reference " + raw + " could not be resolved");
                secretValues.put(f.key(), raw);
                display.put(f.key(), Redactor.mask(raw));
                continue;
            }
            String v = raw == null || raw.isBlank() ? f.defaultValue() : raw.trim();
            if (f.required() && (v == null || v.isBlank())) { errors.add(f.label() + " is required"); continue; }
            if (v == null) continue;
            switch (f.type()) {
                case NUMBER -> {
                    try {
                        int n = Integer.parseInt(v);
                        if ((f.min() != null && n < f.min()) || (f.max() != null && n > f.max())) {
                            errors.add(f.label() + " must be between " + f.min() + " and " + f.max());
                        }
                    } catch (NumberFormatException e) {
                        errors.add(f.label() + " must be a number");
                    }
                }
                case BOOLEAN -> v = String.valueOf(Boolean.parseBoolean(v));
                case SELECT -> { if (!f.options().isEmpty() && !f.options().contains(v)) errors.add(f.label() + " must be one of " + f.options()); }
                case URL -> {
                    if (!v.equalsIgnoreCase("self") && !v.startsWith("self:")) {
                        try {
                            guard.requireAllowedUrl(v);
                        } catch (ScanRejectedException e) {
                            errors.add(f.label() + ": " + e.getMessage());
                        }
                    }
                }
                default -> { }
            }
            options.put(f.key(), v);
            display.put(f.key(), Redactor.redact(v));
        }
        if (!errors.isEmpty()) throw new ApiException(422, "invalid_configuration", "Configuration is invalid", errors);
        // internal policy flags (never user-settable)
        options.put("_allowExternalIntelligence", String.valueOf(props.getSecurity().isAllowExternalIntelligence()));
        options.put("_allowEmbeddedLoad", String.valueOf(props.module(ModuleCatalog.PERFORMANCE).isAllowEmbeddedLoadGeneration()));
        options.put("_maxConcurrency", String.valueOf(props.module(ModuleCatalog.PERFORMANCE).getMaxConcurrency()));
        return new Validated(options, display, secretValues);
    }

    private RuntimeScanContext context(ScanJob job, Validated v) {
        TargetGuard guard = guard();
        int rate = 10;
        try { rate = Integer.parseInt(v.options().getOrDefault("rate", "10")); } catch (NumberFormatException ignored) { /* default */ }
        GuardedHttpProbe http = new GuardedHttpProbe(guard, props.getExecution().getConnectTimeout(), Duration.ofSeconds(30), rate);
        AllowlistCommandRunner commands = new AllowlistCommandRunner(new HashSet<>(props.getExecution().getAllowedCommands()));
        return new RuntimeScanContext(job, v.options(), v.secrets(), secrets, app.sourceRoot(), guard, http, commands, app.info(),
                store.dir().resolve("artifacts").resolve(job.id));
    }

    public List<PreflightCheck> preflight(String scannerId, Map<String, String> options) {
        Scanner scanner = registry.get(scannerId);
        ScannerDescriptor d = scanner.descriptor();
        List<PreflightCheck> checks = new ArrayList<>();
        checks.add(modules.isEnabled(d.getModuleId()) ? PreflightCheck.ok("Module", d.getModuleId() + " is enabled")
                : PreflightCheck.error("Module", "Module '" + d.getModuleId() + "' is disabled. Enable it first."));
        Validated v;
        try {
            v = validate(d, options);
        } catch (ApiException e) {
            for (Object detail : e.details()) checks.add(PreflightCheck.error("Configuration", String.valueOf(detail)));
            return checks;
        }
        if (d.isRequiresSourceRoot()) {
            checks.add(app.sourceRoot().isPresent() ? PreflightCheck.ok("Workspace", app.sourceRoot().get().toString())
                    : PreflightCheck.error("Workspace", "No source workspace (securetest.workspace.source-root)."));
        }
        if (d.getMode() == ScanMode.ACTIVE) {
            checks.add(props.getSecurity().isRequireApprovalForActiveScans()
                    ? PreflightCheck.warn("Approval", "Active scan: requires approval by a user with APPROVE permission.")
                    : PreflightCheck.warn("Approval", "Active scan approval is disabled by configuration."));
        }
        ScanJob probe = new ScanJob();
        probe.id = "preflight";
        try {
            checks.addAll(scanner.preflight(context(probe, v)));
        } catch (RuntimeException e) {
            checks.add(PreflightCheck.error("Preflight", Redactor.redact(String.valueOf(e.getMessage()))));
        }
        int running = (int) jobs.values().stream().filter(j -> !j.status.terminal()).count();
        checks.add(running >= props.getExecution().getMaxQueuedJobs() ? PreflightCheck.error("Capacity", "Job queue is full")
                : PreflightCheck.ok("Capacity", running + " active job(s), limit " + props.getExecution().getMaxConcurrentJobs() + " concurrent"));
        return checks;
    }

    // ------------------------------------------------------------------ submit / approve / cancel

    public ScanJob submit(SubmitRequest req, SecureTestPrincipal principal) {
        if (req.idempotencyKey() != null && !req.idempotencyKey().isBlank()) {
            String existing = idempotency.get(principal.name() + "|" + req.idempotencyKey());
            if (existing != null && jobs.containsKey(existing)) return jobs.get(existing);
        }
        Scanner scanner = registry.get(req.scannerId());
        ScannerDescriptor d = scanner.descriptor();
        if (!modules.isEnabled(d.getModuleId())) {
            throw ApiException.conflict("Module '" + d.getModuleId() + "' is disabled. Enable it before running scans.");
        }
        long active = jobs.values().stream().filter(j -> !j.status.terminal()).count();
        if (active >= props.getExecution().getMaxQueuedJobs()) throw new ApiException(429, "queue_full", "Too many queued jobs; try again later.");
        Validated v = validate(d, req.options());
        if (d.isRequiresConfirmation() && !req.confirmed()) {
            throw new ApiException(400, "confirmation_required", "This is a " + d.getMode() + " operation: explicit confirmation is required.");
        }
        ScanJob job = new ScanJob();
        job.id = "S-" + Instant.now().toEpochMilli() + "-" + UUID.randomUUID().toString().substring(0, 4);
        job.moduleId = d.getModuleId();
        job.scannerId = d.getId();
        job.scannerName = d.getName();
        job.toolVersion = d.getToolName() + " " + d.getToolVersion();
        job.profileName = req.profileName();
        job.requestedBy = principal.name();
        job.idempotencyKey = req.idempotencyKey();
        job.createdAt = Instant.now();
        job.options = v.displayOptions();
        job.executionLocation = d.getLocation().name();
        RuntimeScanContext ctx = context(job, v);
        List<PreflightCheck> checks = new ArrayList<>();
        try {
            checks.addAll(scanner.preflight(ctx));
        } catch (RuntimeException e) {
            checks.add(PreflightCheck.error("Preflight", Redactor.redact(String.valueOf(e.getMessage()))));
        }
        if (d.isRequiresSourceRoot() && app.sourceRoot().isEmpty()) checks.add(PreflightCheck.error("Workspace", "No source workspace configured."));
        List<PreflightCheck> blocking = checks.stream().filter(PreflightCheck::blocking).toList();
        if (!blocking.isEmpty()) {
            audit.record(principal, "scan.rejected", d.getId(), "REJECTED", Map.of("reason", blocking.get(0).message()));
            throw new ApiException(422, "preflight_failed", "Preflight checks failed", checks);
        }
        jobs.put(job.id, job);
        if (req.idempotencyKey() != null && !req.idempotencyKey().isBlank()) idempotency.put(principal.name() + "|" + req.idempotencyKey(), job.id);
        boolean needsApproval = d.getMode() == ScanMode.ACTIVE && props.getSecurity().isRequireApprovalForActiveScans();
        if (needsApproval && !principal.has(Permission.APPROVE)) {
            job.status = JobStatus.AWAITING_APPROVAL;
            contexts.put(job.id, ctx);
            audit.record(principal, "scan.requested", job.id, "AWAITING_APPROVAL", Map.of("scanner", d.getId()));
            notifications.publish("approval.required", "Active scan " + d.getName() + " requested by " + principal.name() + " awaits approval (" + job.id + ")", Map.of("jobId", job.id));
        } else {
            if (needsApproval) job.approvedBy = principal.name() + " (self-approved)";
            audit.record(principal, "scan.launched", job.id, "QUEUED",
                    Map.of("scanner", d.getId(), "mode", d.getMode().name(), "confirmed", String.valueOf(req.confirmed())));
            enqueue(job, scanner, ctx);
        }
        store.markDirty("jobs");
        return job;
    }

    public ScanJob approve(String id, SecureTestPrincipal approver) {
        ScanJob job = get(id);
        if (job.status != JobStatus.AWAITING_APPROVAL) throw ApiException.conflict("Job is " + job.status);
        if (approver.name().equals(job.requestedBy)) throw ApiException.forbidden("Separation of duties: requesters cannot approve their own scans.");
        RuntimeScanContext ctx = contexts.remove(id);
        if (ctx == null) throw ApiException.conflict("Approval context expired; submit the scan again.");
        job.approvedBy = approver.name();
        audit.record(approver, "scan.approved", id, "QUEUED", Map.of("requestedBy", job.requestedBy));
        enqueue(job, registry.get(job.scannerId), ctx);
        store.markDirty("jobs");
        return job;
    }

    public ScanJob reject(String id, SecureTestPrincipal approver, String reason) {
        ScanJob job = get(id);
        if (job.status != JobStatus.AWAITING_APPROVAL) throw ApiException.conflict("Job is " + job.status);
        contexts.remove(id);
        job.status = JobStatus.REJECTED;
        job.error = "Rejected by " + approver.name() + (reason == null ? "" : ": " + reason);
        job.endedAt = Instant.now();
        audit.record(approver, "scan.rejected", id, "REJECTED", Map.of("reason", String.valueOf(reason)));
        store.markDirty("jobs");
        return job;
    }

    public ScanJob cancel(String id, SecureTestPrincipal principal) {
        ScanJob job = get(id);
        if (job.status.terminal()) throw ApiException.conflict("Job already " + job.status);
        RuntimeScanContext ctx = contexts.get(id);
        if (ctx != null) ctx.cancelled.set(true);
        Future<?> f = futures.get(id);
        if (f != null) f.cancel(true);
        if (job.status == JobStatus.QUEUED || job.status == JobStatus.AWAITING_APPROVAL) {
            job.status = JobStatus.CANCELLED;
            job.endedAt = Instant.now();
            contexts.remove(id);
        }
        job.appendLog("Cancellation requested by " + principal.name());
        audit.record(principal, "scan.cancelled", id, "OK", Map.of());
        store.markDirty("jobs");
        return job;
    }

    /** Called when a module is disabled: queued jobs are cancelled; running jobs follow the safe-cancel policy. */
    public void onModuleDisabled(String moduleId, SecureTestPrincipal principal) {
        for (ScanJob j : jobs.values()) {
            if (!moduleId.equals(j.moduleId) || j.status.terminal()) continue;
            if (j.status != JobStatus.RUNNING || props.getExecution().isCancelRunningOnDisable()) cancel(j.id, principal);
        }
    }

    private void enqueue(ScanJob job, Scanner scanner, RuntimeScanContext ctx) {
        job.status = JobStatus.QUEUED;
        contexts.put(job.id, ctx);
        futures.put(job.id, executor.submit(() -> run(job, scanner, ctx)));
    }

    private void run(ScanJob job, Scanner scanner, RuntimeScanContext ctx) {
        if (ctx.cancelled() || job.status == JobStatus.CANCELLED) return;
        job.status = JobStatus.RUNNING;
        job.startedAt = Instant.now();
        job.appendLog("Started " + job.scannerName + " on " + Thread.currentThread().getName());
        store.markDirty("jobs");
        Future<?> self = futures.get(job.id);
        var timeout = watchdog.schedule(() -> {
            ctx.cancelled.set(true);
            job.error = "Timed out after " + props.getExecution().getJobTimeout();
            if (self != null) self.cancel(true);
        }, props.getExecution().getJobTimeout().toMillis(), TimeUnit.MILLISECONDS);
        try {
            scanner.scan(ctx);
            if (ctx.cancelled()) throw new InterruptedException("cancelled");
            Optional<Path> root = app.sourceRoot();
            String rev = root.flatMap(git::head).orElse(root.isPresent() ? "workspace" : null);
            List<Finding> merged = findings.ingest(job, ctx.findings(), rev, true);
            job.findingsCount = merged.size();
            Map<String, Integer> counts = new LinkedHashMap<>();
            for (Severity s : Severity.values()) counts.put(s.name(), 0);
            merged.forEach(f -> counts.merge((f.priority == null ? f.sourceSeverity : f.priority).name(), 1, Integer::sum));
            job.severityCounts = counts;
            job.status = JobStatus.COMPLETED;
            job.progress = 100;
            job.progressMessage = "Completed with " + merged.size() + " finding(s)";
            long critical = counts.getOrDefault("CRITICAL", 0);
            if (critical > 0) {
                notifications.publish("finding.critical", job.scannerName + " found " + critical + " critical finding(s) in " + app.name(), Map.of("jobId", job.id));
            }
            notifications.publish("scan.completed", job.scannerName + " completed: " + merged.size() + " finding(s)", Map.of("jobId", job.id));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            job.status = job.error != null && job.error.startsWith("Timed out") ? JobStatus.FAILED : JobStatus.CANCELLED;
        } catch (ScanRejectedException e) {
            job.status = JobStatus.FAILED;
            job.error = e.getMessage();
        } catch (Throwable e) {
            if (ctx.cancelled()) {
                job.status = job.error != null && job.error.startsWith("Timed out") ? JobStatus.FAILED : JobStatus.CANCELLED;
            } else {
                job.status = JobStatus.FAILED;
                job.error = e.getClass().getSimpleName() + ": " + Redactor.redact(String.valueOf(e.getMessage()));
                log.warn("SecureTest scan {} failed", job.id, e);
            }
        } finally {
            timeout.cancel(false);
            job.endedAt = Instant.now();
            job.appendLog("Finished with status " + job.status + (job.error != null ? " — " + job.error : ""));
            contexts.remove(job.id);
            futures.remove(job.id);
            if (job.status != JobStatus.COMPLETED) findings.jobEnded(job);
            audit.record(job.requestedBy, null, "scan.finished", job.id, job.status.name(),
                    Map.of("scanner", job.scannerId, "findings", String.valueOf(job.findingsCount)));
            if (job.status == JobStatus.FAILED) notifications.publish("scan.failed", job.scannerName + " failed: " + job.error, Map.of("jobId", job.id));
            store.markDirty("jobs");
        }
    }

    // ------------------------------------------------------------------ queries

    public ScanJob get(String id) {
        ScanJob j = jobs.get(id);
        if (j == null) throw ApiException.notFound("Scan " + id);
        return j;
    }

    public FindingService.Page<ScanJob> list(String moduleId, String scannerId, int page, int size) {
        List<ScanJob> list = jobs.values().stream()
                .filter(j -> moduleId == null || moduleId.equals(j.moduleId))
                .filter(j -> scannerId == null || scannerId.equals(j.scannerId))
                .sorted(Comparator.comparing((ScanJob j) -> j.createdAt).reversed()).toList();
        int from = Math.min(list.size(), page * size);
        return new FindingService.Page<>(list.subList(from, Math.min(list.size(), from + size)), list.size(), page, size);
    }

    public List<ScanJob> all() { return new ArrayList<>(jobs.values()); }

    public Optional<ScanJob> latest(String scannerId, JobStatus status) {
        return jobs.values().stream().filter(j -> j.scannerId.equals(scannerId) && (status == null || j.status == status))
                .max(Comparator.comparing(j -> j.createdAt));
    }

    public Optional<ScanJob> latestForModule(String moduleId) {
        return jobs.values().stream().filter(j -> moduleId.equals(j.moduleId)).max(Comparator.comparing(j -> j.createdAt));
    }

    public Path artifact(String jobId, String name) {
        ScanJob j = get(jobId);
        if (!j.artifacts.contains(name)) throw ApiException.notFound("Artifact " + name);
        Path p = store.dir().resolve("artifacts").resolve(jobId).resolve(name);
        if (!Files.exists(p)) throw ApiException.notFound("Artifact file " + name);
        return p;
    }

    public int activeCount() {
        return (int) jobs.values().stream().filter(j -> !j.status.terminal()).count();
    }

    public int housekeeping(Duration retention) {
        Instant cutoff = Instant.now().minus(retention);
        List<String> old = jobs.values().stream().filter(j -> j.status.terminal() && j.createdAt.isBefore(cutoff)).map(j -> j.id).toList();
        for (String id : old) {
            jobs.remove(id);
            Path dir = store.dir().resolve("artifacts").resolve(id);
            if (Files.isDirectory(dir)) {
                try (var s = Files.walk(dir)) {
                    s.sorted(Comparator.reverseOrder()).forEach(p -> p.toFile().delete());
                } catch (Exception ignored) {
                    // best effort
                }
            }
        }
        if (!old.isEmpty()) store.markDirty("jobs");
        return old.size();
    }

    public void shutdown() {
        contexts.values().forEach(c -> c.cancelled.set(true));
        executor.shutdownNow();
        watchdog.shutdownNow();
        for (ScanJob j : jobs.values()) {
            if (!j.status.terminal()) {
                j.status = JobStatus.CANCELLED;
                j.error = "Application shutdown";
                j.endedAt = Instant.now();
            }
        }
        store.markDirty("jobs");
    }
}
