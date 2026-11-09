package com.securetest.controlplane.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.securetest.controlplane.ControlPlaneProperties;
import com.securetest.controlplane.security.ApiException;
import com.securetest.controlplane.security.Caller;
import com.securetest.controlplane.security.Role.Permission;
import com.securetest.controlplane.service.TenantAccess.Scope;
import com.securetest.controlplane.store.AuditStore;
import com.securetest.controlplane.store.InventoryStore;
import com.securetest.controlplane.store.InventoryStore.Application;
import com.securetest.controlplane.store.InventoryStore.Environment;
import com.securetest.controlplane.store.JobStore;
import com.securetest.controlplane.store.JobStore.Job;
import com.securetest.controlplane.store.WorkerStore;
import com.securetest.core.model.Enums.JobStatus;
import com.securetest.core.model.Finding;
import com.securetest.core.model.Severity;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.http.HttpStatus;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Remote scan job queue (SRS "Embedded + Remote Worker" profile): users enqueue, workers claim with a lease,
 * report progress through heartbeats and post normalized findings back.
 */
@Service
public class JobService {

    private static final Logger log = LoggerFactory.getLogger(JobService.class);
    private static final Pattern SECRET_KEY = Pattern.compile("(?i).*(password|passwd|secret|token|apikey|api_key|credential|private).*");
    private static final Pattern SCANNER_ID = Pattern.compile("[\\w.-]{1,100}");

    public record CreateJob(String applicationId, String serviceId, String environment, String scannerId, String targetUrl,
                            Map<String, String> options, boolean confirmed, String idempotencyKey) { }

    public record ScannerInfo(String id, String moduleId, String name, String mode) { }

    public record WorkerRegistration(String workerId, String name, String version, String sandbox, List<ScannerInfo> scanners) { }

    public record Completion(String workerId, String status, String error, List<Finding> findings, Map<String, Object> results,
                             List<String> log) { }

    private final JobStore jobs;
    private final InventoryStore inventory;
    private final WorkerStore workers;
    private final FindingIngestService ingest;
    private final AuditStore audit;
    private final ControlPlaneProperties props;
    private final ObjectMapper mapper;

    public JobService(JobStore jobs, InventoryStore inventory, WorkerStore workers, FindingIngestService ingest,
                      AuditStore audit, ControlPlaneProperties props, ObjectMapper mapper) {
        this.jobs = jobs;
        this.inventory = inventory;
        this.workers = workers;
        this.ingest = ingest;
        this.audit = audit;
        this.props = props;
        this.mapper = mapper;
    }

    // ================================================================== user side

    public Map<String, Object> create(Scope scope, Caller caller, CreateJob req) {
        if (req == null || req.scannerId() == null || !SCANNER_ID.matcher(req.scannerId()).matches()) {
            throw ApiException.badRequest("scannerId is required");
        }
        if (req.idempotencyKey() != null && !req.idempotencyKey().isBlank()) {
            Optional<Job> previous = jobs.findByIdempotencyKey(scope.tenantId(), req.idempotencyKey());
            if (previous.isPresent()) return view(previous.get());
        }
        Application app = (req.applicationId() != null
                ? inventory.findApplication(scope.tenantId(), req.applicationId())
                : req.serviceId() != null ? inventory.findApplicationByServiceId(scope.tenantId(), req.serviceId()) : Optional.<Application>empty())
                .orElseThrow(() -> ApiException.notFound("Application"));
        Environment env = (req.environment() != null && !req.environment().isBlank()
                ? inventory.findEnvironment(scope.tenantId(), app.id(), req.environment())
                : inventory.latestEnvironment(scope.tenantId(), app.id()))
                .orElseThrow(() -> ApiException.notFound("Environment"));

        String target = validateTarget(req.targetUrl());
        Map<String, String> options = new LinkedHashMap<>();
        if (req.options() != null) {
            if (req.options().size() > 100) throw ApiException.badRequest("Too many options");
            req.options().forEach((k, v) -> {
                if (k == null || SECRET_KEY.matcher(k).matches()) {
                    throw ApiException.badRequest("Option '" + k + "' looks like a credential. Remote jobs never carry secrets; "
                            + "configure them on the worker or the target instead.");
                }
                options.put(k, v == null ? "" : v.length() > 4000 ? v.substring(0, 4000) : v);
            });
        }

        // Mode comes from the scanner descriptors advertised by the worker fleet; unknown scanners are treated
        // as active so they always need APPROVE + explicit confirmation (SRS 6.2 safety rules).
        ScannerInfo info = scannerCatalog().get(req.scannerId());
        String mode = info == null ? "ACTIVE" : info.mode();
        if ("PASSIVE".equals(mode)) {
            requirePermission(caller, Permission.EXECUTE);
        } else {
            requirePermission(caller, Permission.APPROVE);
            if (!req.confirmed()) {
                throw new ApiException(HttpStatus.PRECONDITION_REQUIRED, "Scanner '" + req.scannerId() + "' is "
                        + mode.toLowerCase(Locale.ROOT).replace('_', '-') + " (or not advertised by any worker); set confirmed=true "
                        + "to confirm you are authorized to test " + target);
            }
        }

        String id = com.securetest.controlplane.store.Rows.newId();
        try {
            jobs.insert(id, scope.tenantId(), app.id(), env.id(), req.scannerId(), info == null ? null : info.moduleId(), target,
                    write(options), scope.actor(), blankToNull(req.idempotencyKey()), props.getJobs().getMaxAttempts());
        } catch (DuplicateKeyException e) {
            return jobs.findByIdempotencyKey(scope.tenantId(), req.idempotencyKey()).map(this::view).orElseThrow();
        }
        audit.append(scope.tenantId(), scope.actor(), "SCAN_QUEUED", "job:" + id,
                req.scannerId() + " -> " + target + " (" + app.serviceId() + "/" + env.name() + ", mode " + mode + ")");
        return view(jobs.find(scope.tenantId(), id).orElseThrow());
    }

    private static void requirePermission(Caller caller, Permission p) {
        if (!caller.has(p)) throw ApiException.forbidden("Missing permission " + p);
    }

    static String validateTarget(String url) {
        if (url == null || url.isBlank()) throw ApiException.badRequest("targetUrl is required");
        URI uri;
        try {
            uri = URI.create(url.trim());
        } catch (IllegalArgumentException e) {
            throw ApiException.badRequest("Invalid targetUrl");
        }
        String scheme = uri.getScheme() == null ? "" : uri.getScheme().toLowerCase(Locale.ROOT);
        if (!scheme.equals("http") && !scheme.equals("https")) throw ApiException.badRequest("targetUrl must be http or https");
        if (uri.getUserInfo() != null) throw ApiException.badRequest("Credentials in targetUrl are not allowed");
        if (uri.getHost() == null) throw ApiException.badRequest("targetUrl needs a host");
        if (url.length() > 2000) throw ApiException.badRequest("targetUrl too long");
        return url.trim();
    }

    public Map<String, Object> get(Scope scope, String id) {
        return jobs.find(scope.tenantId(), id).map(this::view).orElseThrow(() -> ApiException.notFound("Scan job"));
    }

    public List<Map<String, Object>> list(Scope scope, String applicationId, int limit) {
        return jobs.list(scope.tenantId(), applicationId, Math.max(1, Math.min(500, limit))).stream().map(this::view).toList();
    }

    public Map<String, Object> cancel(Scope scope, String id) {
        Job job = jobs.find(scope.tenantId(), id).orElseThrow(() -> ApiException.notFound("Scan job"));
        if (job.status().terminal()) throw new ApiException(HttpStatus.CONFLICT, "Job already " + job.status());
        jobs.cancel(scope.tenantId(), id);
        audit.append(scope.tenantId(), scope.actor(), "SCAN_CANCEL_REQUESTED", "job:" + id, null);
        return get(scope, id);
    }

    /** Scanner id to descriptor summary, merged across workers seen in the last 10 minutes. */
    public Map<String, ScannerInfo> scannerCatalog() {
        Map<String, ScannerInfo> out = new LinkedHashMap<>();
        for (Map<String, Object> w : workers.list(Instant.now().minus(Duration.ofMinutes(10)))) {
            String json = (String) w.get("scannersJson");
            if (json == null) continue;
            try {
                for (ScannerInfo s : mapper.readValue(json, new TypeReference<List<ScannerInfo>>() { })) out.putIfAbsent(s.id(), s);
            } catch (Exception e) {
                log.debug("Ignoring unreadable scanner catalog of worker {}", w.get("id"));
            }
        }
        return out;
    }

    // ================================================================== worker side

    public void registerWorker(WorkerRegistration reg) {
        if (reg == null || reg.workerId() == null || !SCANNER_ID.matcher(reg.workerId()).matches()) {
            throw ApiException.badRequest("workerId is required");
        }
        List<ScannerInfo> scanners = reg.scanners() == null ? List.of() : reg.scanners().stream().limit(500).toList();
        workers.upsert(reg.workerId(), reg.name(), reg.version(), reg.sandbox(), write(scanners));
    }

    /** Claims the oldest queued job the worker can run, or returns empty. */
    public Optional<Map<String, Object>> claim(String workerId, List<String> scannerIds) {
        if (workerId == null || !SCANNER_ID.matcher(workerId).matches()) throw ApiException.badRequest("workerId is required");
        workers.touch(workerId);
        Set<String> ids = new LinkedHashSet<>(scannerIds == null ? List.of() : scannerIds);
        Instant lease = Instant.now().plus(props.getJobs().getLease());
        for (String id : jobs.candidates(ids, 10)) {
            if (jobs.tryClaim(id, workerId, lease)) {
                Job job = jobs.findAnyTenant(id).orElseThrow();
                audit.append(job.tenantId(), "worker:" + workerId, "SCAN_STARTED", "job:" + id, "attempt " + job.attempts());
                return Optional.of(dispatch(job));
            }
        }
        return Optional.empty();
    }

    /** What a worker receives: everything needed to run the scan, nothing more (no tenant data, no secrets). */
    private Map<String, Object> dispatch(Job job) {
        Application app = inventory.findApplication(job.tenantId(), job.applicationId()).orElseThrow();
        Environment env = inventory.findEnvironmentById(job.tenantId(), job.environmentId()).orElseThrow();
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("jobId", job.id());
        m.put("scannerId", job.scannerId());
        m.put("targetUrl", job.targetUrl());
        m.put("options", read(job.optionsJson()));
        m.put("attempt", job.attempts());
        m.put("leaseSeconds", props.getJobs().getLease().toSeconds());
        m.put("application", Map.of("serviceId", app.serviceId(), "name", app.name(), "environment", env.name()));
        return m;
    }

    public Map<String, Object> heartbeat(String jobId, String workerId, int progress, String message) {
        Job job = jobs.findAnyTenant(jobId).orElseThrow(() -> ApiException.notFound("Scan job"));
        boolean owned = jobs.heartbeat(jobId, workerId, Instant.now().plus(props.getJobs().getLease()), progress, message);
        if (!owned) throw new ApiException(HttpStatus.CONFLICT, "Job is not leased to this worker");
        return Map.of("cancelRequested", job.cancelRequested());
    }

    public Map<String, Object> complete(String jobId, Completion c) {
        Job job = jobs.findAnyTenant(jobId).orElseThrow(() -> ApiException.notFound("Scan job"));
        if (c == null || c.workerId() == null || !c.workerId().equals(job.workerId()) || job.status() != JobStatus.RUNNING) {
            throw new ApiException(HttpStatus.CONFLICT, "Job is not leased to this worker");
        }
        JobStatus status = job.cancelRequested() ? JobStatus.CANCELLED
                : "COMPLETED".equalsIgnoreCase(c.status()) ? JobStatus.COMPLETED : JobStatus.FAILED;
        List<Finding> reported = c.findings() == null ? List.of() : c.findings();
        int max = props.getJobs().getMaxFindingsPerJob();
        boolean truncated = reported.size() > max;
        if (truncated) reported = reported.subList(0, max);

        FindingIngestService.Result result = ingest.ingest(job, reported, status == JobStatus.COMPLETED && !truncated);
        Map<String, Integer> sev = new LinkedHashMap<>();
        for (Severity s : Severity.values()) sev.put(s.name(), result.byPriority().getOrDefault(s, 0));
        List<String> logLines = c.log() == null ? List.of() : c.log();
        if (logLines.size() > 500) logLines = logLines.subList(logLines.size() - 500, logLines.size());
        String logText = com.securetest.core.util.Redactor.redact(String.join("\n", logLines));
        if (logText != null && logText.length() > 200_000) logText = logText.substring(logText.length() - 200_000);
        Map<String, Object> results = c.results() == null ? new LinkedHashMap<>() : new LinkedHashMap<>(c.results());
        if (truncated) results.put("truncatedFindings", true);
        results.put("autoClosed", result.autoClosed());
        String resultsJson = write(results);
        if (resultsJson.length() > 1_000_000) resultsJson = write(Map.of("omitted", "results larger than 1 MB"));

        if (!jobs.finish(jobId, c.workerId(), status, result.accepted(), write(sev), resultsJson, logText, c.error())) {
            throw new ApiException(HttpStatus.CONFLICT, "Job lease was lost before completion");
        }
        audit.append(job.tenantId(), "worker:" + c.workerId(), "SCAN_" + status.name(), "job:" + jobId,
                result.accepted() + " findings, " + result.autoClosed() + " auto-closed" + (c.error() != null ? ", error: " + c.error() : ""));
        return Map.of("status", status.name(), "accepted", result.accepted());
    }

    @Scheduled(fixedDelay = 15_000, initialDelay = 15_000)
    public void reapExpiredLeases() {
        try {
            int n = jobs.reapExpiredLeases(Instant.now());
            if (n > 0) log.info("Re-queued, cancelled or failed {} scan job(s) whose worker lease expired", n);
        } catch (Exception e) {
            log.warn("Lease reaper failed: {}", e.getMessage());
        }
    }

    // ================================================================== helpers

    Map<String, Object> view(Job j) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("id", j.id());
        m.put("applicationId", j.applicationId());
        m.put("environmentId", j.environmentId());
        m.put("scannerId", j.scannerId());
        m.put("moduleId", j.moduleId());
        m.put("targetUrl", j.targetUrl());
        m.put("options", read(j.optionsJson()));
        m.put("status", j.status().name());
        m.put("requestedBy", j.requestedBy());
        m.put("workerId", j.workerId());
        m.put("attempts", j.attempts());
        m.put("cancelRequested", j.cancelRequested());
        m.put("progress", j.progress());
        m.put("progressMessage", j.progressMessage());
        m.put("findingsCount", j.findingsCount());
        m.put("severityCounts", read(j.severityCountsJson()));
        m.put("results", read(j.resultsJson()));
        m.put("log", j.logText() == null ? List.of() : new ArrayList<>(List.of(j.logText().split("\n"))));
        m.put("error", j.error());
        m.put("createdAt", j.createdAt());
        m.put("startedAt", j.startedAt());
        m.put("endedAt", j.endedAt());
        return m;
    }

    private Object read(String json) {
        if (json == null) return null;
        try {
            return mapper.readValue(json, Object.class);
        } catch (Exception e) {
            return null;
        }
    }

    private String write(Object o) {
        try {
            return mapper.writeValueAsString(o);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static String blankToNull(String s) { return s == null || s.isBlank() ? null : s; }
}
