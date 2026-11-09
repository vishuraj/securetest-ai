package com.securetest.controlplane.store;

import com.securetest.core.model.Enums.JobStatus;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Optional;

import static com.securetest.controlplane.store.Rows.ts;

/**
 * Durable job queue on the {@code scan_job} table.
 * <p>
 * Claiming uses a conditional update ({@code ... WHERE status = 'QUEUED'}) so that two workers can never
 * own the same job, on any database and without row locks. A lease ({@code lease_until}) is renewed by
 * worker heartbeats; expired leases are re-queued by the reaper.
 */
@Repository
public class JobStore {

    public record Job(String id, String tenantId, String applicationId, String environmentId, String scannerId,
                      String moduleId, String targetUrl, String optionsJson, JobStatus status, String requestedBy,
                      String idempotencyKey, String workerId, int attempts, int maxAttempts, Instant leaseUntil,
                      boolean cancelRequested, int progress, String progressMessage, int findingsCount,
                      String severityCountsJson, String resultsJson, String logText, String error,
                      Instant createdAt, Instant startedAt, Instant endedAt) { }

    private final JdbcClient jdbc;

    public JobStore(JdbcClient jdbc) { this.jdbc = jdbc; }

    public void insert(String id, String tenantId, String applicationId, String environmentId, String scannerId,
                       String moduleId, String targetUrl, String optionsJson, String requestedBy, String idempotencyKey,
                       int maxAttempts) {
        jdbc.sql("""
                INSERT INTO scan_job (id, tenant_id, application_id, environment_id, scanner_id, module_id, target_url,
                       options_json, status, requested_by, idempotency_key, attempts, max_attempts, created_at)
                VALUES (:id, :t, :a, :e, :s, :m, :url, :opts, 'QUEUED', :by, :key, 0, :max, :now)""")
                .param("id", id).param("t", tenantId).param("a", applicationId).param("e", environmentId)
                .param("s", scannerId).param("m", moduleId).param("url", targetUrl).param("opts", optionsJson)
                .param("by", requestedBy).param("key", idempotencyKey).param("max", maxAttempts)
                .param("now", ts(Instant.now())).update();
    }

    public Optional<Job> find(String tenantId, String id) {
        return jdbc.sql("SELECT * FROM scan_job WHERE tenant_id = :t AND id = :id")
                .param("t", tenantId).param("id", id).query(this::map).optional();
    }

    public Optional<Job> findByIdempotencyKey(String tenantId, String key) {
        return jdbc.sql("SELECT * FROM scan_job WHERE tenant_id = :t AND idempotency_key = :k")
                .param("t", tenantId).param("k", key).query(this::map).optional();
    }

    /** Unscoped lookup, for worker endpoints only (workers serve every tenant). */
    public Optional<Job> findAnyTenant(String id) {
        return jdbc.sql("SELECT * FROM scan_job WHERE id = :id").param("id", id).query(this::map).optional();
    }

    public List<Job> list(String tenantId, String applicationId, int limit) {
        var spec = jdbc.sql("SELECT * FROM scan_job WHERE tenant_id = :t"
                        + (applicationId != null ? " AND application_id = :a" : "") + " ORDER BY created_at DESC LIMIT :lim")
                .param("t", tenantId).param("lim", limit);
        if (applicationId != null) spec = spec.param("a", applicationId);
        return spec.query(this::map).list();
    }

    /** Oldest queued jobs a worker could run (candidates; ownership is decided by {@link #tryClaim}). */
    public List<String> candidates(Collection<String> scannerIds, int limit) {
        if (scannerIds.isEmpty()) return List.of();
        return jdbc.sql("""
                SELECT id FROM scan_job WHERE status = 'QUEUED' AND cancel_requested = FALSE AND scanner_id IN (:s)
                ORDER BY created_at LIMIT :lim""")
                .param("s", scannerIds).param("lim", limit).query(String.class).list();
    }

    public boolean tryClaim(String id, String workerId, Instant leaseUntil) {
        return jdbc.sql("""
                UPDATE scan_job SET status = 'RUNNING', worker_id = :w, lease_until = :lease, attempts = attempts + 1,
                       started_at = :now, progress = 0, progress_message = 'Claimed by worker', error = NULL
                WHERE id = :id AND status = 'QUEUED' AND cancel_requested = FALSE""")
                .param("w", workerId).param("lease", ts(leaseUntil)).param("now", ts(Instant.now())).param("id", id)
                .update() == 1;
    }

    /** Renews the lease if the worker still owns the job. */
    public boolean heartbeat(String id, String workerId, Instant leaseUntil, int progress, String message) {
        return jdbc.sql("""
                UPDATE scan_job SET lease_until = :lease, progress = :p, progress_message = :msg
                WHERE id = :id AND worker_id = :w AND status = 'RUNNING'""")
                .param("lease", ts(leaseUntil)).param("p", Math.max(0, Math.min(100, progress)))
                .param("msg", Rows.truncate(message, 500)).param("id", id).param("w", workerId).update() == 1;
    }

    public boolean finish(String id, String workerId, JobStatus status, int findingsCount, String severityCountsJson,
                          String resultsJson, String logText, String error) {
        return jdbc.sql("""
                UPDATE scan_job SET status = :st, findings_count = :fc, severity_counts_json = :sc, results_json = :r,
                       log_text = :log, error = :err, ended_at = :now, lease_until = NULL, progress = 100,
                       progress_message = :st
                WHERE id = :id AND worker_id = :w AND status = 'RUNNING'""")
                .param("st", status.name()).param("fc", findingsCount).param("sc", severityCountsJson)
                .param("r", resultsJson).param("log", logText).param("err", Rows.truncate(error, 2000))
                .param("now", ts(Instant.now())).param("id", id).param("w", workerId).update() == 1;
    }

    /** Cancels a queued job immediately, or flags a running one so its worker stops at the next heartbeat. */
    public boolean cancel(String tenantId, String id) {
        int queued = jdbc.sql("""
                UPDATE scan_job SET status = 'CANCELLED', cancel_requested = TRUE, ended_at = :now
                WHERE tenant_id = :t AND id = :id AND status = 'QUEUED'""")
                .param("now", ts(Instant.now())).param("t", tenantId).param("id", id).update();
        if (queued == 1) return true;
        return jdbc.sql("UPDATE scan_job SET cancel_requested = TRUE WHERE tenant_id = :t AND id = :id AND status = 'RUNNING'")
                .param("t", tenantId).param("id", id).update() == 1;
    }

    /** Re-queues (or fails, after max attempts) running jobs whose worker stopped heart-beating. */
    public int reapExpiredLeases(Instant now) {
        int failed = jdbc.sql("""
                UPDATE scan_job SET status = 'FAILED', ended_at = :now, lease_until = NULL,
                       error = 'Worker lease expired; maximum attempts reached'
                WHERE status = 'RUNNING' AND lease_until < :now AND attempts >= max_attempts""")
                .param("now", ts(now)).update();
        int requeued = jdbc.sql("""
                UPDATE scan_job SET status = 'QUEUED', worker_id = NULL, lease_until = NULL,
                       progress_message = 'Re-queued after worker lease expired'
                WHERE status = 'RUNNING' AND lease_until < :now AND attempts < max_attempts""")
                .param("now", ts(now)).update();
        int cancelled = jdbc.sql("""
                UPDATE scan_job SET status = 'CANCELLED', ended_at = :now, lease_until = NULL
                WHERE status = 'RUNNING' AND cancel_requested = TRUE AND lease_until < :now""")
                .param("now", ts(now)).update();
        return failed + requeued + cancelled;
    }

    private Job map(ResultSet rs, int n) throws SQLException {
        return new Job(rs.getString("id"), rs.getString("tenant_id"), rs.getString("application_id"),
                rs.getString("environment_id"), rs.getString("scanner_id"), rs.getString("module_id"),
                rs.getString("target_url"), rs.getString("options_json"), JobStatus.valueOf(rs.getString("status")),
                rs.getString("requested_by"), rs.getString("idempotency_key"), rs.getString("worker_id"),
                rs.getInt("attempts"), rs.getInt("max_attempts"), Rows.instant(rs, "lease_until"),
                rs.getBoolean("cancel_requested"), rs.getInt("progress"), rs.getString("progress_message"),
                rs.getInt("findings_count"), rs.getString("severity_counts_json"), rs.getString("results_json"),
                rs.getString("log_text"), rs.getString("error"), Rows.instant(rs, "created_at"),
                Rows.instant(rs, "started_at"), Rows.instant(rs, "ended_at"));
    }
}
