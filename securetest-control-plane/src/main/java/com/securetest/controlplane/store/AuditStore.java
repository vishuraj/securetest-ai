package com.securetest.controlplane.store;

import com.securetest.core.util.Hashing;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import static com.securetest.controlplane.store.Rows.truncate;
import static com.securetest.controlplane.store.Rows.ts;

/**
 * Append-only audit trail (SRS 12 Audit). Each tenant's events form a SHA-256 hash chain; platform events
 * ({@code tenant_id IS NULL}) form their own chain. Rows are never updated or deleted by the application.
 */
@Repository
public class AuditStore {

    private final JdbcClient jdbc;

    public AuditStore(JdbcClient jdbc) { this.jdbc = jdbc; }

    // Appends are serialized per JVM; for several control-plane replicas run the chain verifier
    // (GET /api/v1/audit/verify) which reports any fork.
    @Transactional
    public synchronized void append(String tenantId, String actor, String action, String target, String detail) {
        String prev = tenantId == null
                ? jdbc.sql("SELECT hash FROM audit_event WHERE tenant_id IS NULL ORDER BY seq DESC LIMIT 1").query(String.class).optional().orElse(null)
                : jdbc.sql("SELECT hash FROM audit_event WHERE tenant_id = :t ORDER BY seq DESC LIMIT 1").param("t", tenantId)
                        .query(String.class).optional().orElse(null);
        Instant at = Instant.now();
        String id = Rows.newId();
        String safeTarget = truncate(target, 500);
        String safeDetail = truncate(detail, 2000);
        String hash = hash(prev, id, tenantId, at, actor, action, safeTarget, safeDetail);
        jdbc.sql("""
                INSERT INTO audit_event (id, tenant_id, occurred_at, actor, action, target, detail, prev_hash, hash)
                VALUES (:id, :t, :at, :actor, :action, :target, :detail, :prev, :hash)""")
                .param("id", id).param("t", tenantId).param("at", ts(at)).param("actor", truncate(actor, 200))
                .param("action", truncate(action, 100)).param("target", safeTarget).param("detail", safeDetail)
                .param("prev", prev).param("hash", hash).update();
    }

    static String hash(String prev, String id, String tenantId, Instant at, String actor, String action, String target, String detail) {
        return Hashing.sha256(String.join("\u001f", Objects.toString(prev, ""), id, Objects.toString(tenantId, ""),
                String.valueOf(at.toEpochMilli()), Objects.toString(truncate(actor, 200), ""), Objects.toString(truncate(action, 100), ""),
                Objects.toString(target, ""), Objects.toString(detail, "")));
    }

    public List<Map<String, Object>> list(String tenantId, int limit) {
        return jdbc.sql("SELECT * FROM audit_event WHERE tenant_id = :t ORDER BY seq DESC LIMIT :lim")
                .param("t", tenantId).param("lim", limit)
                .query((rs, n) -> {
                    Map<String, Object> m = new LinkedHashMap<>();
                    m.put("id", rs.getString("id"));
                    m.put("at", Rows.instant(rs, "occurred_at"));
                    m.put("actor", rs.getString("actor"));
                    m.put("action", rs.getString("action"));
                    m.put("target", rs.getString("target"));
                    m.put("detail", rs.getString("detail"));
                    m.put("hash", rs.getString("hash"));
                    return m;
                }).list();
    }

    /** Recomputes the tenant's hash chain. */
    public Map<String, Object> verify(String tenantId) {
        Map<String, Object> out = new LinkedHashMap<>();
        String[] prev = {null};
        long[] count = {0};
        String[] broken = {null};
        jdbc.sql("SELECT * FROM audit_event WHERE tenant_id = :t ORDER BY seq").param("t", tenantId).query(rs -> {
            if (broken[0] != null) return;
            String id = rs.getString("id");
            Instant at = Rows.instant(rs, "occurred_at");
            String expected = hash(prev[0], id, tenantId, at, rs.getString("actor"), rs.getString("action"),
                    rs.getString("target"), rs.getString("detail"));
            if (!Objects.equals(prev[0], rs.getString("prev_hash")) || !expected.equals(rs.getString("hash"))) {
                broken[0] = id;
                return;
            }
            prev[0] = rs.getString("hash");
            count[0]++;
        });
        out.put("valid", broken[0] == null);
        out.put("verifiedEvents", count[0]);
        if (broken[0] != null) out.put("firstInvalidEvent", broken[0]);
        return out;
    }
}
