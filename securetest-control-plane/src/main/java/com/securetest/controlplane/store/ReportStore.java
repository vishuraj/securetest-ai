package com.securetest.controlplane.store;

import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static com.securetest.controlplane.store.Rows.ts;

@Repository
public class ReportStore {

    public record Content(String format, String title, byte[] data) { }

    private final JdbcClient jdbc;

    public ReportStore(JdbcClient jdbc) { this.jdbc = jdbc; }

    public void insert(String id, String tenantId, String applicationId, String format, String title, int findingsCount,
                       String sha256, byte[] content, String createdBy) {
        jdbc.sql("""
                INSERT INTO report (id, tenant_id, application_id, format, title, findings_count, sha256, content, created_by, created_at)
                VALUES (:id, :t, :a, :f, :title, :n, :sha, :content, :by, :now)""")
                .param("id", id).param("t", tenantId).param("a", applicationId).param("f", format).param("title", title)
                .param("n", findingsCount).param("sha", sha256).param("content", content).param("by", createdBy)
                .param("now", ts(Instant.now())).update();
    }

    public List<Map<String, Object>> list(String tenantId) {
        return jdbc.sql("""
                SELECT id, application_id, format, title, findings_count, sha256, created_by, created_at
                FROM report WHERE tenant_id = :t ORDER BY created_at DESC LIMIT 200""")
                .param("t", tenantId)
                .query((rs, n) -> {
                    Map<String, Object> m = new LinkedHashMap<>();
                    m.put("id", rs.getString("id"));
                    m.put("applicationId", rs.getString("application_id"));
                    m.put("format", rs.getString("format"));
                    m.put("title", rs.getString("title"));
                    m.put("findingsCount", rs.getInt("findings_count"));
                    m.put("sha256", rs.getString("sha256"));
                    m.put("createdBy", rs.getString("created_by"));
                    m.put("createdAt", Rows.instant(rs, "created_at"));
                    return m;
                }).list();
    }

    public Optional<Content> content(String tenantId, String id) {
        return jdbc.sql("SELECT format, title, content FROM report WHERE tenant_id = :t AND id = :id")
                .param("t", tenantId).param("id", id)
                .query((rs, n) -> new Content(rs.getString("format"), rs.getString("title"), rs.getBytes("content")))
                .optional();
    }
}
