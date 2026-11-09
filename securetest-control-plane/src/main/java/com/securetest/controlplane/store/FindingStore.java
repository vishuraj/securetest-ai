package com.securetest.controlplane.store;

import com.securetest.core.model.Finding;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static com.securetest.controlplane.store.Rows.truncate;
import static com.securetest.controlplane.store.Rows.ts;

/** Central, de-duplicated finding store. Identity = (tenant, application, environment, fingerprint). */
@Repository
public class FindingStore {

    public record Existing(String id, String status, Instant firstDetected, int occurrences) { }

    public record Filter(String applicationId, String priority, String status, String source, int limit) { }

    private static final String OPEN_STATES = "('OPEN','IN_PROGRESS')";

    private final JdbcClient jdbc;

    public FindingStore(JdbcClient jdbc) { this.jdbc = jdbc; }

    public Optional<Existing> find(String tenantId, String applicationId, String environmentId, String fingerprint) {
        return jdbc.sql("""
                SELECT id, status, first_detected, occurrences FROM finding
                WHERE tenant_id = :t AND application_id = :a AND environment_id = :e AND fingerprint = :fp""")
                .param("t", tenantId).param("a", applicationId).param("e", environmentId).param("fp", fingerprint)
                .query((rs, n) -> new Existing(rs.getString("id"), rs.getString("status"),
                        Rows.instant(rs, "first_detected"), rs.getInt("occurrences")))
                .optional();
    }

    public void insert(String tenantId, String applicationId, String environmentId, Finding f, String payloadJson) {
        jdbc.sql("""
                INSERT INTO finding (id, tenant_id, application_id, environment_id, fingerprint, module_id, source, rule_id,
                       category, title, source_severity, priority, confidence, status, asset, file_path, line_start,
                       first_detected, last_detected, last_scan_id, occurrences, payload_json)
                VALUES (:id, :t, :a, :e, :fp, :m, :src, :rule, :cat, :title, :sev, :prio, :conf, :st, :asset, :file, :line,
                       :first, :last, :scan, :occ, :payload)""")
                .param("id", f.id).param("t", tenantId).param("a", applicationId).param("e", environmentId)
                .param("fp", f.fingerprint).params(columns(f)).param("first", ts(f.firstDetected))
                .param("payload", payloadJson).update();
    }

    public void update(String tenantId, Finding f, String payloadJson) {
        jdbc.sql("""
                UPDATE finding SET module_id = :m, source = :src, rule_id = :rule, category = :cat, title = :title,
                       source_severity = :sev, priority = :prio, confidence = :conf, status = :st, asset = :asset,
                       file_path = :file, line_start = :line, last_detected = :last, last_scan_id = :scan,
                       occurrences = :occ, payload_json = :payload
                WHERE tenant_id = :t AND id = :id""")
                .params(columns(f)).param("payload", payloadJson).param("t", tenantId).param("id", f.id).update();
    }

    private static Map<String, Object> columns(Finding f) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("m", truncate(f.moduleId, 100));
        m.put("src", truncate(f.source, 100));
        m.put("rule", truncate(f.ruleId, 200));
        m.put("cat", truncate(f.category, 200));
        m.put("title", truncate(f.title, 1000));
        m.put("sev", f.sourceSeverity.name());
        m.put("prio", f.priority.name());
        m.put("conf", f.confidence == null ? null : f.confidence.name());
        m.put("st", f.status.name());
        m.put("asset", truncate(f.asset, 1000));
        m.put("file", truncate(f.filePath, 1000));
        m.put("line", f.lineStart);
        m.put("last", ts(f.lastDetected));
        m.put("scan", f.lastScanId);
        m.put("occ", f.occurrences);
        return m;
    }

    /** Marks open findings from {@code source} that were not reported by the latest complete scan as fixed. */
    public int autoClose(String tenantId, String applicationId, String environmentId, String source, Set<String> seen) {
        String sql = "UPDATE finding SET status = 'FIXED' WHERE tenant_id = :t AND application_id = :a"
                + " AND environment_id = :e AND source = :src AND status IN " + OPEN_STATES
                + (seen.isEmpty() ? "" : " AND fingerprint NOT IN (:seen)");
        var spec = jdbc.sql(sql).param("t", tenantId).param("a", applicationId).param("e", environmentId).param("src", source);
        if (!seen.isEmpty()) spec = spec.param("seen", seen);
        return spec.update();
    }

    public List<Map<String, Object>> list(String tenantId, Filter filter) {
        StringBuilder sql = new StringBuilder("""
                SELECT f.*, a.service_id, a.name AS application_name, e.name AS environment_name
                FROM finding f JOIN application a ON a.id = f.application_id JOIN environment e ON e.id = f.environment_id
                WHERE f.tenant_id = :t""");
        Map<String, Object> params = new LinkedHashMap<>();
        params.put("t", tenantId);
        if (filter.applicationId() != null) { sql.append(" AND f.application_id = :a"); params.put("a", filter.applicationId()); }
        if (filter.priority() != null) { sql.append(" AND f.priority = :p"); params.put("p", filter.priority()); }
        if (filter.status() != null) {
            if (filter.status().equalsIgnoreCase("open")) sql.append(" AND f.status IN " + OPEN_STATES);
            else { sql.append(" AND f.status = :s"); params.put("s", filter.status()); }
        }
        if (filter.source() != null) { sql.append(" AND f.source = :src"); params.put("src", filter.source()); }
        sql.append(" ORDER BY f.last_detected DESC, f.id LIMIT :lim");
        params.put("lim", filter.limit());
        return jdbc.sql(sql.toString()).params(params).query(this::summaryRow).list();
    }

    public Optional<Map<String, Object>> get(String tenantId, String id) {
        return jdbc.sql("""
                SELECT f.*, a.service_id, a.name AS application_name, e.name AS environment_name
                FROM finding f JOIN application a ON a.id = f.application_id JOIN environment e ON e.id = f.environment_id
                WHERE f.tenant_id = :t AND f.id = :id""")
                .param("t", tenantId).param("id", id)
                .query((rs, n) -> {
                    Map<String, Object> m = summaryRow(rs, n);
                    m.put("payloadJson", rs.getString("payload_json"));
                    return m;
                }).optional();
    }

    /** Full finding documents, for reports. */
    public List<String> openPayloads(String tenantId, String applicationId, int limit) {
        var spec = jdbc.sql("SELECT payload_json FROM finding WHERE tenant_id = :t AND status IN " + OPEN_STATES
                        + (applicationId != null ? " AND application_id = :a" : "") + " ORDER BY last_detected DESC LIMIT :lim")
                .param("t", tenantId).param("lim", limit);
        if (applicationId != null) spec = spec.param("a", applicationId);
        return spec.query(String.class).list();
    }

    /** Open findings aggregated by priority and by application. */
    public Map<String, Object> summary(String tenantId) {
        Map<String, Long> byPriority = new LinkedHashMap<>();
        for (String p : List.of("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")) byPriority.put(p, 0L);
        jdbc.sql("SELECT priority, COUNT(*) AS c FROM finding WHERE tenant_id = :t AND status IN " + OPEN_STATES + " GROUP BY priority")
                .param("t", tenantId)
                .query(rs -> { byPriority.put(rs.getString("priority"), rs.getLong("c")); });
        List<Map<String, Object>> byApp = new ArrayList<>();
        jdbc.sql("SELECT a.id, a.service_id, a.name, COUNT(f.id) AS open_count,"
                        + " SUM(CASE WHEN f.priority IN ('CRITICAL','HIGH') THEN 1 ELSE 0 END) AS urgent"
                        + " FROM application a LEFT JOIN finding f ON f.application_id = a.id AND f.status IN " + OPEN_STATES
                        + " WHERE a.tenant_id = :t GROUP BY a.id, a.service_id, a.name ORDER BY a.service_id")
                .param("t", tenantId)
                .query(rs -> {
                    Map<String, Object> m = new LinkedHashMap<>();
                    m.put("applicationId", rs.getString("id"));
                    m.put("serviceId", rs.getString("service_id"));
                    m.put("name", rs.getString("name"));
                    m.put("open", rs.getLong("open_count"));
                    m.put("criticalOrHigh", rs.getLong("urgent"));
                    byApp.add(m);
                });
        long total = byPriority.values().stream().mapToLong(Long::longValue).sum();
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("open", total);
        out.put("byPriority", byPriority);
        out.put("byApplication", byApp);
        return out;
    }

    private Map<String, Object> summaryRow(ResultSet rs, int n) throws SQLException {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("id", rs.getString("id"));
        m.put("applicationId", rs.getString("application_id"));
        m.put("serviceId", rs.getString("service_id"));
        m.put("application", rs.getString("application_name"));
        m.put("environment", rs.getString("environment_name"));
        m.put("fingerprint", rs.getString("fingerprint"));
        m.put("moduleId", rs.getString("module_id"));
        m.put("source", rs.getString("source"));
        m.put("ruleId", rs.getString("rule_id"));
        m.put("category", rs.getString("category"));
        m.put("title", rs.getString("title"));
        m.put("sourceSeverity", rs.getString("source_severity"));
        m.put("priority", rs.getString("priority"));
        m.put("confidence", rs.getString("confidence"));
        m.put("status", rs.getString("status"));
        m.put("asset", rs.getString("asset"));
        m.put("filePath", rs.getString("file_path"));
        m.put("lineStart", Rows.intOrNull(rs, "line_start"));
        m.put("firstDetected", Rows.instant(rs, "first_detected"));
        m.put("lastDetected", Rows.instant(rs, "last_detected"));
        m.put("lastScanId", rs.getString("last_scan_id"));
        m.put("occurrences", rs.getInt("occurrences"));
        return m;
    }
}
