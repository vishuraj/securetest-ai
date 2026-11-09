package com.securetest.controlplane.store;

import org.springframework.dao.DuplicateKeyException;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.function.Supplier;

import static com.securetest.controlplane.store.Rows.newId;
import static com.securetest.controlplane.store.Rows.ts;

/** Organization / project / application / environment / agent registration (SRS 12). */
@Repository
public class InventoryStore {

    public static final String DEFAULT_ORGANIZATION = "default";
    public static final String DEFAULT_PROJECT = "default";

    public record Application(String id, String tenantId, String projectId, String serviceId, String name) { }
    public record Environment(String id, String applicationId, String name, boolean production) { }

    private final JdbcClient jdbc;

    public InventoryStore(JdbcClient jdbc) { this.jdbc = jdbc; }

    /** Insert-if-absent that is safe under concurrent registrations (relies on unique constraints). */
    private static <T> T getOrCreate(Supplier<Optional<T>> find, Runnable insert) {
        Optional<T> existing = find.get();
        if (existing.isPresent()) return existing.get();
        try {
            insert.run();
        } catch (DuplicateKeyException race) {
            // created concurrently; re-read below
        }
        return find.get().orElseThrow();
    }

    public String defaultProject(String tenantId) {
        String orgId = getOrCreate(
                () -> jdbc.sql("SELECT id FROM organization WHERE tenant_id = :t AND name = :n")
                        .param("t", tenantId).param("n", DEFAULT_ORGANIZATION).query(String.class).optional(),
                () -> jdbc.sql("INSERT INTO organization (id, tenant_id, name, created_at) VALUES (:id, :t, :n, :at)")
                        .param("id", newId()).param("t", tenantId).param("n", DEFAULT_ORGANIZATION).param("at", ts(Instant.now())).update());
        return getOrCreate(
                () -> jdbc.sql("SELECT id FROM project WHERE organization_id = :o AND name = :n")
                        .param("o", orgId).param("n", DEFAULT_PROJECT).query(String.class).optional(),
                () -> jdbc.sql("INSERT INTO project (id, tenant_id, organization_id, name, created_at) VALUES (:id, :t, :o, :n, :at)")
                        .param("id", newId()).param("t", tenantId).param("o", orgId).param("n", DEFAULT_PROJECT)
                        .param("at", ts(Instant.now())).update());
    }

    public Application upsertApplication(String tenantId, String serviceId, String name) {
        Application app = getOrCreate(() -> findApplicationByServiceId(tenantId, serviceId), () -> {
            String projectId = defaultProject(tenantId);
            jdbc.sql("""
                    INSERT INTO application (id, tenant_id, project_id, service_id, name, created_at)
                    VALUES (:id, :t, :p, :s, :n, :at)""")
                    .param("id", newId()).param("t", tenantId).param("p", projectId).param("s", serviceId)
                    .param("n", name).param("at", ts(Instant.now())).update();
        });
        if (name != null && !name.equals(app.name())) {
            jdbc.sql("UPDATE application SET name = :n WHERE id = :id").param("n", name).param("id", app.id()).update();
        }
        return app;
    }

    public Environment upsertEnvironment(String tenantId, String applicationId, String name) {
        return getOrCreate(() -> findEnvironment(tenantId, applicationId, name), () ->
                jdbc.sql("""
                        INSERT INTO environment (id, tenant_id, application_id, name, production, created_at)
                        VALUES (:id, :t, :a, :n, :p, :at)""")
                        .param("id", newId()).param("t", tenantId).param("a", applicationId).param("n", name)
                        .param("p", isProductionName(name)).param("at", ts(Instant.now())).update());
    }

    static boolean isProductionName(String env) {
        if (env == null) return false;
        String e = env.toLowerCase(Locale.ROOT);
        return e.equals("prod") || e.equals("production") || e.startsWith("prod-") || e.endsWith("-prod");
    }

    /** @return true when this is the first registration of the agent */
    public boolean upsertAgent(String tenantId, String applicationId, String environmentId, String agentVersion,
                               String appVersion, String runtimeJson, String capabilitiesJson, String remoteAddress) {
        Instant now = Instant.now();
        int updated = jdbc.sql("""
                UPDATE agent_registration SET agent_version = :av, app_version = :v, runtime_json = :r,
                       capabilities_json = :c, remote_address = :ip, last_seen = :now
                WHERE tenant_id = :t AND application_id = :a AND environment_id = :e""")
                .param("av", agentVersion).param("v", appVersion).param("r", runtimeJson).param("c", capabilitiesJson)
                .param("ip", remoteAddress).param("now", ts(now)).param("t", tenantId).param("a", applicationId)
                .param("e", environmentId).update();
        if (updated > 0) return false;
        try {
            jdbc.sql("""
                    INSERT INTO agent_registration (id, tenant_id, application_id, environment_id, agent_version, app_version,
                           runtime_json, capabilities_json, remote_address, first_seen, last_seen)
                    VALUES (:id, :t, :a, :e, :av, :v, :r, :c, :ip, :now, :now)""")
                    .param("id", newId()).param("t", tenantId).param("a", applicationId).param("e", environmentId)
                    .param("av", agentVersion).param("v", appVersion).param("r", runtimeJson).param("c", capabilitiesJson)
                    .param("ip", remoteAddress).param("now", ts(now)).update();
            return true;
        } catch (DuplicateKeyException race) {
            return false;
        }
    }

    public Optional<Application> findApplication(String tenantId, String applicationId) {
        return jdbc.sql("SELECT * FROM application WHERE tenant_id = :t AND id = :id")
                .param("t", tenantId).param("id", applicationId).query(this::app).optional();
    }

    public Optional<Application> findApplicationByServiceId(String tenantId, String serviceId) {
        return jdbc.sql("SELECT * FROM application WHERE tenant_id = :t AND service_id = :s")
                .param("t", tenantId).param("s", serviceId).query(this::app).optional();
    }

    public Optional<Environment> findEnvironment(String tenantId, String applicationId, String name) {
        return jdbc.sql("SELECT * FROM environment WHERE tenant_id = :t AND application_id = :a AND name = :n")
                .param("t", tenantId).param("a", applicationId).param("n", name).query(this::env).optional();
    }

    public Optional<Environment> findEnvironmentById(String tenantId, String id) {
        return jdbc.sql("SELECT * FROM environment WHERE tenant_id = :t AND id = :id")
                .param("t", tenantId).param("id", id).query(this::env).optional();
    }

    /** Most recently seen environment of an application (used when a scan request names none). */
    public Optional<Environment> latestEnvironment(String tenantId, String applicationId) {
        return jdbc.sql("""
                SELECT e.* FROM environment e LEFT JOIN agent_registration r ON r.environment_id = e.id
                WHERE e.tenant_id = :t AND e.application_id = :a
                ORDER BY r.last_seen DESC NULLS LAST, e.created_at DESC LIMIT 1""")
                .param("t", tenantId).param("a", applicationId).query(this::env).optional();
    }

    public List<Map<String, Object>> agents(String tenantId) {
        return jdbc.sql("""
                SELECT r.id, a.id AS application_id, a.service_id, a.name AS application_name, e.name AS environment,
                       r.agent_version, r.app_version, r.runtime_json, r.capabilities_json, r.first_seen, r.last_seen
                FROM agent_registration r
                JOIN application a ON a.id = r.application_id
                JOIN environment e ON e.id = r.environment_id
                WHERE r.tenant_id = :t ORDER BY a.service_id, e.name""")
                .param("t", tenantId)
                .query((rs, n) -> {
                    Map<String, Object> m = new LinkedHashMap<>();
                    m.put("id", rs.getString("id"));
                    m.put("applicationId", rs.getString("application_id"));
                    m.put("serviceId", rs.getString("service_id"));
                    m.put("application", rs.getString("application_name"));
                    m.put("environment", rs.getString("environment"));
                    m.put("agentVersion", rs.getString("agent_version"));
                    m.put("appVersion", rs.getString("app_version"));
                    m.put("runtimeJson", rs.getString("runtime_json"));
                    m.put("capabilitiesJson", rs.getString("capabilities_json"));
                    m.put("firstSeen", Rows.instant(rs, "first_seen"));
                    m.put("lastSeen", Rows.instant(rs, "last_seen"));
                    return m;
                }).list();
    }

    public List<Application> applications(String tenantId) {
        return jdbc.sql("SELECT * FROM application WHERE tenant_id = :t ORDER BY service_id").param("t", tenantId).query(this::app).list();
    }

    public List<Environment> environments(String tenantId) {
        return jdbc.sql("SELECT * FROM environment WHERE tenant_id = :t ORDER BY name").param("t", tenantId).query(this::env).list();
    }

    private Application app(ResultSet rs, int n) throws SQLException {
        return new Application(rs.getString("id"), rs.getString("tenant_id"), rs.getString("project_id"),
                rs.getString("service_id"), rs.getString("name"));
    }

    private Environment env(ResultSet rs, int n) throws SQLException {
        return new Environment(rs.getString("id"), rs.getString("application_id"), rs.getString("name"), rs.getBoolean("production"));
    }
}
