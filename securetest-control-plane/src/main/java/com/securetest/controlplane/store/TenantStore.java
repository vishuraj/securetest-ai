package com.securetest.controlplane.store;

import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

import static com.securetest.controlplane.store.Rows.newId;
import static com.securetest.controlplane.store.Rows.ts;

@Repository
public class TenantStore {

    public record Tenant(String id, String slug, String name, Instant createdAt) { }

    private final JdbcClient jdbc;

    public TenantStore(JdbcClient jdbc) { this.jdbc = jdbc; }

    public Tenant create(String slug, String name) {
        String id = newId();
        Instant now = Instant.now();
        jdbc.sql("INSERT INTO tenant (id, slug, name, created_at) VALUES (:id, :slug, :name, :at)")
                .param("id", id).param("slug", slug).param("name", name).param("at", ts(now)).update();
        return new Tenant(id, slug, name, now);
    }

    public Optional<Tenant> findBySlug(String slug) {
        if (slug == null) return Optional.empty();
        return jdbc.sql("SELECT * FROM tenant WHERE slug = :slug").param("slug", slug).query(this::map).optional();
    }

    public Optional<Tenant> findById(String id) {
        return jdbc.sql("SELECT * FROM tenant WHERE id = :id").param("id", id).query(this::map).optional();
    }

    public List<Tenant> list() {
        return jdbc.sql("SELECT * FROM tenant ORDER BY slug").query(this::map).list();
    }

    private Tenant map(java.sql.ResultSet rs, int n) throws java.sql.SQLException {
        return new Tenant(rs.getString("id"), rs.getString("slug"), rs.getString("name"), Rows.instant(rs, "created_at"));
    }

    public String addEnrollmentToken(String tenantId, String tokenHash, String description, String createdBy) {
        String id = newId();
        jdbc.sql("""
                INSERT INTO enrollment_token (id, tenant_id, token_hash, description, created_by, created_at, revoked)
                VALUES (:id, :tenant, :hash, :desc, :by, :at, FALSE)""")
                .param("id", id).param("tenant", tenantId).param("hash", tokenHash).param("desc", description)
                .param("by", createdBy).param("at", ts(Instant.now())).update();
        return id;
    }

    public boolean enrollmentTokenExists(String tokenHash) {
        return jdbc.sql("SELECT COUNT(*) FROM enrollment_token WHERE token_hash = :h").param("h", tokenHash)
                .query(Long.class).single() > 0;
    }

    public boolean revokeEnrollmentToken(String tenantId, String id) {
        return jdbc.sql("UPDATE enrollment_token SET revoked = TRUE WHERE tenant_id = :t AND id = :id")
                .param("t", tenantId).param("id", id).update() > 0;
    }

    public Optional<String> tenantIdForEnrollmentToken(String tokenHash) {
        return jdbc.sql("SELECT tenant_id FROM enrollment_token WHERE token_hash = :h AND revoked = FALSE")
                .param("h", tokenHash).query(String.class).optional();
    }
}
