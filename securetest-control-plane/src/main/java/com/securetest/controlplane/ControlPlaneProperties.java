package com.securetest.controlplane;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

/** {@code securetest.control-plane.*} settings. */
@ConfigurationProperties(prefix = "securetest.control-plane")
public class ControlPlaneProperties {

    private final Security security = new Security();
    private final Workers workers = new Workers();
    private final Jobs jobs = new Jobs();
    private final Bootstrap bootstrap = new Bootstrap();

    public Security getSecurity() { return security; }
    public Workers getWorkers() { return workers; }
    public Jobs getJobs() { return jobs; }
    public Bootstrap getBootstrap() { return bootstrap; }

    /** OIDC claim mapping. Users authenticate with JWT access tokens issued by the configured OIDC provider. */
    public static class Security {
        /** Claim holding the tenant slug the user belongs to. */
        private String tenantClaim = "tenant";
        /** Claim holding the user's SecureTest roles (string or array). */
        private String rolesClaim = "roles";
        /** Role that may manage tenants across the platform. */
        private String platformAdminRole = "PLATFORM_ADMIN";

        public String getTenantClaim() { return tenantClaim; }
        public void setTenantClaim(String v) { this.tenantClaim = v; }
        public String getRolesClaim() { return rolesClaim; }
        public void setRolesClaim(String v) { this.rolesClaim = v; }
        public String getPlatformAdminRole() { return platformAdminRole; }
        public void setPlatformAdminRole(String v) { this.platformAdminRole = v; }
    }

    public static class Workers {
        /** Shared secrets accepted from workers (inject from a secret store, e.g. env SECURETEST_CONTROL_PLANE_WORKERS_TOKENS). */
        private List<String> tokens = new ArrayList<>();

        public List<String> getTokens() { return tokens; }
        public void setTokens(List<String> tokens) { this.tokens = tokens; }
    }

    public static class Jobs {
        /** How long a worker may hold a job without a heartbeat before it is re-queued. */
        private Duration lease = Duration.ofMinutes(2);
        private int maxAttempts = 3;
        /** Maximum findings accepted from one job. */
        private int maxFindingsPerJob = 20_000;

        public Duration getLease() { return lease; }
        public void setLease(Duration v) { this.lease = v; }
        public int getMaxAttempts() { return maxAttempts; }
        public void setMaxAttempts(int v) { this.maxAttempts = v; }
        public int getMaxFindingsPerJob() { return maxFindingsPerJob; }
        public void setMaxFindingsPerJob(int v) { this.maxFindingsPerJob = v; }
    }

    /** Optional first-start seeding so a fresh installation is usable without manual SQL. Idempotent. */
    public static class Bootstrap {
        private String tenantSlug;
        private String tenantName;
        /** Raw enrollment token to register for the bootstrap tenant (stored hashed). */
        private String enrollmentToken;

        public String getTenantSlug() { return tenantSlug; }
        public void setTenantSlug(String v) { this.tenantSlug = v; }
        public String getTenantName() { return tenantName; }
        public void setTenantName(String v) { this.tenantName = v; }
        public String getEnrollmentToken() { return enrollmentToken; }
        public void setEnrollmentToken(String v) { this.enrollmentToken = v; }
    }
}
