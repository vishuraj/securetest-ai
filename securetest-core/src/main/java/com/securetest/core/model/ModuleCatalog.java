package com.securetest.core.model;

import java.util.List;
import java.util.Optional;

/** The feature modules shown in the navigation (SRS 5.2). Every module is independently toggleable. */
public final class ModuleCatalog {

    public record ModuleInfo(String id, String name, String summary, boolean defaultEnabled, String help) { }

    public static final String HEALTH = "health";
    public static final String METRICS = "metrics";
    public static final String TESTING = "testing";
    public static final String CODE_QUALITY = "code-quality";
    public static final String VULNERABILITY = "vulnerability";
    public static final String API_SECURITY = "api-security";
    public static final String PERFORMANCE = "performance";
    public static final String COMPLIANCE = "compliance";
    public static final String NETWORK_SECURITY = "network-security";
    public static final String ADVANCED_SECURITY = "advanced-security";
    public static final String CLOUD_SECURITY = "cloud-security";
    public static final String MIGRATION = "migration";

    public static final List<ModuleInfo> MODULES = List.of(
            new ModuleInfo(HEALTH, "Health", "Application health and baseline JVM snapshot.", true,
                    "Reads health indicators and JVM MXBeans on demand. No background polling."),
            new ModuleInfo(METRICS, "Runtime Metrics", "Sampled CPU, memory, GC, thread and HTTP metrics with history and thresholds.", false,
                    "When enabled, a low-frequency sampler records metric history and HTTP request timings."),
            new ModuleInfo(TESTING, "Testing", "Unit/integration result import, coverage, API contract tests, manual and exploratory testing.", false,
                    "Imports JUnit/TestNG XML and JaCoCo reports from the workspace. Test commands only run when allowlisted."),
            new ModuleInfo(CODE_QUALITY, "Code Quality", "Static analysis with built-in rules and SonarQube integration.", false,
                    "Needs read access to the source workspace (securetest.workspace.source-root) or a SonarQube server."),
            new ModuleInfo(VULNERABILITY, "Vulnerability", "Dependency inventory, SBOM, OSV/Trivy vulnerability intelligence, licenses and secrets.", false,
                    "Inventory and SBOM are local. Online vulnerability lookups need explicit opt-in."),
            new ModuleInfo(API_SECURITY, "API Security", "Security headers, CORS, exposure checks, passive/active DAST and OWASP ZAP integration.", false,
                    "Targets must be on the allowlist. Active probes need confirmation and an approver."),
            new ModuleInfo(PERFORMANCE, "Performance", "Bounded load tests, latency percentiles, baselines and JMeter integration.", false,
                    "Load generation inside the application JVM is blocked unless explicitly allowed."),
            new ModuleInfo(COMPLIANCE, "Compliance", "Configuration posture and mapping to OWASP, ASVS, CIS, ISO 27001, SOC 2, GDPR and PCI DSS.", false,
                    "Technical evidence support only: not legal certification."),
            new ModuleInfo(NETWORK_SECURITY, "Network / System", "TLS/certificate posture and authorized port exposure checks.", false,
                    "Only hosts on the allowlist can be checked. Port checks are active scans."),
            new ModuleInfo(ADVANCED_SECURITY, "Advanced Security", "Import and correlation of runtime security alerts (Falco, Wazuh, SIEM webhooks).", false,
                    "SecureTest does not prevent attacks itself; it correlates and explains alerts."),
            new ModuleInfo(CLOUD_SECURITY, "Cloud / Kubernetes", "Dockerfile, Kubernetes, Compose and Terraform checks; Checkov, Trivy and Prowler adapters.", false,
                    "Cloud account checks use your installed tools and least-privilege read-only credentials."),
            new ModuleInfo(MIGRATION, "Migration", "Java, Spring Boot, javax→jakarta and build modernization with diff, apply and undo.", false,
                    "Analysis never changes files. Applying changes needs policy opt-in, approval and a rollback point.")
    );

    private ModuleCatalog() { }

    public static Optional<ModuleInfo> find(String id) {
        return MODULES.stream().filter(m -> m.id().equals(id)).findFirst();
    }
}
