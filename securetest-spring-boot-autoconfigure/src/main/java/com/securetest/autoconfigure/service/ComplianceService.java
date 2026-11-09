package com.securetest.autoconfigure.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.securetest.autoconfigure.support.LocalStore;
import com.securetest.core.model.Enums.ControlStatus;
import com.securetest.core.model.Enums.JobStatus;
import com.securetest.core.model.Finding;
import com.securetest.core.model.ModuleCatalog;
import com.securetest.core.model.ScanJob;
import com.securetest.core.model.Severity;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Maps technical findings and scan coverage to framework controls (SRS 5.12). Technical evidence support only:
 * not legal advice and not a certification.
 */
public class ComplianceService {

    public static final String DISCLAIMER = "Compliance mappings are technical evidence support, not legal certification or a compliance guarantee. "
            + "Controls marked PASS only mean no mapped automated finding is open for the assessed scope.";

    public record Control(String framework, String id, String title, List<String> tagPrefixes, List<String> modules) { }

    public record ControlResult(String framework, String id, String title, ControlStatus status, String rationale,
                                List<String> openFindings, List<String> evidenceScans, List<String> assessedBy, String notApplicableReason) { }

    public static class Applicability {
        public String reason;
        public String by;
        public Instant at;
    }

    private static final List<String> SEC = List.of(ModuleCatalog.CODE_QUALITY, ModuleCatalog.API_SECURITY, ModuleCatalog.VULNERABILITY);

    public static final List<Control> CONTROLS = List.of(
            // OWASP Top 10 2021
            c("OWASP Top 10 2021", "A01", "Broken Access Control", List.of("OWASP-A01"), ModuleCatalog.API_SECURITY, ModuleCatalog.CODE_QUALITY, ModuleCatalog.TESTING),
            c("OWASP Top 10 2021", "A02", "Cryptographic Failures", List.of("OWASP-A02"), ModuleCatalog.CODE_QUALITY, ModuleCatalog.NETWORK_SECURITY),
            c("OWASP Top 10 2021", "A03", "Injection", List.of("OWASP-A03"), ModuleCatalog.CODE_QUALITY, ModuleCatalog.API_SECURITY),
            c("OWASP Top 10 2021", "A04", "Insecure Design", List.of("OWASP-A04"), ModuleCatalog.CODE_QUALITY),
            c("OWASP Top 10 2021", "A05", "Security Misconfiguration", List.of("OWASP-A05"), ModuleCatalog.API_SECURITY, ModuleCatalog.COMPLIANCE, ModuleCatalog.CLOUD_SECURITY),
            c("OWASP Top 10 2021", "A06", "Vulnerable and Outdated Components", List.of("OWASP-A06"), ModuleCatalog.VULNERABILITY),
            c("OWASP Top 10 2021", "A07", "Identification and Authentication Failures", List.of("OWASP-A07"), ModuleCatalog.VULNERABILITY, ModuleCatalog.CODE_QUALITY, ModuleCatalog.COMPLIANCE),
            c("OWASP Top 10 2021", "A08", "Software and Data Integrity Failures", List.of("OWASP-A08"), ModuleCatalog.CODE_QUALITY, ModuleCatalog.VULNERABILITY),
            c("OWASP Top 10 2021", "A09", "Security Logging and Monitoring Failures", List.of("OWASP-A09"), ModuleCatalog.COMPLIANCE, ModuleCatalog.ADVANCED_SECURITY),
            c("OWASP Top 10 2021", "A10", "Server-Side Request Forgery", List.of("OWASP-A10", "CWE-918"), ModuleCatalog.CODE_QUALITY, ModuleCatalog.API_SECURITY),
            // OWASP ASVS 4.0 chapters
            c("OWASP ASVS 4.0", "V2", "Authentication", List.of("ASVS-2."), ModuleCatalog.CODE_QUALITY, ModuleCatalog.VULNERABILITY),
            c("OWASP ASVS 4.0", "V3", "Session Management", List.of("ASVS-3."), ModuleCatalog.API_SECURITY, ModuleCatalog.COMPLIANCE),
            c("OWASP ASVS 4.0", "V4", "Access Control", List.of("ASVS-4."), ModuleCatalog.CODE_QUALITY, ModuleCatalog.TESTING),
            c("OWASP ASVS 4.0", "V5", "Validation, Sanitization and Encoding", List.of("ASVS-5."), ModuleCatalog.CODE_QUALITY, ModuleCatalog.API_SECURITY),
            c("OWASP ASVS 4.0", "V6", "Stored Cryptography", List.of("ASVS-6."), ModuleCatalog.CODE_QUALITY),
            c("OWASP ASVS 4.0", "V7", "Error Handling and Logging", List.of("ASVS-7."), ModuleCatalog.CODE_QUALITY, ModuleCatalog.API_SECURITY),
            c("OWASP ASVS 4.0", "V9", "Communication", List.of("ASVS-9."), ModuleCatalog.NETWORK_SECURITY),
            c("OWASP ASVS 4.0", "V12", "Files and Resources", List.of("ASVS-12."), ModuleCatalog.CODE_QUALITY, ModuleCatalog.API_SECURITY),
            c("OWASP ASVS 4.0", "V13", "API and Web Service", List.of("ASVS-13.", "OWASP-API"), ModuleCatalog.TESTING, ModuleCatalog.API_SECURITY),
            c("OWASP ASVS 4.0", "V14", "Configuration", List.of("ASVS-14."), ModuleCatalog.API_SECURITY, ModuleCatalog.COMPLIANCE),
            // CIS
            c("CIS Benchmarks", "CIS-DOCKER", "Docker image and runtime configuration", List.of("CIS-DOCKER"), ModuleCatalog.CLOUD_SECURITY),
            c("CIS Benchmarks", "CIS-K8S", "Kubernetes workload policies", List.of("CIS-K8S", "NSA-K8S"), ModuleCatalog.CLOUD_SECURITY),
            c("CIS Benchmarks", "CIS-CLOUD", "Cloud account foundations", List.of("CIS-AWS", "CIS-CLOUD"), ModuleCatalog.CLOUD_SECURITY),
            c("CIS Benchmarks", "CIS-SECRETS", "Secrets management", List.of("CIS-SECRETS"), ModuleCatalog.VULNERABILITY, ModuleCatalog.COMPLIANCE),
            c("CIS Benchmarks", "CIS-NETWORK", "Network exposure and TLS", List.of("CIS-NETWORK", "CIS-TLS"), ModuleCatalog.NETWORK_SECURITY),
            // ISO 27001:2022 Annex A themes
            c("ISO/IEC 27001:2022", "A.8.8", "Management of technical vulnerabilities", List.of("ISO27001-A.8.8", "OWASP-A06"), ModuleCatalog.VULNERABILITY),
            c("ISO/IEC 27001:2022", "A.8.9", "Configuration management", List.of("ISO27001-A.8.9", "OWASP-A05", "CIS-"), ModuleCatalog.COMPLIANCE, ModuleCatalog.CLOUD_SECURITY),
            c("ISO/IEC 27001:2022", "A.8.16", "Monitoring activities", List.of("ISO27001-A.8.16", "OWASP-A09"), ModuleCatalog.ADVANCED_SECURITY, ModuleCatalog.COMPLIANCE),
            c("ISO/IEC 27001:2022", "A.8.20", "Network security", List.of("ISO27001-A.8.20", "CIS-NETWORK"), ModuleCatalog.NETWORK_SECURITY),
            c("ISO/IEC 27001:2022", "A.8.24", "Use of cryptography", List.of("ISO27001-A.8.24", "OWASP-A02"), ModuleCatalog.CODE_QUALITY, ModuleCatalog.NETWORK_SECURITY),
            c("ISO/IEC 27001:2022", "A.8.28", "Secure coding", List.of("OWASP-A03", "OWASP-A04", "OWASP-A08", "CWE-"), ModuleCatalog.CODE_QUALITY),
            c("ISO/IEC 27001:2022", "A.8.29", "Security testing in development and acceptance", List.of("ISO27001-A.8.29"), ModuleCatalog.TESTING, ModuleCatalog.API_SECURITY),
            // SOC 2
            c("SOC 2 (TSC 2017)", "CC6.1", "Logical access security", List.of("SOC2-CC6.1", "OWASP-A01", "OWASP-A07"), ModuleCatalog.COMPLIANCE, ModuleCatalog.API_SECURITY),
            c("SOC 2 (TSC 2017)", "CC6.7", "Transmission of data", List.of("PCI-4.2", "ASVS-9."), ModuleCatalog.NETWORK_SECURITY),
            c("SOC 2 (TSC 2017)", "CC7.1", "Detection of vulnerabilities and configuration changes", List.of("SOC2-CC7.1", "OWASP-A06", "OWASP-A05"), ModuleCatalog.VULNERABILITY, ModuleCatalog.COMPLIANCE),
            c("SOC 2 (TSC 2017)", "CC7.2", "Monitoring of system components", List.of("SOC2-CC7.2", "OWASP-A09"), ModuleCatalog.ADVANCED_SECURITY),
            c("SOC 2 (TSC 2017)", "CC8.1", "Change management (testing of changes)", List.of("SOC2-CC8.1"), ModuleCatalog.TESTING),
            // GDPR
            c("GDPR (technical)", "Art.32", "Security of processing (encryption, confidentiality, testing)", List.of("GDPR-32", "OWASP-A02"), ModuleCatalog.CODE_QUALITY, ModuleCatalog.CLOUD_SECURITY, ModuleCatalog.COMPLIANCE),
            c("GDPR (technical)", "Art.5(1)(f)", "Integrity and confidentiality of personal data", List.of("GDPR-32", "CIS-SECRETS", "OWASP-A01"), ModuleCatalog.VULNERABILITY, ModuleCatalog.API_SECURITY),
            // PCI DSS 4.0
            c("PCI DSS 4.0", "1.3", "Network access to/from the cardholder data environment is restricted", List.of("PCI-1."), ModuleCatalog.NETWORK_SECURITY, ModuleCatalog.CLOUD_SECURITY),
            c("PCI DSS 4.0", "2.2", "System components are configured securely", List.of("PCI-2.", "OWASP-A05"), ModuleCatalog.COMPLIANCE),
            c("PCI DSS 4.0", "3.5-3.6", "Stored account data and keys are protected", List.of("PCI-3."), ModuleCatalog.CODE_QUALITY, ModuleCatalog.VULNERABILITY),
            c("PCI DSS 4.0", "4.2", "Strong cryptography during transmission", List.of("PCI-4."), ModuleCatalog.NETWORK_SECURITY),
            c("PCI DSS 4.0", "6.2.4", "Software engineering techniques prevent common attacks", List.of("PCI-6.2.4", "OWASP-A03"), ModuleCatalog.CODE_QUALITY, ModuleCatalog.API_SECURITY),
            c("PCI DSS 4.0", "6.3.3", "Security patches are installed", List.of("PCI-6.3.3"), ModuleCatalog.VULNERABILITY),
            c("PCI DSS 4.0", "8.2-8.3", "User identification and strong authentication", List.of("PCI-8."), ModuleCatalog.VULNERABILITY, ModuleCatalog.COMPLIANCE),
            c("PCI DSS 4.0", "10.4", "Audit logs are reviewed", List.of("PCI-10."), ModuleCatalog.ADVANCED_SECURITY)
    );

    private static Control c(String fw, String id, String title, List<String> tags, String... modules) {
        return new Control(fw, id, title, tags, List.of(modules));
    }

    private final FindingService findings;
    private final JobService jobs;
    private final LocalStore store;
    private final Map<String, Applicability> notApplicable;

    public ComplianceService(FindingService findings, JobService jobs, LocalStore store) {
        this.findings = findings;
        this.jobs = jobs;
        this.store = store;
        this.notApplicable = new ConcurrentHashMap<>(store.load("compliance", new TypeReference<Map<String, Applicability>>() { }, LinkedHashMap::new));
        store.register("compliance", () -> new LinkedHashMap<>(notApplicable));
    }

    public static String key(Control c) { return c.framework() + "|" + c.id(); }

    public List<ControlResult> evaluate() {
        List<Finding> open = findings.all().stream().filter(Finding::isOpen).toList();
        Map<String, ScanJob> lastCompletedByModule = new LinkedHashMap<>();
        for (ScanJob j : jobs.all()) {
            if (j.status != JobStatus.COMPLETED) continue;
            ScanJob prev = lastCompletedByModule.get(j.moduleId);
            if (prev == null || j.createdAt.isAfter(prev.createdAt)) lastCompletedByModule.put(j.moduleId, j);
        }
        List<ControlResult> out = new ArrayList<>();
        for (Control c : CONTROLS) {
            Applicability na = notApplicable.get(key(c));
            if (na != null) {
                out.add(new ControlResult(c.framework(), c.id(), c.title(), ControlStatus.NOT_APPLICABLE, "Marked not applicable by " + na.by,
                        List.of(), List.of(), List.of(), na.reason));
                continue;
            }
            List<Finding> mapped = open.stream().filter(f -> f.complianceTags.stream().anyMatch(t -> c.tagPrefixes().stream().anyMatch(t::startsWith))).toList();
            List<String> assessed = c.modules().stream().filter(lastCompletedByModule::containsKey).toList();
            List<String> evidence = assessed.stream().map(m -> {
                ScanJob j = lastCompletedByModule.get(m);
                return j.id + " (" + j.scannerName + ", " + j.toolVersion + ", " + j.endedAt + ")";
            }).toList();
            ControlStatus status;
            String rationale;
            if (!mapped.isEmpty()) {
                boolean severe = mapped.stream().anyMatch(f -> (f.priority == null ? f.sourceSeverity : f.priority).atLeast(Severity.HIGH));
                status = severe ? ControlStatus.FAIL : ControlStatus.PARTIAL;
                rationale = mapped.size() + " open finding(s) mapped to this control" + (severe ? " including High/Critical." : " (Medium or lower).");
            } else if (assessed.isEmpty()) {
                status = ControlStatus.NOT_ASSESSED;
                rationale = "No completed scan from relevant modules: " + c.modules();
            } else if (assessed.size() < c.modules().size()) {
                status = ControlStatus.PARTIAL;
                rationale = "No open findings, but only " + assessed.size() + " of " + c.modules().size() + " relevant modules were assessed.";
            } else {
                status = ControlStatus.PASS;
                rationale = "All relevant modules assessed with no open mapped findings.";
            }
            out.add(new ControlResult(c.framework(), c.id(), c.title(), status, rationale,
                    mapped.stream().map(f -> f.id).limit(50).toList(), evidence, assessed, null));
        }
        return out;
    }

    public Map<String, Object> summary() {
        Map<String, Map<String, Integer>> byFramework = new LinkedHashMap<>();
        for (ControlResult r : evaluate()) {
            byFramework.computeIfAbsent(r.framework(), k -> new LinkedHashMap<>()).merge(r.status().name(), 1, Integer::sum);
        }
        return Map.of("frameworks", byFramework, "disclaimer", DISCLAIMER);
    }

    public void setNotApplicable(String framework, String id, boolean na, String reason, String actor) {
        String k = framework + "|" + id;
        if (CONTROLS.stream().noneMatch(c -> key(c).equals(k))) throw com.securetest.autoconfigure.security.ApiException.notFound("Control " + k);
        if (na) {
            if (reason == null || reason.isBlank()) throw com.securetest.autoconfigure.security.ApiException.badRequest("A rationale is required.");
            Applicability a = new Applicability();
            a.reason = reason;
            a.by = actor;
            a.at = Instant.now();
            notApplicable.put(k, a);
        } else {
            notApplicable.remove(k);
        }
        store.markDirty("compliance");
    }
}
