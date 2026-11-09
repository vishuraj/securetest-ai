package com.securetest.core.model;

import com.securetest.core.model.Enums.Confidence;
import com.securetest.core.model.Enums.FindingStatus;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Normalized issue, vulnerability, defect, observation or compliance gap (SRS 7.2, 12).
 * Public fields keep the DTO trivially serializable by any JSON mapper.
 */
public class Finding {
    // identity
    public String id;
    public String fingerprint;
    public String moduleId;
    /** Scanner / adapter id that produced the finding. */
    public String source;
    public String sourceToolVersion;
    public String ruleId;
    public String category;

    // description
    public String title;
    public String description;
    public String impact;
    public String remediation;
    public List<String> references = new ArrayList<>();
    /** Tags such as "OWASP-A05", "ASVS-14.4", "CIS-K8S-5.2.1" used by the compliance mapper. */
    public List<String> complianceTags = new ArrayList<>();

    // rating
    /** Severity as reported by the source tool, preserved verbatim (normalized to the enum). */
    public Severity sourceSeverity = Severity.INFO;
    public String sourceSeverityRaw;
    /** SecureTest normalized priority. */
    public Severity priority;
    public List<String> priorityRationale = new ArrayList<>();
    public Confidence confidence = Confidence.MEDIUM;
    public String exposure;          // e.g. "internet", "internal", "local"
    public Boolean reachable;        // null = unknown
    public String effort;            // e.g. "S", "M", "L"

    // location
    public String asset;             // application, host, image, url...
    public String filePath;          // relative to the source root
    public Integer lineStart;
    public Integer lineEnd;
    public List<CodeLine> snippet = new ArrayList<>();
    public String revision;          // git commit (or "workspace") at scan time
    public String fileHash;          // sha-256 of the file at scan time

    // dependency info (SCA)
    public DependencyInfo dependency;

    // evidence
    public String evidence;          // sanitized request/response, log excerpt, etc.
    public Map<String, String> attributes = new LinkedHashMap<>();
    public String fixId;             // id understood by a FixProvider, when an automated patch exists

    // workflow
    public FindingStatus status = FindingStatus.OPEN;
    public String owner;
    public Instant dueDate;
    public Instant firstDetected;
    public Instant lastDetected;
    public String lastScanId;
    public int occurrences;
    public boolean regression;
    public Suppression suppression;
    public List<String> relatedFindingIds = new ArrayList<>();
    public List<HistoryEntry> history = new ArrayList<>();

    public Finding() { }

    // ------------------------------------------------------------------ fluent helpers for scanners

    public static Finding of(String moduleId, String source, String ruleId, String title, Severity severity) {
        Finding f = new Finding();
        f.moduleId = moduleId;
        f.source = source;
        f.ruleId = ruleId;
        f.title = title;
        f.sourceSeverity = severity;
        f.sourceSeverityRaw = severity.name();
        return f;
    }

    public Finding description(String v) { this.description = v; return this; }
    public Finding impact(String v) { this.impact = v; return this; }
    public Finding remediation(String v) { this.remediation = v; return this; }
    public Finding category(String v) { this.category = v; return this; }
    public Finding confidence(Confidence v) { this.confidence = v; return this; }
    public Finding asset(String v) { this.asset = v; return this; }
    public Finding evidence(String v) { this.evidence = v; return this; }
    public Finding exposure(String v) { this.exposure = v; return this; }
    public Finding effort(String v) { this.effort = v; return this; }
    public Finding fix(String fixId) { this.fixId = fixId; return this; }
    public Finding rawSeverity(String raw) { this.sourceSeverityRaw = raw; return this; }
    public Finding toolVersion(String v) { this.sourceToolVersion = v; return this; }

    public Finding location(String file, Integer start, Integer end) {
        this.filePath = file;
        this.lineStart = start;
        this.lineEnd = end == null ? start : end;
        return this;
    }

    public Finding refs(String... urls) { references.addAll(List.of(urls)); return this; }
    public Finding tags(String... tags) { complianceTags.addAll(List.of(tags)); return this; }
    public Finding attr(String k, String v) { if (v != null) attributes.put(k, v); return this; }

    public boolean isOpen() {
        return status == FindingStatus.OPEN || status == FindingStatus.IN_PROGRESS;
    }

    public void addHistory(String actor, String action, String detail) {
        history.add(new HistoryEntry(Instant.now(), actor, action, detail));
        if (history.size() > 200) history.remove(0);
    }

    // ------------------------------------------------------------------ nested value types

    public static class CodeLine {
        public int number;
        public String text;
        public boolean highlighted;

        public CodeLine() { }
        public CodeLine(int number, String text, boolean highlighted) {
            this.number = number;
            this.text = text;
            this.highlighted = highlighted;
        }
    }

    public static class DependencyInfo {
        public String packageName;     // group:artifact
        public String installedVersion;
        public String fixedVersion;
        public String advisoryId;      // GHSA / OSV id
        public List<String> aliases = new ArrayList<>(); // CVE ids
        public Double cvssScore;
        public String cvssVector;
        public List<String> dependencyPath = new ArrayList<>();
        public String license;

        public DependencyInfo() { }
        public DependencyInfo(String packageName, String installedVersion) {
            this.packageName = packageName;
            this.installedVersion = installedVersion;
        }
    }

    public static class Suppression {
        public String reason;
        public String owner;
        public Instant expiresAt;
        public String createdBy;
        public String approvedBy;
        public Instant createdAt;
        public FindingStatus resultingStatus;

        public boolean expired(Instant now) { return expiresAt != null && now.isAfter(expiresAt); }
    }

    public record HistoryEntry(Instant at, String actor, String action, String detail) { }
}
