package com.securetest.reporting;

import com.securetest.core.model.Finding;
import com.securetest.core.model.Severity;

import java.time.Instant;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Format-independent report content (SRS 8.2). Writers render it to PDF, XLSX, CSV. */
public class ReportDocument {

    public String reportId;
    public String type;
    public String title;
    public String organization = "SecureTest AI";
    public String classification = "INTERNAL";
    public String owner;
    public ZoneId zone = ZoneId.systemDefault();
    public Instant generatedAt = Instant.now();
    public String applicationName;
    public String environment;
    public String revision;
    public String snapshotVersion;
    public String scope;
    public String executiveSummary;
    public Map<Severity, Integer> severityCounts = new EnumMap<>(Severity.class);
    public Map<String, String> metadata = new LinkedHashMap<>();
    public List<String> recommendations = new ArrayList<>();
    public List<String> limitations = new ArrayList<>();
    public List<Finding> findings = new ArrayList<>();
    /** Additional tables (Assets, Scan Metadata, Remediation, Compliance Evidence, Performance...). */
    public List<Table> tables = new ArrayList<>();
    /** Set by the generator once the primary file is written. */
    public String checksum;

    public record Table(String title, List<String> headers, List<List<String>> rows) { }

    public void addTable(String title, List<String> headers, List<List<String>> rows) {
        tables.add(new Table(title, headers, rows));
    }
}
