package com.securetest.autoconfigure.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.securetest.autoconfigure.SecureTestProperties;
import com.securetest.autoconfigure.security.ApiException;
import com.securetest.autoconfigure.security.SecureTestPrincipal;
import com.securetest.autoconfigure.support.AppContext;
import com.securetest.autoconfigure.support.LocalStore;
import com.securetest.core.model.Enums.ControlStatus;
import com.securetest.core.model.Enums.JobStatus;
import com.securetest.core.model.Finding;
import com.securetest.core.model.ModuleCatalog;
import com.securetest.core.model.ScanJob;
import com.securetest.core.model.Severity;
import com.securetest.core.util.Hashing;
import com.securetest.migration.MigrationModels.MigrationRun;
import com.securetest.reporting.CsvReportWriter;
import com.securetest.reporting.PdfReportWriter;
import com.securetest.reporting.ReportDocument;
import com.securetest.reporting.XlsxReportWriter;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/** Report generation (SRS 8): asynchronous, in PDF / XLSX / JSON / CSV, with metadata and integrity checksums. */
public class ReportService {

    public static final Map<String, String> TYPES = new LinkedHashMap<>();

    static {
        TYPES.put("executive", "Executive application posture report");
        TYPES.put("technical", "Detailed technical findings report");
        TYPES.put("security", "Security / vulnerability report");
        TYPES.put("code-quality", "Code quality and coverage report");
        TYPES.put("performance", "Performance / load-test report");
        TYPES.put("cloud-network", "Cloud, network and container assessment report");
        TYPES.put("compliance", "Compliance evidence report");
        TYPES.put("migration", "Migration assessment and execution report");
        TYPES.put("remediation", "Remediation progress and SLA report");
    }

    public static class Report {
        public String id;
        public String type;
        public String title;
        public String status;
        public String error;
        public String generatedBy;
        public Instant requestedAt;
        public Instant generatedAt;
        public Map<String, String> filters = new LinkedHashMap<>();
        public Map<String, Map<String, Object>> files = new LinkedHashMap<>();
        public int findings;
        public String snapshotVersion;
        public String checksum;
    }

    // Boxed so a missing JSON field means false on every Jackson version (Jackson 3 rejects null for primitives).
    public record Request(String type, String title, List<String> modules, String minPriority, Boolean includeClosed, String migrationId) {
        public Request {
            includeClosed = Boolean.TRUE.equals(includeClosed);
        }
    }

    private final SecureTestProperties props;
    private final AppContext app;
    private final FindingService findings;
    private final JobService jobs;
    private final ComplianceService compliance;
    private final MigrationService migrations;
    private final ChangeSetService changes;
    private final ModuleService modules;
    private final AuditService audit;
    private final NotificationService notifications;
    private final LocalStore store;
    private final Map<String, Report> reports;
    private final ExecutorService executor = Executors.newSingleThreadExecutor(r -> {
        Thread t = new Thread(r, "securetest-report");
        t.setDaemon(true);
        t.setPriority(Thread.NORM_PRIORITY - 1);
        return t;
    });

    public ReportService(SecureTestProperties props, AppContext app, FindingService findings, JobService jobs, ComplianceService compliance,
                         MigrationService migrations, ChangeSetService changes, ModuleService modules, AuditService audit,
                         NotificationService notifications, LocalStore store) {
        this.props = props;
        this.app = app;
        this.findings = findings;
        this.jobs = jobs;
        this.compliance = compliance;
        this.migrations = migrations;
        this.changes = changes;
        this.modules = modules;
        this.audit = audit;
        this.notifications = notifications;
        this.store = store;
        this.reports = new ConcurrentHashMap<>(store.load("reports", new TypeReference<Map<String, Report>>() { }, LinkedHashMap::new));
        reports.values().stream().filter(r -> "GENERATING".equals(r.status)).forEach(r -> { r.status = "FAILED"; r.error = "Interrupted by restart"; });
        store.register("reports", () -> new LinkedHashMap<>(reports));
    }

    public Report request(Request req, SecureTestPrincipal p) {
        if (!TYPES.containsKey(req.type())) throw ApiException.badRequest("Unknown report type. Use one of " + TYPES.keySet());
        Report r = new Report();
        r.id = "R-" + UUID.randomUUID().toString().substring(0, 8).toUpperCase();
        r.type = req.type();
        r.title = req.title() == null || req.title().isBlank() ? TYPES.get(req.type()) : req.title();
        r.status = "GENERATING";
        r.generatedBy = p.name();
        r.requestedAt = Instant.now();
        if (req.modules() != null && !req.modules().isEmpty()) r.filters.put("modules", String.join(",", req.modules()));
        if (req.minPriority() != null) r.filters.put("minPriority", req.minPriority());
        r.filters.put("includeClosed", String.valueOf(req.includeClosed()));
        if (req.migrationId() != null) r.filters.put("migrationId", req.migrationId());
        reports.put(r.id, r);
        store.markDirty("reports");
        audit.record(p, "report.requested", r.id, "GENERATING", Map.of("type", r.type));
        executor.submit(() -> generate(r, req));
        return r;
    }

    private void generate(Report r, Request req) {
        try {
            ReportDocument doc = build(r, req);
            Path dir = store.subdir("reports");
            Map<String, byte[]> out = new LinkedHashMap<>();
            out.put("pdf", new PdfReportWriter().write(doc));
            out.put("xlsx", new XlsxReportWriter().write(doc));
            out.put("csv", new CsvReportWriter().write(doc));
            out.put("json", store.mapper().writerWithDefaultPrettyPrinter().writeValueAsBytes(doc));
            for (Map.Entry<String, byte[]> e : out.entrySet()) {
                Files.write(dir.resolve(r.id + "." + e.getKey()), e.getValue());
                Map<String, Object> meta = new LinkedHashMap<>();
                meta.put("size", e.getValue().length);
                meta.put("sha256", Hashing.sha256(e.getValue()));
                r.files.put(e.getKey(), meta);
            }
            r.checksum = (String) r.files.get("pdf").get("sha256");
            r.findings = doc.findings.size();
            r.snapshotVersion = doc.snapshotVersion;
            r.generatedAt = Instant.now();
            r.status = "READY";
            notifications.publish("report.ready", "Report " + r.title + " (" + r.id + ") is ready", Map.of("reportId", r.id));
        } catch (Exception e) {
            r.status = "FAILED";
            r.error = e.getClass().getSimpleName() + ": " + e.getMessage();
        } finally {
            store.markDirty("reports");
        }
    }

    ReportDocument build(Report r, Request req) {
        ReportDocument d = new ReportDocument();
        d.reportId = r.id;
        d.type = r.type;
        d.title = r.title;
        d.owner = r.generatedBy;
        d.organization = props.getReports().getOrganization();
        d.classification = props.getReports().getClassification();
        if (props.getReports().getTimezone() != null) d.zone = ZoneId.of(props.getReports().getTimezone());
        d.applicationName = app.name();
        d.environment = app.environmentName();
        d.revision = app.sourceRoot().map(root -> new com.securetest.migration.GitWorkspace(props.getExecution().isGitEnabled()).head(root).orElse("workspace")).orElse("n/a");
        d.snapshotVersion = "findings-rev-" + findings.revision() + " @ " + Instant.now();
        d.generatedAt = Instant.now();

        Set<String> scope = scopeModules(r.type, req.modules());
        Severity min = req.minPriority() == null ? Severity.INFO : Severity.valueOf(req.minPriority());
        List<Finding> list = findings.all().stream()
                .filter(f -> scope.isEmpty() || scope.contains(f.moduleId))
                .filter(f -> req.includeClosed() || f.isOpen())
                .filter(f -> (f.priority == null ? f.sourceSeverity : f.priority).atLeast(min))
                .sorted(Comparator.comparingInt((Finding f) -> -(f.priority == null ? f.sourceSeverity : f.priority).rank()))
                .toList();
        if (r.type.equals("executive")) list = list.stream().limit(15).toList();
        d.findings = new ArrayList<>(list);
        for (Severity s : Severity.values()) d.severityCounts.put(s, 0);
        findings.all().stream().filter(f -> scope.isEmpty() || scope.contains(f.moduleId)).filter(Finding::isOpen)
                .forEach(f -> d.severityCounts.merge(f.priority == null ? f.sourceSeverity : f.priority, 1, Integer::sum));
        d.scope = "Application " + app.name() + " (" + app.info().serviceId() + "), environment " + app.environmentName()
                + ". Modules: " + (scope.isEmpty() ? "all" : String.join(", ", scope)) + ". Minimum priority: " + min.label()
                + (req.includeClosed() ? ". Includes closed findings." : ". Open findings only.");
        int open = d.severityCounts.values().stream().mapToInt(Integer::intValue).sum();
        d.executiveSummary = open + " open finding(s) in scope: " + d.severityCounts.get(Severity.CRITICAL) + " critical, "
                + d.severityCounts.get(Severity.HIGH) + " high, " + d.severityCounts.get(Severity.MEDIUM) + " medium, "
                + d.severityCounts.get(Severity.LOW) + " low, " + d.severityCounts.get(Severity.INFO) + " informational. "
                + gateSentence();

        var info = app.info();
        d.metadata.put("Service ID", info.serviceId());
        d.metadata.put("Application version", String.valueOf(info.version()));
        d.metadata.put("Runtime", "Java " + info.javaVersion() + " (" + info.javaVendor() + "), Spring Boot " + info.springBootVersion());
        d.metadata.put("Build tool", info.buildTool());
        d.metadata.put("SecureTest version", "1.0.1");
        d.metadata.put("Time zone", d.zone.getId());

        List<ScanJob> scans = jobs.all().stream().filter(j -> scope.isEmpty() || scope.contains(j.moduleId))
                .sorted(Comparator.comparing((ScanJob j) -> j.createdAt).reversed()).limit(200).toList();
        Set<String> tools = new LinkedHashSet<>();
        scans.stream().filter(j -> j.status == JobStatus.COMPLETED).forEach(j -> tools.add(j.scannerName + " — " + j.toolVersion));
        d.metadata.put("Tool versions", tools.isEmpty() ? "No completed scans in scope" : String.join("; ", tools));

        d.addTable("Scan Metadata", List.of("Scan", "Scanner", "Tool", "Status", "Requested by", "Approved by", "Started", "Duration (s)", "Findings"),
                scans.stream().map(j -> List.of(j.id, j.scannerName, String.valueOf(j.toolVersion), j.status.name(), String.valueOf(j.requestedBy),
                        String.valueOf(j.approvedBy == null ? "" : j.approvedBy), String.valueOf(j.startedAt),
                        j.getDurationMs() == null ? "" : String.valueOf(j.getDurationMs() / 1000), String.valueOf(j.findingsCount))).toList());
        Map<String, int[]> assets = new LinkedHashMap<>();
        list.forEach(f -> {
            int[] c = assets.computeIfAbsent(f.asset == null ? "(application)" : f.asset, k -> new int[2]);
            c[0]++;
            if ((f.priority == null ? f.sourceSeverity : f.priority).atLeast(Severity.HIGH)) c[1]++;
        });
        d.addTable("Assets", List.of("Asset", "Findings", "High or Critical"),
                assets.entrySet().stream().limit(500).map(e -> List.of(e.getKey(), String.valueOf(e.getValue()[0]), String.valueOf(e.getValue()[1]))).toList());

        switch (r.type) {
            case "executive" -> executive(d);
            case "code-quality" -> codeQuality(d);
            case "performance" -> performance(d);
            case "compliance" -> complianceTables(d);
            case "migration" -> migration(d, req.migrationId());
            case "remediation" -> remediation(d, list);
            default -> { }
        }
        if (!r.type.equals("executive") && !r.type.equals("compliance")) remediationTable(d, list);
        recommendations(d, list);
        d.limitations.add("Embedded runtime analysis cannot see build-time artifacts; source checks cover the configured workspace only.");
        d.limitations.add("Findings reflect the state at the data snapshot " + d.snapshotVersion + ".");
        return d;
    }

    private String gateSentence() {
        long crit = findings.openCounts(null).getOrDefault(Severity.CRITICAL, 0);
        long high = findings.openCounts(null).getOrDefault(Severity.HIGH, 0);
        boolean pass = crit <= props.getPolicy().getMaxCritical() && high <= props.getPolicy().getMaxHigh();
        return "Release gate (policy: max " + props.getPolicy().getMaxCritical() + " critical / " + props.getPolicy().getMaxHigh() + " high): "
                + (pass ? "PASS." : "FAIL.");
    }

    private static Set<String> scopeModules(String type, List<String> requested) {
        if (requested != null && !requested.isEmpty()) return new LinkedHashSet<>(requested);
        return switch (type) {
            case "security" -> new LinkedHashSet<>(List.of(ModuleCatalog.VULNERABILITY, ModuleCatalog.API_SECURITY, ModuleCatalog.NETWORK_SECURITY,
                    ModuleCatalog.ADVANCED_SECURITY, ModuleCatalog.CLOUD_SECURITY, ModuleCatalog.CODE_QUALITY, ModuleCatalog.COMPLIANCE));
            case "code-quality" -> new LinkedHashSet<>(List.of(ModuleCatalog.CODE_QUALITY, ModuleCatalog.TESTING));
            case "performance" -> new LinkedHashSet<>(List.of(ModuleCatalog.PERFORMANCE));
            case "cloud-network" -> new LinkedHashSet<>(List.of(ModuleCatalog.CLOUD_SECURITY, ModuleCatalog.NETWORK_SECURITY));
            case "migration" -> new LinkedHashSet<>(List.of(ModuleCatalog.MIGRATION));
            default -> new LinkedHashSet<>();
        };
    }

    private void executive(ReportDocument d) {
        d.addTable("Module Status", List.of("Module", "Enabled", "Last scan", "Status", "Open findings"),
                ModuleCatalog.MODULES.stream().map(m -> {
                    Optional<ScanJob> last = jobs.latestForModule(m.id());
                    int open = findings.openCounts(m.id()).values().stream().mapToInt(Integer::intValue).sum();
                    return List.of(m.name(), String.valueOf(modules.isEnabled(m.id())), last.map(j -> String.valueOf(j.createdAt)).orElse("never"),
                            last.map(j -> j.status.name()).orElse("-"), String.valueOf(open));
                }).toList());
        complianceSummary(d);
    }

    private void complianceSummary(ReportDocument d) {
        Map<String, Map<ControlStatus, Integer>> byFw = new LinkedHashMap<>();
        compliance.evaluate().forEach(c -> byFw.computeIfAbsent(c.framework(), k -> new LinkedHashMap<>()).merge(c.status(), 1, Integer::sum));
        d.addTable("Compliance Summary", List.of("Framework", "Pass", "Partial", "Fail", "Not assessed", "N/A"),
                byFw.entrySet().stream().map(e -> List.of(e.getKey(), n(e.getValue(), ControlStatus.PASS), n(e.getValue(), ControlStatus.PARTIAL),
                        n(e.getValue(), ControlStatus.FAIL), n(e.getValue(), ControlStatus.NOT_ASSESSED), n(e.getValue(), ControlStatus.NOT_APPLICABLE))).toList());
    }

    private static String n(Map<ControlStatus, Integer> m, ControlStatus s) { return String.valueOf(m.getOrDefault(s, 0)); }

    private void complianceTables(ReportDocument d) {
        complianceSummary(d);
        d.addTable("Compliance Evidence", List.of("Framework", "Control", "Title", "Status", "Rationale", "Open findings", "Evidence (scans)"),
                compliance.evaluate().stream().map(c -> List.of(c.framework(), c.id(), c.title(), c.status().name(),
                        c.rationale() + (c.notApplicableReason() != null ? " — " + c.notApplicableReason() : ""),
                        String.join(" ", c.openFindings()), String.join("; ", c.evidenceScans()))).toList());
        d.limitations.add(ComplianceService.DISCLAIMER);
    }

    @SuppressWarnings("unchecked")
    private void codeQuality(ReportDocument d) {
        jobs.latest("builtin-static-analysis", JobStatus.COMPLETED).ifPresent(j -> {
            Map<String, Object> m = (Map<String, Object>) j.results.getOrDefault("metrics", Map.of());
            d.addTable("Code Metrics", List.of("Metric", "Value"), m.entrySet().stream().map(e -> List.of(e.getKey(), String.valueOf(e.getValue()))).toList());
        });
        jobs.latest("sonarqube", JobStatus.COMPLETED).ifPresent(j -> {
            Map<String, Object> m = (Map<String, Object>) j.results.getOrDefault("sonarMeasures", Map.of());
            d.addTable("SonarQube Measures", List.of("Metric", "Value"), m.entrySet().stream().map(e -> List.of(e.getKey(), String.valueOf(e.getValue()))).toList());
        });
        latestTestJob().ifPresent(j -> {
            Map<String, Object> s = (Map<String, Object>) j.results.getOrDefault("testSummary", Map.of());
            List<List<String>> rows = new ArrayList<>(s.entrySet().stream().map(e -> List.of(e.getKey(), String.valueOf(e.getValue()))).toList());
            Map<String, Object> cov = (Map<String, Object>) j.results.get("coverage");
            if (cov != null) {
                rows.add(List.of("lineCoverage", String.valueOf(cov.get("lineCoverage"))));
                rows.add(List.of("branchCoverage", String.valueOf(cov.get("branchCoverage"))));
            }
            d.addTable("Test Results and Coverage", List.of("Metric", "Value"), rows);
        });
    }

    private Optional<ScanJob> latestTestJob() {
        return jobs.all().stream().filter(j -> j.status == JobStatus.COMPLETED && j.results.containsKey("testSummary"))
                .max(Comparator.comparing(j -> j.createdAt));
    }

    @SuppressWarnings("unchecked")
    private void performance(ReportDocument d) {
        List<ScanJob> runs = jobs.all().stream().filter(j -> j.status == JobStatus.COMPLETED
                        && (j.results.containsKey("loadSummary") || j.results.containsKey("jmeterSummary")))
                .sorted(Comparator.comparing((ScanJob j) -> j.createdAt).reversed()).limit(20).toList();
        d.addTable("Load Test Runs", List.of("Scan", "Date", "Target", "Requests", "Throughput (rps)", "p50", "p95", "p99", "Error %", "Gate"),
                runs.stream().map(j -> {
                    Map<String, Object> s = (Map<String, Object>) j.results.getOrDefault("loadSummary", j.results.get("jmeterSummary"));
                    return List.of(j.id, String.valueOf(j.createdAt), String.valueOf(s.getOrDefault("target", j.options.getOrDefault("plan", ""))),
                            String.valueOf(s.get("requests")), String.valueOf(s.get("throughputRps")), String.valueOf(s.getOrDefault("p50Ms", "")),
                            String.valueOf(s.getOrDefault("p95Ms", "")), String.valueOf(s.getOrDefault("p99Ms", "")), String.valueOf(s.get("errorRatePct")),
                            String.valueOf(s.getOrDefault("gate", "")));
                }).toList());
    }

    private void migration(ReportDocument d, String migrationId) {
        List<MigrationRun> list = migrations.list();
        MigrationRun run = migrationId != null ? migrations.get(migrationId) : list.isEmpty() ? null : list.get(0);
        if (run == null) {
            d.limitations.add("No migration assessment exists yet.");
            return;
        }
        var a = run.assessment;
        d.metadata.put("Migration", run.id + " — " + run.status);
        d.metadata.put("Source versions", run.sourceVersions.toString());
        d.metadata.put("Target versions", run.targetVersions.toString());
        d.metadata.put("Baseline", run.baselineRef);
        d.metadata.put("Risk", a.riskScore + "/100 (" + a.riskLevel + "): " + String.join("; ", a.riskFactors));
        d.addTable("Compatibility", List.of("Type", "Message"), new ArrayList<>(a.compatibilityErrors.stream().map(e -> List.of("ERROR", e)).toList()) {{
            addAll(a.compatibilityWarnings.stream().map(w -> List.of("WARNING", w)).toList());
        }});
        d.addTable("Migration Items", List.of("Rule", "Category", "Severity", "File", "Line", "Message", "Automated", "Guidance"),
                a.items.stream().limit(2000).map(i -> List.of(i.id(), i.category(), i.severity(), String.valueOf(i.file()), String.valueOf(i.line()),
                        i.message(), String.valueOf(i.autoFixable()), String.valueOf(i.guidance()))).toList());
        if (run.plan != null) {
            d.addTable("Migration Plan", List.of("#", "Step", "Complexity", "Files", "Automated", "Rollback"),
                    run.plan.steps.stream().map(s -> List.of(String.valueOf(s.order()), s.title(), s.complexity(), String.valueOf(s.affectedFiles().size()),
                            String.valueOf(s.automated()), s.rollback())).toList());
        }
        if (run.changeSetId != null) {
            var cs = changes.get(run.changeSetId);
            d.addTable("Execution", List.of("Field", "Value"), List.of(
                    List.of("Change set", cs.id), List.of("Status", cs.status.name()), List.of("Files", String.valueOf(cs.files.size())),
                    List.of("Branch", String.valueOf(cs.gitBranch)), List.of("Commit", String.valueOf(cs.gitCommit)),
                    List.of("Approved by", String.valueOf(cs.approvedBy)),
                    List.of("Validation", cs.validation == null ? "not run" : (cs.validation.passed() ? "PASSED" : "FAILED") + " — " + cs.validation.command()),
                    List.of("History", String.join(" | ", cs.history))));
        }
    }

    private void remediation(ReportDocument d, List<Finding> list) {
        Instant now = Instant.now();
        int overdue = 0;
        List<List<String>> rows = new ArrayList<>();
        for (Finding f : list) {
            Severity p = f.priority == null ? f.sourceSeverity : f.priority;
            Instant due = f.dueDate != null ? f.dueDate : f.firstDetected == null ? null
                    : f.firstDetected.plus(Duration.ofDays(props.getPolicy().getSlaDays().getOrDefault(p.name(), 90)));
            boolean late = f.isOpen() && due != null && now.isAfter(due);
            if (late) overdue++;
            rows.add(List.of(f.id, f.title, p.label(), f.status.name(), String.valueOf(f.owner == null ? "unassigned" : f.owner),
                    String.valueOf(due), late ? "OVERDUE" : "on track"));
        }
        d.metadata.put("SLA policy (days)", props.getPolicy().getSlaDays().toString());
        d.metadata.put("Overdue findings", String.valueOf(overdue));
        d.addTable("SLA Status", List.of("ID", "Title", "Priority", "Status", "Owner", "Due", "SLA"), rows);
        d.addTable("Change Sets", List.of("ID", "Kind", "Title", "Status", "Applied by", "Approved by", "Commit"),
                changes.list(null).stream().map(c -> List.of(c.id, c.kind, c.title, c.status.name(), String.valueOf(c.appliedBy),
                        String.valueOf(c.approvedBy), String.valueOf(c.gitCommit))).toList());
    }

    private static void remediationTable(ReportDocument d, List<Finding> list) {
        d.addTable("Remediation", List.of("ID", "Priority", "Title", "Owner", "Due", "Recommended fix"),
                list.stream().limit(1000).map(f -> List.of(f.id, (f.priority == null ? f.sourceSeverity : f.priority).label(), f.title,
                        String.valueOf(f.owner == null ? "" : f.owner), String.valueOf(f.dueDate == null ? "" : f.dueDate),
                        String.valueOf(f.remediation == null ? "" : f.remediation))).toList());
    }

    private static void recommendations(ReportDocument d, List<Finding> list) {
        long crit = list.stream().filter(f -> f.priority == Severity.CRITICAL).count();
        long deps = list.stream().filter(f -> f.dependency != null && f.dependency.fixedVersion != null).count();
        long secrets = list.stream().filter(f -> "Secrets".equals(f.category)).count();
        if (crit > 0) d.recommendations.add("Triage the " + crit + " critical finding(s) immediately and block releases until resolved or formally accepted.");
        if (deps > 0) d.recommendations.add("Upgrade " + deps + " vulnerable dependencies that already have fixed versions (often via a Spring Boot/BOM bump).");
        if (secrets > 0) d.recommendations.add("Rotate the " + secrets + " exposed secret(s) and move them to a secret manager; purge them from VCS history.");
        if (list.stream().anyMatch(f -> f.ruleId != null && f.ruleId.startsWith("HDR-"))) d.recommendations.add("Add standard security headers centrally (Spring Security headers DSL or gateway).");
        if (d.recommendations.isEmpty() && !list.isEmpty()) d.recommendations.add("Address findings in priority order and re-run scans to confirm fixes.");
    }

    // ------------------------------------------------------------------ queries

    public List<Report> list() {
        return reports.values().stream().sorted(Comparator.comparing((Report r) -> r.requestedAt).reversed()).toList();
    }

    public Report get(String id) {
        Report r = reports.get(id);
        if (r == null) throw ApiException.notFound("Report " + id);
        return r;
    }

    public Path file(String id, String format) {
        Report r = get(id);
        if (!"READY".equals(r.status)) throw ApiException.conflict("Report is " + r.status);
        if (!r.files.containsKey(format)) throw ApiException.badRequest("Format must be one of " + r.files.keySet());
        Path p = store.dir().resolve("reports").resolve(r.id + "." + format);
        if (!Files.exists(p)) throw ApiException.notFound("Report file");
        return p;
    }

    public int housekeeping(Duration retention) {
        Instant cutoff = Instant.now().minus(retention);
        List<Report> old = reports.values().stream().filter(r -> r.requestedAt.isBefore(cutoff)).toList();
        for (Report r : old) {
            reports.remove(r.id);
            for (String ext : r.files.keySet()) {
                try { Files.deleteIfExists(store.dir().resolve("reports").resolve(r.id + "." + ext)); } catch (IOException ignored) { /* best effort */ }
            }
        }
        if (!old.isEmpty()) store.markDirty("reports");
        return old.size();
    }

    public void shutdown() { executor.shutdownNow(); }
}
