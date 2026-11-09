package com.securetest.autoconfigure.web;

import com.securetest.autoconfigure.security.ApiException;
import com.securetest.autoconfigure.security.Authz;
import com.securetest.autoconfigure.security.Rbac.Permission;
import com.securetest.autoconfigure.security.SecureTestPrincipal;
import com.securetest.autoconfigure.service.AuditService;
import com.securetest.autoconfigure.service.ComplianceService;
import com.securetest.autoconfigure.service.FindingService;
import com.securetest.autoconfigure.service.JobService;
import com.securetest.autoconfigure.service.MigrationService;
import com.securetest.autoconfigure.service.ReportService;
import com.securetest.core.model.AuditEvent;
import com.securetest.core.model.Finding;
import com.securetest.core.model.ModuleCatalog;
import com.securetest.core.util.Hashing;
import com.securetest.migration.ChangeSet;
import com.securetest.migration.MigrationModels.Inventory;
import com.securetest.migration.MigrationModels.MigrationRun;
import org.springframework.context.ApplicationContext;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.core.io.Resource;
import org.springframework.http.ContentDisposition;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.file.Path;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Predicate;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/** Migration workflow, compliance, reports and audit. */
@RestController
@RequestMapping("${securetest.dashboard.path:/securetest}/api/v1")
public class GovernanceApiController {

    private final MigrationService migrations;
    private final ComplianceService compliance;
    private final ReportService reports;
    private final AuditService audit;
    private final FindingService findings;
    private final JobService jobs;
    private final ApplicationContext context;
    private final Map<String, String> reportIdempotency = new ConcurrentHashMap<>();

    public GovernanceApiController(MigrationService migrations, ComplianceService compliance, ReportService reports, AuditService audit,
                                   FindingService findings, JobService jobs, ApplicationContext context) {
        this.migrations = migrations;
        this.compliance = compliance;
        this.reports = reports;
        this.audit = audit;
        this.findings = findings;
        this.jobs = jobs;
        this.context = context;
    }

    private void requireMigrationModule() {
        if (!context.getBean(com.securetest.autoconfigure.service.ModuleService.class).isEnabled(ModuleCatalog.MIGRATION)) {
            throw ApiException.conflict("The Migration module is disabled.");
        }
    }

    // ------------------------------------------------------------------ migration

    @GetMapping("/migrations/discover")
    public Inventory discover() {
        Authz.require(Permission.VIEW);
        requireMigrationModule();
        return migrations.discover();
    }

    @GetMapping("/migrations/matrix")
    public Map<String, Object> matrix() {
        Authz.require(Permission.VIEW);
        return migrations.matrix();
    }

    public record AssessRequest(int javaVersion, String springBootVersion) { }

    @PostMapping("/migrations/assess")
    public MigrationRun assess(@RequestBody AssessRequest req) {
        SecureTestPrincipal p = Authz.require(Permission.EXECUTE);
        requireMigrationModule();
        if (req.springBootVersion() == null) throw ApiException.badRequest("springBootVersion is required");
        return migrations.assess(req.javaVersion(), req.springBootVersion(), p);
    }

    @GetMapping("/migrations")
    public List<MigrationRun> listMigrations() {
        Authz.require(Permission.VIEW);
        return migrations.list();
    }

    @GetMapping("/migrations/{id}")
    public MigrationRun migration(@PathVariable String id) {
        Authz.require(Permission.VIEW);
        return migrations.get(id);
    }

    @PostMapping("/migrations/{id}/plan")
    public MigrationRun plan(@PathVariable String id) {
        SecureTestPrincipal p = Authz.require(Permission.EXECUTE);
        requireMigrationModule();
        return migrations.plan(id, p);
    }

    @PostMapping("/migrations/{id}/preview")
    public ChangeSet preview(@PathVariable String id, @RequestBody(required = false) Map<String, List<String>> body) {
        SecureTestPrincipal p = Authz.require(Permission.REMEDIATE);
        requireMigrationModule();
        return migrations.preview(id, body == null ? null : body.get("categories"), p);
    }

    @PostMapping("/migrations/{id}/apply")
    public ChangeSet applyMigration(@PathVariable String id, @RequestBody(required = false) FindingApiController.ApplyRequest body) {
        SecureTestPrincipal p = Authz.require(Permission.APPROVE);
        requireMigrationModule();
        FindingApiController.ApplyRequest r = body == null ? new FindingApiController.ApplyRequest(true, false) : body;
        return migrations.apply(id, r.createBranch(), r.allowDirtyWithSnapshot(), p);
    }

    // ------------------------------------------------------------------ compliance

    @GetMapping("/compliance")
    public Map<String, Object> compliance() {
        Authz.require(Permission.VIEW);
        Map<String, Object> m = new LinkedHashMap<>(compliance.summary());
        m.put("controls", compliance.evaluate());
        return m;
    }

    public record Applicability(String framework, String controlId, boolean notApplicable, String reason) { }

    @PutMapping("/compliance/applicability")
    public Map<String, Object> applicability(@RequestBody Applicability req) {
        SecureTestPrincipal p = Authz.require(Permission.APPROVE);
        compliance.setNotApplicable(req.framework(), req.controlId(), req.notApplicable(), req.reason(), p.name());
        audit.record(p.name(), p.remoteAddress(), "compliance.applicability", req.framework() + "/" + req.controlId(), "OK",
                Map.of("notApplicable", String.valueOf(req.notApplicable()), "reason", String.valueOf(req.reason())));
        return compliance();
    }

    /** Evidence pack: compliance status, open findings, scan metadata, audit trail and a manifest of SHA-256 checksums. */
    @GetMapping("/compliance/evidence-pack")
    public ResponseEntity<Resource> evidencePack() throws IOException {
        SecureTestPrincipal p = Authz.require(Permission.AUDIT);
        var mapper = new com.fasterxml.jackson.databind.ObjectMapper().findAndRegisterModules()
                .disable(com.fasterxml.jackson.databind.SerializationFeature.WRITE_DATES_AS_TIMESTAMPS)
                .writerWithDefaultPrettyPrinter();
        Map<String, byte[]> entries = new LinkedHashMap<>();
        entries.put("compliance.json", mapper.writeValueAsBytes(compliance()));
        entries.put("findings.json", mapper.writeValueAsBytes(findings.all().stream().filter(Finding::isOpen).toList()));
        entries.put("scans.json", mapper.writeValueAsBytes(jobs.all()));
        entries.put("audit-events.json", mapper.writeValueAsBytes(audit.query(e -> true, 0, 5000)));
        entries.put("audit-verification.json", mapper.writeValueAsBytes(audit.verify()));
        Map<String, Object> manifest = new LinkedHashMap<>();
        manifest.put("generatedAt", Instant.now().toString());
        manifest.put("generatedBy", p.name());
        manifest.put("disclaimer", ComplianceService.DISCLAIMER);
        Map<String, String> sums = new LinkedHashMap<>();
        entries.forEach((k, v) -> sums.put(k, Hashing.sha256(v)));
        manifest.put("sha256", sums);
        entries.put("manifest.json", mapper.writeValueAsBytes(manifest));
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try (ZipOutputStream z = new ZipOutputStream(bos)) {
            for (var e : entries.entrySet()) {
                z.putNextEntry(new ZipEntry(e.getKey()));
                z.write(e.getValue());
                z.closeEntry();
            }
        }
        audit.record(p.name(), p.remoteAddress(), "compliance.evidence.exported", "evidence-pack", "OK", Map.of("sha256", Hashing.sha256(bos.toByteArray())));
        return ResponseEntity.ok().contentType(MediaType.parseMediaType("application/zip"))
                .header(HttpHeaders.CONTENT_DISPOSITION, ContentDisposition.attachment().filename("securetest-evidence-" + Instant.now().toEpochMilli() + ".zip").build().toString())
                .body(new ByteArrayResource(bos.toByteArray()));
    }

    // ------------------------------------------------------------------ reports

    @GetMapping("/reports")
    public Map<String, Object> reports() {
        Authz.require(Permission.VIEW);
        return Map.of("types", ReportService.TYPES, "reports", reports.list());
    }

    @PostMapping("/reports")
    public ResponseEntity<ReportService.Report> generate(@RequestBody ReportService.Request req,
                                                         @RequestHeader(value = "Idempotency-Key", required = false) String key) {
        SecureTestPrincipal p = Authz.require(Permission.VIEW);
        if (key != null && reportIdempotency.containsKey(p.name() + "|" + key)) {
            return ResponseEntity.ok(reports.get(reportIdempotency.get(p.name() + "|" + key)));
        }
        ReportService.Report r = reports.request(req, p);
        if (key != null) reportIdempotency.put(p.name() + "|" + key, r.id);
        return ResponseEntity.status(202).body(r);
    }

    @GetMapping("/reports/{id}")
    public ReportService.Report report(@PathVariable String id) {
        Authz.require(Permission.VIEW);
        return reports.get(id);
    }

    @GetMapping("/reports/{id}/data")
    public ResponseEntity<Resource> reportData(@PathVariable String id) {
        Authz.require(Permission.VIEW);
        return ScanApiController.download(reports.file(id, "json"), id + ".json", MediaType.APPLICATION_JSON);
    }

    @GetMapping("/reports/{id}/download")
    public ResponseEntity<Resource> download(@PathVariable String id, @RequestParam(defaultValue = "pdf") String format) {
        SecureTestPrincipal p = Authz.require(Permission.VIEW);
        Path file = reports.file(id, format);
        MediaType type = switch (format) {
            case "pdf" -> MediaType.APPLICATION_PDF;
            case "xlsx" -> MediaType.parseMediaType("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet");
            case "csv" -> MediaType.parseMediaType("text/csv");
            default -> MediaType.APPLICATION_JSON;
        };
        audit.record(p.name(), p.remoteAddress(), "report.exported", id, "OK", Map.of("format", format));
        return ScanApiController.download(file, "securetest-" + id + "." + format, type);
    }

    // ------------------------------------------------------------------ audit

    @GetMapping("/audit-events")
    public Map<String, Object> auditEvents(@RequestParam(required = false) String actor, @RequestParam(required = false) String action,
                                           @RequestParam(required = false) String target,
                                           @RequestParam(defaultValue = "0") int page, @RequestParam(defaultValue = "50") int size) {
        Authz.require(Permission.AUDIT);
        Predicate<AuditEvent> f = e -> (actor == null || actor.isBlank() || e.actor().contains(actor))
                && (action == null || action.isBlank() || e.action().startsWith(action))
                && (target == null || target.isBlank() || String.valueOf(e.target()).contains(target));
        int s = Math.min(500, Math.max(1, size));
        return Map.of("items", audit.query(f, Math.max(0, page) * s, s), "total", audit.count(f), "page", page, "size", s);
    }

    @GetMapping("/audit-events/verify")
    public Map<String, Object> verifyAudit() {
        Authz.require(Permission.AUDIT);
        return audit.verify();
    }
}
