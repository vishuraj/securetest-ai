package com.securetest.controlplane.web;

import com.securetest.controlplane.security.ApiException;
import com.securetest.controlplane.security.Caller;
import com.securetest.controlplane.security.Role.Permission;
import com.securetest.controlplane.service.JobService;
import com.securetest.controlplane.service.JobService.CreateJob;
import com.securetest.controlplane.service.ReportService;
import com.securetest.controlplane.service.TenantAccess;
import com.securetest.controlplane.service.TenantAccess.Scope;
import com.securetest.controlplane.store.AuditStore;
import com.securetest.controlplane.store.FindingStore;
import com.securetest.controlplane.store.InventoryStore;
import com.securetest.controlplane.store.ReportStore;
import com.securetest.controlplane.store.TenantStore;
import com.securetest.controlplane.store.WorkerStore;
import com.securetest.core.util.Hashing;
import org.springframework.http.ContentDisposition;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Tenant-scoped API for users (OIDC JWT). Every handler resolves the caller's tenant through
 * {@link TenantAccess} and passes only that tenant id to the stores.
 */
@RestController
@RequestMapping("/api/v1")
public class TenantApiController {

    private final TenantAccess access;
    private final InventoryStore inventory;
    private final FindingStore findings;
    private final JobService jobs;
    private final ReportService reportService;
    private final ReportStore reports;
    private final AuditStore audit;
    private final TenantStore tenants;
    private final WorkerStore workers;
    private final SecureRandom random = new SecureRandom();

    public TenantApiController(TenantAccess access, InventoryStore inventory, FindingStore findings, JobService jobs,
                               ReportService reportService, ReportStore reports, AuditStore audit, TenantStore tenants,
                               WorkerStore workers) {
        this.access = access;
        this.inventory = inventory;
        this.findings = findings;
        this.jobs = jobs;
        this.reportService = reportService;
        this.reports = reports;
        this.audit = audit;
        this.tenants = tenants;
        this.workers = workers;
    }

    @GetMapping("/me")
    public Map<String, Object> me(@AuthenticationPrincipal Caller caller) {
        Scope scope = access.require(caller, Permission.VIEW);
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("subject", caller.subject());
        m.put("tenant", scope.tenantSlug());
        m.put("roles", caller.roles());
        m.put("platformAdmin", caller.platformAdmin());
        return m;
    }

    // ------------------------------------------------------------------ inventory

    @GetMapping("/inventory")
    public Map<String, Object> inventory(@AuthenticationPrincipal Caller caller) {
        Scope scope = access.require(caller, Permission.VIEW);
        List<Map<String, Object>> agents = inventory.agents(scope.tenantId());
        List<Map<String, Object>> apps = new ArrayList<>();
        for (InventoryStore.Application a : inventory.applications(scope.tenantId())) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("id", a.id());
            m.put("serviceId", a.serviceId());
            m.put("name", a.name());
            m.put("environments", inventory.environments(scope.tenantId()).stream()
                    .filter(e -> e.applicationId().equals(a.id()))
                    .map(e -> Map.of("id", e.id(), "name", e.name(), "production", e.production())).toList());
            m.put("agents", agents.stream().filter(g -> a.id().equals(g.get("applicationId"))).toList());
            apps.add(m);
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("tenant", scope.tenantSlug());
        out.put("applications", apps);
        out.put("findings", findings.summary(scope.tenantId()));
        return out;
    }

    @GetMapping("/agents")
    public List<Map<String, Object>> agents(@AuthenticationPrincipal Caller caller) {
        return inventory.agents(access.require(caller, Permission.VIEW).tenantId());
    }

    @GetMapping("/workers")
    public List<Map<String, Object>> workers(@AuthenticationPrincipal Caller caller) {
        access.require(caller, Permission.VIEW);
        return workers.list(Instant.now().minus(Duration.ofHours(1)));
    }

    // ------------------------------------------------------------------ findings

    @GetMapping("/findings")
    public List<Map<String, Object>> findings(@AuthenticationPrincipal Caller caller,
                                              @RequestParam(required = false) String applicationId,
                                              @RequestParam(required = false) String priority,
                                              @RequestParam(required = false) String status,
                                              @RequestParam(required = false) String source,
                                              @RequestParam(defaultValue = "200") int limit) {
        Scope scope = access.require(caller, Permission.VIEW);
        return findings.list(scope.tenantId(), new FindingStore.Filter(applicationId,
                priority == null ? null : priority.toUpperCase(Locale.ROOT),
                status == null ? null : status.toUpperCase(Locale.ROOT), source, Math.max(1, Math.min(1000, limit))));
    }

    @GetMapping("/findings/summary")
    public Map<String, Object> findingSummary(@AuthenticationPrincipal Caller caller) {
        return findings.summary(access.require(caller, Permission.VIEW).tenantId());
    }

    @GetMapping("/findings/{id}")
    public Map<String, Object> finding(@AuthenticationPrincipal Caller caller, @PathVariable String id) {
        Scope scope = access.require(caller, Permission.VIEW);
        return findings.get(scope.tenantId(), id).orElseThrow(() -> ApiException.notFound("Finding"));
    }

    // ------------------------------------------------------------------ remote scans

    @PostMapping("/scans")
    @ResponseStatus(HttpStatus.CREATED)
    public Map<String, Object> createScan(@AuthenticationPrincipal Caller caller, @RequestBody CreateJob body) {
        Scope scope = access.require(caller, Permission.EXECUTE);
        return jobs.create(scope, caller, body);
    }

    @GetMapping("/scans")
    public List<Map<String, Object>> scans(@AuthenticationPrincipal Caller caller,
                                           @RequestParam(required = false) String applicationId,
                                           @RequestParam(defaultValue = "100") int limit) {
        return jobs.list(access.require(caller, Permission.VIEW), applicationId, limit);
    }

    @GetMapping("/scans/{id}")
    public Map<String, Object> scan(@AuthenticationPrincipal Caller caller, @PathVariable String id) {
        return jobs.get(access.require(caller, Permission.VIEW), id);
    }

    @PostMapping("/scans/{id}/cancel")
    public Map<String, Object> cancel(@AuthenticationPrincipal Caller caller, @PathVariable String id) {
        return jobs.cancel(access.require(caller, Permission.EXECUTE), id);
    }

    @GetMapping("/scanners")
    public List<JobService.ScannerInfo> scanners(@AuthenticationPrincipal Caller caller) {
        access.require(caller, Permission.VIEW);
        return new ArrayList<>(jobs.scannerCatalog().values());
    }

    // ------------------------------------------------------------------ reports

    public record ReportRequest(String format, String applicationId) { }

    @PostMapping("/reports")
    @ResponseStatus(HttpStatus.CREATED)
    public Map<String, Object> createReport(@AuthenticationPrincipal Caller caller, @RequestBody ReportRequest body) {
        return reportService.generate(access.require(caller, Permission.REPORT), body.format(), body.applicationId());
    }

    @GetMapping("/reports")
    public List<Map<String, Object>> reports(@AuthenticationPrincipal Caller caller) {
        return reports.list(access.require(caller, Permission.VIEW).tenantId());
    }

    @GetMapping("/reports/{id}/content")
    public ResponseEntity<byte[]> reportContent(@AuthenticationPrincipal Caller caller, @PathVariable String id) {
        Scope scope = access.require(caller, Permission.VIEW);
        ReportStore.Content c = reports.content(scope.tenantId(), id).orElseThrow(() -> ApiException.notFound("Report"));
        MediaType type = switch (c.format()) {
            case "CSV" -> MediaType.parseMediaType("text/csv");
            case "XLSX" -> MediaType.parseMediaType("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet");
            default -> MediaType.APPLICATION_PDF;
        };
        return ResponseEntity.ok().contentType(type)
                .header(HttpHeaders.CONTENT_DISPOSITION, ContentDisposition.attachment()
                        .filename("securetest-report-" + id + "." + c.format().toLowerCase(Locale.ROOT)).build().toString())
                .body(c.data());
    }

    // ------------------------------------------------------------------ audit & administration

    @GetMapping("/audit")
    public List<Map<String, Object>> audit(@AuthenticationPrincipal Caller caller, @RequestParam(defaultValue = "200") int limit) {
        return audit.list(access.require(caller, Permission.AUDIT).tenantId(), Math.max(1, Math.min(1000, limit)));
    }

    @GetMapping("/audit/verify")
    public Map<String, Object> verifyAudit(@AuthenticationPrincipal Caller caller) {
        return audit.verify(access.require(caller, Permission.AUDIT).tenantId());
    }

    public record TokenRequest(String description) { }

    /** Creates an agent enrollment token for the caller's tenant. The raw token is returned once and never stored. */
    @PostMapping("/enrollment-tokens")
    @ResponseStatus(HttpStatus.CREATED)
    public Map<String, Object> createEnrollmentToken(@AuthenticationPrincipal Caller caller, @RequestBody(required = false) TokenRequest body) {
        Scope scope = access.require(caller, Permission.ADMIN);
        byte[] raw = new byte[32];
        random.nextBytes(raw);
        String token = "stk_" + Base64.getUrlEncoder().withoutPadding().encodeToString(raw);
        String desc = body == null ? null : body.description();
        String id = tenants.addEnrollmentToken(scope.tenantId(), Hashing.sha256(token), desc, scope.actor());
        audit.append(scope.tenantId(), scope.actor(), "ENROLLMENT_TOKEN_CREATED", "token:" + id, desc);
        return Map.of("id", id, "token", token);
    }

    @PostMapping("/enrollment-tokens/{id}/revoke")
    public Map<String, Object> revokeEnrollmentToken(@AuthenticationPrincipal Caller caller, @PathVariable String id) {
        Scope scope = access.require(caller, Permission.ADMIN);
        if (!tenants.revokeEnrollmentToken(scope.tenantId(), id)) throw ApiException.notFound("Enrollment token");
        audit.append(scope.tenantId(), scope.actor(), "ENROLLMENT_TOKEN_REVOKED", "token:" + id, null);
        return Map.of("id", id, "revoked", true);
    }

    // ------------------------------------------------------------------ platform administration

    public record TenantRequest(String slug, String name) { }

    @PostMapping("/admin/tenants")
    @ResponseStatus(HttpStatus.CREATED)
    public TenantStore.Tenant createTenant(@AuthenticationPrincipal Caller caller, @RequestBody TenantRequest body) {
        access.requirePlatformAdmin(caller);
        if (body == null || body.slug() == null || !body.slug().matches("[a-z0-9][a-z0-9-]{1,62}")) {
            throw ApiException.badRequest("slug must be 2-63 lower-case letters, digits or '-'");
        }
        if (tenants.findBySlug(body.slug()).isPresent()) throw new ApiException(HttpStatus.CONFLICT, "Tenant exists");
        TenantStore.Tenant t = tenants.create(body.slug(), body.name() == null ? body.slug() : body.name());
        inventory.defaultProject(t.id());
        audit.append(null, caller.subject(), "TENANT_CREATED", "tenant:" + t.slug(), null);
        return t;
    }

    @GetMapping("/admin/tenants")
    public List<TenantStore.Tenant> listTenants(@AuthenticationPrincipal Caller caller) {
        access.requirePlatformAdmin(caller);
        return tenants.list();
    }
}
