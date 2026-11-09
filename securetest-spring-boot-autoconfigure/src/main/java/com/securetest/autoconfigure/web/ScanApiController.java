package com.securetest.autoconfigure.web;

import com.securetest.autoconfigure.security.ApiException;
import com.securetest.autoconfigure.security.Authz;
import com.securetest.autoconfigure.security.Rbac.Permission;
import com.securetest.autoconfigure.security.SecureTestPrincipal;
import com.securetest.autoconfigure.service.AuditService;
import com.securetest.autoconfigure.service.FindingService;
import com.securetest.autoconfigure.service.JobService;
import com.securetest.autoconfigure.service.WorkspaceServices.ProfileService;
import com.securetest.autoconfigure.service.WorkspaceServices.ScheduleService;
import com.securetest.adapters.builtin.DependencyScanner;
import com.securetest.core.model.Enums.JobStatus;
import com.securetest.core.model.ScanJob;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.springframework.http.ContentDisposition;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Scan jobs, approvals, artifacts, SBOM, saved profiles and schedules. */
@RestController
@RequestMapping("${securetest.dashboard.path:/securetest}/api/v1")
public class ScanApiController {

    private final JobService jobs;
    private final ProfileService profiles;
    private final ScheduleService schedules;
    private final AuditService audit;

    public ScanApiController(JobService jobs, ProfileService profiles, ScheduleService schedules, AuditService audit) {
        this.jobs = jobs;
        this.profiles = profiles;
        this.schedules = schedules;
        this.audit = audit;
    }

    public record ScanRequest(String scannerId, Map<String, String> options, boolean confirmed, String profileName, boolean saveProfile) { }

    @PostMapping("/scans")
    public ResponseEntity<Map<String, Object>> create(@RequestBody ScanRequest req,
                                                      @RequestHeader(value = "Idempotency-Key", required = false) String idempotencyKey, SecureTestPrincipal principal) {
        SecureTestPrincipal p = Authz.require(principal, Permission.EXECUTE);
        if (req.scannerId() == null) throw ApiException.badRequest("scannerId is required");
        Map<String, String> options = new LinkedHashMap<>();
        if (req.profileName() != null && !req.profileName().isBlank() && !req.saveProfile()) {
            options.putAll(profiles.get(req.scannerId(), req.profileName()).options);
        }
        if (req.options() != null) req.options().forEach((k, v) -> { if (!k.startsWith("_")) options.put(k, v); });
        if (req.saveProfile() && req.profileName() != null && !req.profileName().isBlank()) {
            Authz.require(principal, Permission.CONFIGURE);
            profiles.save(req.profileName(), req.scannerId(), options, p.name());
        }
        ScanJob job = jobs.submit(new JobService.SubmitRequest(req.scannerId(), options, req.confirmed(), req.profileName(), idempotencyKey), p);
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("job", job);
        body.put("statusUrl", "scans/" + job.id);
        return ResponseEntity.status(job.status == JobStatus.AWAITING_APPROVAL ? 202 : 201).body(body);
    }

    @GetMapping("/scans")
    public FindingService.Page<ScanJob> list(@RequestParam(required = false) String module, @RequestParam(required = false) String scanner,
                                             @RequestParam(defaultValue = "0") int page, @RequestParam(defaultValue = "25") int size, SecureTestPrincipal principal) {
        Authz.require(principal, Permission.VIEW);
        return jobs.list(module, scanner, Math.max(0, page), Math.min(200, Math.max(1, size)));
    }

    @GetMapping("/scans/{scanId}")
    public ScanJob get(@PathVariable String scanId, SecureTestPrincipal principal) {
        Authz.require(principal, Permission.VIEW);
        return jobs.get(scanId);
    }

    @PostMapping("/scans/{scanId}/cancel")
    public ScanJob cancel(@PathVariable String scanId, SecureTestPrincipal principal) {
        return jobs.cancel(scanId, Authz.require(principal, Permission.EXECUTE));
    }

    @PostMapping("/scans/{scanId}/approve")
    public ScanJob approve(@PathVariable String scanId, SecureTestPrincipal principal) {
        return jobs.approve(scanId, Authz.require(principal, Permission.APPROVE));
    }

    @PostMapping("/scans/{scanId}/reject")
    public ScanJob reject(@PathVariable String scanId, @RequestBody(required = false) Map<String, String> body, SecureTestPrincipal principal) {
        return jobs.reject(scanId, Authz.require(principal, Permission.APPROVE), body == null ? null : body.get("reason"));
    }

    @GetMapping("/scans/{scanId}/artifacts/{name}")
    public ResponseEntity<Resource> artifact(@PathVariable String scanId, @PathVariable String name, SecureTestPrincipal principal) {
        SecureTestPrincipal p = Authz.require(principal, Permission.VIEW);
        Path file = jobs.artifact(scanId, name);
        audit.record(p, "artifact.downloaded", scanId + "/" + name, "OK", Map.of());
        MediaType type = name.endsWith(".json") ? MediaType.APPLICATION_JSON : name.endsWith(".png") ? MediaType.IMAGE_PNG
                : name.endsWith(".jpg") || name.endsWith(".jpeg") ? MediaType.IMAGE_JPEG : MediaType.APPLICATION_OCTET_STREAM;
        if (type.getType().equals("image")) {
            return ResponseEntity.ok().contentType(type).body(new org.springframework.core.io.FileSystemResource(file));
        }
        return download(file, name, type);
    }

    /** Latest CycloneDX SBOM produced by the dependency scanner. */
    @GetMapping("/sbom")
    public ResponseEntity<Resource> sbom(SecureTestPrincipal principal) {
        SecureTestPrincipal p = Authz.require(principal, Permission.VIEW);
        ScanJob job = jobs.latest(DependencyScanner.ID, JobStatus.COMPLETED)
                .orElseThrow(() -> ApiException.notFound("SBOM (run the dependency scan first)"));
        audit.record(p, "sbom.exported", job.id, "OK", Map.of());
        return download(jobs.artifact(job.id, "sbom.cdx.json"), "sbom.cdx.json", MediaType.APPLICATION_JSON);
    }

    static ResponseEntity<Resource> download(Path file, String name, MediaType type) {
        return ResponseEntity.ok().contentType(type)
                .header(HttpHeaders.CONTENT_DISPOSITION, ContentDisposition.attachment().filename(name).build().toString())
                .body(new FileSystemResource(file));
    }

    // ------------------------------------------------------------------ profiles

    @GetMapping("/profiles")
    public List<ProfileService.Profile> profiles(@RequestParam(required = false) String scanner, SecureTestPrincipal principal) {
        Authz.require(principal, Permission.VIEW);
        return profiles.list(scanner);
    }

    public record ProfileRequest(String name, String scannerId, Map<String, String> options) { }

    @PostMapping("/profiles")
    public ProfileService.Profile saveProfile(@RequestBody ProfileRequest req, SecureTestPrincipal principal) {
        SecureTestPrincipal p = Authz.require(principal, Permission.CONFIGURE);
        ProfileService.Profile saved = profiles.save(req.name(), req.scannerId(), req.options(), p.name());
        audit.record(p, "profile.saved", req.scannerId() + "/" + req.name(), "OK", Map.of());
        return saved;
    }

    @DeleteMapping("/profiles/{scannerId}/{name}")
    public void deleteProfile(@PathVariable String scannerId, @PathVariable String name, SecureTestPrincipal principal) {
        SecureTestPrincipal p = Authz.require(principal, Permission.CONFIGURE);
        profiles.delete(scannerId, name);
        audit.record(p, "profile.deleted", scannerId + "/" + name, "OK", Map.of());
    }

    // ------------------------------------------------------------------ schedules

    @GetMapping("/schedules")
    public List<ScheduleService.Schedule> schedules(SecureTestPrincipal principal) {
        Authz.require(principal, Permission.VIEW);
        return schedules.list();
    }

    public record ScheduleRequest(String scannerId, String profileName, String cron) { }

    @PostMapping("/schedules")
    public ScheduleService.Schedule createSchedule(@RequestBody ScheduleRequest req, SecureTestPrincipal principal) {
        SecureTestPrincipal p = Authz.require(principal, Permission.CONFIGURE);
        ScheduleService.Schedule s = schedules.create(req.scannerId(), req.profileName(), req.cron(), p);
        audit.record(p, "schedule.created", s.id, "OK", Map.of("scanner", req.scannerId(), "cron", req.cron()));
        return s;
    }

    @PostMapping("/schedules/{id}/enabled")
    public ScheduleService.Schedule toggleSchedule(@PathVariable String id, @RequestParam boolean value, SecureTestPrincipal principal) {
        SecureTestPrincipal p = Authz.require(principal, Permission.CONFIGURE);
        audit.record(p, "schedule.toggled", id, "OK", Map.of("enabled", String.valueOf(value)));
        return schedules.setEnabled(id, value);
    }

    @DeleteMapping("/schedules/{id}")
    public void deleteSchedule(@PathVariable String id, SecureTestPrincipal principal) {
        SecureTestPrincipal p = Authz.require(principal, Permission.CONFIGURE);
        schedules.delete(id);
        audit.record(p, "schedule.deleted", id, "OK", Map.of());
    }
}
