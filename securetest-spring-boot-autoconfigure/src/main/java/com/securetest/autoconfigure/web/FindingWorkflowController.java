package com.securetest.autoconfigure.web;

import com.securetest.autoconfigure.security.ApiException;
import com.securetest.autoconfigure.security.Authz;
import com.securetest.autoconfigure.security.Rbac.Permission;
import com.securetest.autoconfigure.security.SecureTestPrincipal;
import com.securetest.autoconfigure.service.AuditService;
import com.securetest.autoconfigure.service.FindingService;
import com.securetest.autoconfigure.service.IssueTrackerService;
import com.securetest.autoconfigure.service.JobService;
import com.securetest.autoconfigure.service.ScannerRegistry;
import com.securetest.autoconfigure.support.LocalStore;
import com.securetest.core.model.Finding;
import com.securetest.core.model.ScanJob;
import com.securetest.core.util.Hashing;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/**
 * Collaboration on findings: findings reported by testers, retest (proving a fix), comments, evidence attachments and
 * Jira / GitHub issues. Everything here runs only when a user asks for it.
 */
@RestController
@RequestMapping("${securetest.dashboard.path:/securetest}/api/v1")
public class FindingWorkflowController {

    private static final long MAX_ATTACHMENT = 5L * 1024 * 1024;
    private static final Set<String> ATTACHMENT_TYPES = Set.of("image/png", "image/jpeg", "image/gif", "image/webp", "application/pdf",
            "text/plain", "application/json");
    private static final Set<String> INLINE_TYPES = Set.of("image/png", "image/jpeg", "image/gif", "image/webp");

    private final FindingService findings;
    private final JobService jobs;
    private final ScannerRegistry registry;
    private final IssueTrackerService trackers;
    private final AuditService audit;
    private final LocalStore store;

    public FindingWorkflowController(FindingService findings, JobService jobs, ScannerRegistry registry, IssueTrackerService trackers,
                                     AuditService audit, LocalStore store) {
        this.findings = findings;
        this.jobs = jobs;
        this.registry = registry;
        this.trackers = trackers;
        this.audit = audit;
        this.store = store;
    }

    /** Testers, developers and security staff can report and discuss; viewers only read. */
    private static SecureTestPrincipal contributor(SecureTestPrincipal principal) {
        SecureTestPrincipal p = Authz.require(principal, Permission.VIEW);
        if (!p.has(Permission.EXECUTE) && !p.has(Permission.REMEDIATE)) {
            throw ApiException.forbidden("Reporting and commenting need the EXECUTE or REMEDIATE permission.");
        }
        return p;
    }

    // ------------------------------------------------------------------ manual findings

    @PostMapping("/findings")
    public ResponseEntity<Finding> report(@RequestBody FindingService.ManualFinding body, SecureTestPrincipal principal) {
        SecureTestPrincipal p = contributor(principal);
        Finding f = findings.createManual(body, p.name());
        audit.record(p, "finding.reported", f.id, "OK", Map.of("title", f.title, "severity", f.sourceSeverity.name()));
        return ResponseEntity.status(201).body(f);
    }

    // ------------------------------------------------------------------ retest

    public record RetestRequest(Boolean confirmed) { }

    public record Verdict(Boolean fixed, String note) { }

    /**
     * Retest: scanner findings re-run their scanner and are marked verified-fixed when no longer detected; manual
     * findings wait for a tester's verdict.
     */
    @PostMapping("/findings/{findingId}/retest")
    public Map<String, Object> retest(@PathVariable String findingId, @RequestBody(required = false) RetestRequest body, SecureTestPrincipal principal) {
        SecureTestPrincipal p = Authz.require(principal, Permission.EXECUTE);
        Finding f = findings.get(findingId);
        Map<String, Object> out = new LinkedHashMap<>();
        boolean automated = !"manual".equals(f.source) && scannerExists(f.source);
        if (automated) {
            Map<String, String> options = new LinkedHashMap<>();
            if (f.lastScanId != null) {
                try {
                    ScanJob last = jobs.get(f.lastScanId);
                    options.putAll(last.options);
                } catch (ApiException ignored) {
                    // the original scan was purged by retention: retest with default options
                }
            }
            options.put("_retestOf", f.id);
            boolean confirmed = body != null && Boolean.TRUE.equals(body.confirmed());
            ScanJob job = jobs.submit(new JobService.SubmitRequest(f.source, options, confirmed, null, null), p);
            out.put("job", job);
            f = findings.requestRetest(f.id, job.id, p.name());
        } else {
            f = findings.requestRetest(f.id, null, p.name());
        }
        audit.record(p, "finding.retest", findingId, "OK", Map.of("mode", automated ? "scan" : "manual"));
        out.put("finding", f);
        out.put("mode", automated ? "scan" : "manual");
        return out;
    }

    @PostMapping("/findings/{findingId}/verification")
    public Finding verify(@PathVariable String findingId, @RequestBody Verdict body, SecureTestPrincipal principal) {
        SecureTestPrincipal p = Authz.require(principal, Permission.EXECUTE);
        if (body == null || body.fixed() == null) throw ApiException.badRequest("fixed (true/false) is required");
        Finding f = findings.recordVerification(findingId, body.fixed(), body.note(), p.name());
        audit.record(p, "finding.verified", findingId, "OK", Map.of("fixed", String.valueOf(body.fixed())));
        return f;
    }

    private boolean scannerExists(String id) {
        try {
            registry.get(id);
            return true;
        } catch (ApiException e) {
            return false;
        }
    }

    // ------------------------------------------------------------------ comments

    public record CommentRequest(String text) { }

    @PostMapping("/findings/{findingId}/comments")
    public Finding comment(@PathVariable String findingId, @RequestBody CommentRequest body, SecureTestPrincipal principal) {
        SecureTestPrincipal p = contributor(principal);
        return findings.addComment(findingId, body == null ? null : body.text(), p.name());
    }

    // ------------------------------------------------------------------ attachments

    public record AttachmentUpload(String name, String contentType, String dataBase64) { }

    @PostMapping("/findings/{findingId}/attachments")
    public Finding attach(@PathVariable String findingId, @RequestBody AttachmentUpload body, SecureTestPrincipal principal) {
        SecureTestPrincipal p = contributor(principal);
        findings.get(findingId);
        if (body == null || body.dataBase64() == null) throw ApiException.badRequest("dataBase64 is required");
        String type = body.contentType() == null ? "application/octet-stream" : body.contentType().toLowerCase(java.util.Locale.ROOT).trim();
        if (!ATTACHMENT_TYPES.contains(type)) throw ApiException.badRequest("Allowed types: " + String.join(", ", ATTACHMENT_TYPES));
        byte[] data;
        try {
            data = Base64.getDecoder().decode(body.dataBase64().replaceAll("\\s", ""));
        } catch (IllegalArgumentException e) {
            throw ApiException.badRequest("dataBase64 is not valid base64");
        }
        if (data.length == 0) throw ApiException.badRequest("The attachment is empty");
        if (data.length > MAX_ATTACHMENT) throw ApiException.badRequest("Attachments are limited to 5 MB");
        Finding.Attachment a = new Finding.Attachment();
        a.id = "A-" + UUID.randomUUID().toString().substring(0, 12);
        String name = body.name() == null || body.name().isBlank() ? a.id : body.name().replaceAll("[^A-Za-z0-9._ -]", "_");
        a.name = name.length() > 120 ? name.substring(0, 120) : name;
        a.contentType = type;
        a.size = data.length;
        a.sha256 = Hashing.sha256(data);
        a.uploadedBy = p.name();
        a.uploadedAt = Instant.now();
        try {
            Path dir = store.subdir("attachments").resolve(findingId.replaceAll("[^A-Za-z0-9-]", "_"));
            Files.createDirectories(dir);
            Files.write(dir.resolve(a.id), data);
        } catch (IOException e) {
            throw new ApiException(500, "storage_error", "Cannot store the attachment: " + e.getMessage());
        }
        audit.record(p, "finding.attachment", findingId, "OK", Map.of("name", a.name, "size", String.valueOf(a.size)));
        return findings.addAttachment(findingId, a);
    }

    @GetMapping("/findings/{findingId}/attachments/{attachmentId}")
    public ResponseEntity<byte[]> attachment(@PathVariable String findingId, @PathVariable String attachmentId, SecureTestPrincipal principal) {
        Authz.require(principal, Permission.VIEW);
        Finding f = findings.get(findingId);
        Finding.Attachment a = f.attachments.stream().filter(x -> x.id.equals(attachmentId)).findFirst()
                .orElseThrow(() -> ApiException.notFound("Attachment " + attachmentId));
        byte[] data;
        try {
            data = Files.readAllBytes(store.subdir("attachments").resolve(findingId.replaceAll("[^A-Za-z0-9-]", "_")).resolve(a.id));
        } catch (IOException e) {
            throw ApiException.notFound("Attachment file " + attachmentId);
        }
        String disposition = (INLINE_TYPES.contains(a.contentType) ? "inline" : "attachment") + "; filename=\"" + a.name.replace("\"", "") + "\"";
        return ResponseEntity.ok().header(HttpHeaders.CONTENT_TYPE, a.contentType).header(HttpHeaders.CONTENT_DISPOSITION, disposition)
                .header("X-Content-Type-Options", "nosniff").header("Content-Security-Policy", "sandbox; default-src 'none'").body(data);
    }

    // ------------------------------------------------------------------ issue trackers

    @GetMapping("/integrations/issue-trackers")
    public List<Map<String, Object>> trackers(SecureTestPrincipal principal) {
        Authz.require(principal, Permission.VIEW);
        return trackers.trackers();
    }

    public record IssueRequest(String tracker) { }

    @PostMapping("/findings/{findingId}/issues")
    public Finding createIssue(@PathVariable String findingId, @RequestBody IssueRequest body, SecureTestPrincipal principal) {
        SecureTestPrincipal p = contributor(principal);
        Finding f = findings.get(findingId);
        String tracker = body == null || body.tracker() == null ? "" : body.tracker();
        if (f.issues.containsKey(tracker)) throw ApiException.conflict("An issue is already linked: " + f.issues.get(tracker).url);
        Finding.IssueLink link = trackers.create(tracker, f);
        audit.record(p, "finding.issue.created", findingId, "OK", Map.of("tracker", tracker, "issue", link.key));
        return findings.linkIssue(findingId, link, p.name());
    }

    @PostMapping("/findings/{findingId}/issues/{tracker}/refresh")
    public Finding refreshIssue(@PathVariable String findingId, @PathVariable String tracker, SecureTestPrincipal principal) {
        SecureTestPrincipal p = Authz.require(principal, Permission.VIEW);
        Finding f = findings.get(findingId);
        Finding.IssueLink link = f.issues.get(tracker);
        if (link == null) throw ApiException.notFound("No " + tracker + " issue linked");
        trackers.refresh(link);
        findings.touch();
        return f;
    }
}
