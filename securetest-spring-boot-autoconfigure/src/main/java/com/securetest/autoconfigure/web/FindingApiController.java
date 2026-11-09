package com.securetest.autoconfigure.web;

import com.securetest.autoconfigure.SecureTestProperties;
import com.securetest.autoconfigure.security.ApiException;
import com.securetest.autoconfigure.security.Authz;
import com.securetest.autoconfigure.security.Rbac.Permission;
import com.securetest.autoconfigure.security.SecureTestPrincipal;
import com.securetest.autoconfigure.service.AuditService;
import com.securetest.autoconfigure.service.ChangeSetService;
import com.securetest.autoconfigure.service.FindingService;
import com.securetest.autoconfigure.service.RemediationService;
import com.securetest.autoconfigure.support.AppContext;
import com.securetest.core.model.Enums.FindingStatus;
import com.securetest.core.model.Finding;
import com.securetest.core.model.Severity;
import com.securetest.core.util.Hashing;
import com.securetest.core.util.SourceFiles;
import com.securetest.core.util.UnifiedDiff;
import com.securetest.migration.ChangeSet;
import com.securetest.migration.GitWorkspace;
import org.springframework.http.ContentDisposition;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/** Findings, governed exceptions, code highlighting and remediation change sets. */
@RestController
@RequestMapping("${securetest.dashboard.path:/securetest}/api/v1")
public class FindingApiController {

    private final FindingService findings;
    private final RemediationService remediation;
    private final ChangeSetService changes;
    private final AuditService audit;
    private final AppContext app;
    private final SecureTestProperties props;
    private final GitWorkspace git;

    public FindingApiController(FindingService findings, RemediationService remediation, ChangeSetService changes, AuditService audit,
                                AppContext app, SecureTestProperties props, GitWorkspace git) {
        this.findings = findings;
        this.remediation = remediation;
        this.changes = changes;
        this.audit = audit;
        this.app = app;
        this.props = props;
        this.git = git;
    }

    @GetMapping("/findings")
    public FindingService.Page<Finding> search(@RequestParam(required = false) String q,
                                               @RequestParam(required = false) String priority,
                                               @RequestParam(required = false) String status,
                                               @RequestParam(required = false) String module,
                                               @RequestParam(required = false) String source,
                                               @RequestParam(required = false) String sort,
                                               @RequestParam(defaultValue = "false") boolean includeClosed,
                                               @RequestParam(defaultValue = "0") int page,
                                               @RequestParam(defaultValue = "50") int size) {
        Authz.require(Permission.VIEW);
        Set<Severity> pr = csv(priority).stream().map(Severity::valueOf).collect(Collectors.toSet());
        Set<FindingStatus> st = csv(status).stream().map(FindingStatus::valueOf).collect(Collectors.toSet());
        return findings.search(new FindingService.Filter(q, pr, st, csv(module), source, sort, includeClosed),
                Math.max(0, page), Math.min(500, Math.max(1, size)));
    }

    private static Set<String> csv(String s) {
        if (s == null || s.isBlank()) return Set.of();
        return Arrays.stream(s.split(",")).map(String::trim).filter(x -> !x.isEmpty()).collect(Collectors.toSet());
    }

    @GetMapping("/findings/summary")
    public Map<String, Object> summary() {
        Authz.require(Permission.VIEW);
        return findings.summary();
    }

    @GetMapping("/findings/{findingId}")
    public Finding get(@PathVariable String findingId) {
        Authz.require(Permission.VIEW);
        return findings.get(findingId);
    }

    public record FindingUpdate(FindingStatus status, String owner, Instant dueDate, String note) { }

    @PatchMapping("/findings/{findingId}")
    public Finding update(@PathVariable String findingId, @RequestBody FindingUpdate body) {
        SecureTestPrincipal p = Authz.require(Permission.REMEDIATE);
        Finding f = findings.update(findingId, body.status(), body.owner(), body.dueDate(), body.note(), p.name());
        audit.record(p.name(), p.remoteAddress(), "finding.updated", findingId, "OK",
                Map.of("status", String.valueOf(body.status()), "owner", String.valueOf(body.owner())));
        return f;
    }

    public record SuppressionRequest(FindingStatus type, String reason, String owner, Instant expiresAt) { }

    @PostMapping("/findings/{findingId}/suppressions")
    public Finding suppress(@PathVariable String findingId, @RequestBody SuppressionRequest req) {
        SecureTestPrincipal p = Authz.require(Permission.REMEDIATE);
        Finding f = findings.get(findingId);
        Severity eff = f.priority == null ? f.sourceSeverity : f.priority;
        String approver = null;
        if (eff.atLeast(Severity.HIGH)) {
            if (!p.has(Permission.APPROVE)) throw ApiException.forbidden("Exceptions for High/Critical findings require APPROVE permission.");
            approver = p.name();
        }
        Finding out = findings.suppress(findingId, req.type() == null ? FindingStatus.SUPPRESSED : req.type(), req.reason(), req.owner(),
                req.expiresAt(), p.name(), approver);
        audit.record(p.name(), p.remoteAddress(), "finding.exception.created", findingId, "OK",
                Map.of("type", String.valueOf(req.type()), "owner", String.valueOf(req.owner()), "expires", String.valueOf(req.expiresAt())));
        return out;
    }

    @DeleteMapping("/findings/{findingId}/suppressions")
    public Finding revoke(@PathVariable String findingId) {
        SecureTestPrincipal p = Authz.require(Permission.REMEDIATE);
        Finding f = findings.revokeSuppression(findingId, p.name());
        audit.record(p.name(), p.remoteAddress(), "finding.exception.revoked", findingId, "OK", Map.of());
        return f;
    }

    /**
     * Code context with highlighting (SRS 7.6). Compares the current file hash with the one captured at scan time,
     * so a changed file is never presented as the scanned revision.
     */
    @GetMapping("/findings/{findingId}/source")
    public Map<String, Object> source(@PathVariable String findingId, @RequestParam(defaultValue = "12") int context) {
        Authz.require(Permission.VIEW);
        Finding f = findings.get(findingId);
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("path", f.filePath);
        m.put("scannedRevision", f.revision);
        m.put("snapshot", f.snippet);
        m.put("highlight", List.of(f.lineStart == null ? 0 : f.lineStart, f.lineEnd == null ? 0 : f.lineEnd));
        Path root = app.sourceRoot().orElse(null);
        if (f.filePath == null || root == null) {
            m.put("available", false);
            m.put("reason", f.filePath == null ? "This finding has no source location." : "No source workspace configured.");
            return m;
        }
        Path file;
        try {
            file = SourceFiles.resolveInside(root, f.filePath);
        } catch (SecurityException e) {
            throw ApiException.forbidden(e.getMessage());
        }
        if (!Files.isRegularFile(file) || SourceFiles.isSensitive(file)) {
            m.put("available", false);
            m.put("reason", Files.isRegularFile(file) ? "Sensitive file type: only the redacted scan-time snippet is shown." : "File no longer exists in the workspace.");
            return m;
        }
        try {
            String content = SourceFiles.read(file);
            List<String> lines = UnifiedDiff.lines(content);
            String hash = Hashing.sha256(file);
            boolean stale = f.fileHash != null && !f.fileHash.equals(hash);
            int start = f.lineStart == null ? 1 : f.lineStart;
            int end = f.lineEnd == null ? start : f.lineEnd;
            int ctx = Math.max(2, Math.min(60, context));
            m.put("available", true);
            m.put("stale", stale);
            m.put("currentRevision", git.head(root).orElse("workspace"));
            m.put("language", SourceFiles.extension(file));
            m.put("lines", SourceFiles.snippet(lines, start, end, ctx));
            m.put("totalLines", lines.size());
            if (stale) m.put("warning", "The file changed after the scan. The current file is shown for reference; the highlighted lines may have moved. "
                    + "The scan-time snippet is the authoritative evidence.");
            String tpl = props.getWorkspace().getIdeLinkTemplate();
            if (tpl != null && !tpl.isBlank()) {
                m.put("ideLink", tpl.replace("{absPath}", file.toAbsolutePath().toString().replace('\\', '/'))
                        .replace("{path}", f.filePath).replace("{line}", String.valueOf(start)));
            }
            String repo = props.getWorkspace().getRepositoryUrl();
            if (repo != null && f.revision != null && !f.revision.equals("workspace")) {
                m.put("repositoryLink", repo.replaceAll("/$", "") + "/blob/" + f.revision + "/" + f.filePath + "#L" + start);
            }
        } catch (java.io.IOException e) {
            throw new ApiException(500, "io_error", e.getMessage());
        }
        return m;
    }

    // ------------------------------------------------------------------ remediation

    @PostMapping("/remediations/preview")
    public Map<String, Object> preview(@RequestBody Map<String, String> body) {
        SecureTestPrincipal p = Authz.require(Permission.REMEDIATE);
        String id = body.get("findingId");
        if (id == null) throw ApiException.badRequest("findingId is required");
        return remediation.preview(id, p);
    }

    /** Opt-in AI-assisted fix proposal (securetest.ai.*). */
    @PostMapping("/remediations/ai-preview")
    public Map<String, Object> aiPreview(@RequestBody Map<String, String> body) {
        SecureTestPrincipal p = Authz.require(Permission.REMEDIATE);
        String id = body.get("findingId");
        if (id == null) throw ApiException.badRequest("findingId is required");
        return remediation.previewAi(id, p);
    }

    @GetMapping("/ai/status")
    public Map<String, Object> aiStatus() {
        Authz.require(Permission.VIEW);
        return remediation.aiStatus();
    }

    @GetMapping("/remediations")
    public List<ChangeSet> changeSets(@RequestParam(required = false) String kind) {
        Authz.require(Permission.VIEW);
        return changes.list(kind);
    }

    @GetMapping("/remediations/{id}")
    public ChangeSet changeSet(@PathVariable String id) {
        Authz.require(Permission.VIEW);
        return changes.get(id);
    }

    @GetMapping("/remediations/{id}/patch")
    public ResponseEntity<String> patch(@PathVariable String id) {
        SecureTestPrincipal p = Authz.require(Permission.VIEW);
        return ResponseEntity.ok().contentType(MediaType.parseMediaType("text/x-diff"))
                .header(HttpHeaders.CONTENT_DISPOSITION, ContentDisposition.attachment().filename(id + ".patch").build().toString())
                .body(changes.patch(id, p));
    }

    public record ApplyRequest(boolean createBranch, boolean allowDirtyWithSnapshot) { }

    @PostMapping("/remediations/{id}/apply")
    public ChangeSet apply(@PathVariable String id, @RequestBody(required = false) ApplyRequest body) {
        SecureTestPrincipal p = Authz.require(Permission.REMEDIATE);
        ApplyRequest r = body == null ? new ApplyRequest(true, false) : body;
        return changes.apply(id, r.createBranch(), r.allowDirtyWithSnapshot(), p);
    }

    @PostMapping("/remediations/{id}/validate")
    public ChangeSet validate(@PathVariable String id) {
        return changes.validate(id, Authz.require(Permission.REMEDIATE));
    }

    @PostMapping("/remediations/{id}/commit")
    public ChangeSet commit(@PathVariable String id) {
        return changes.commit(id, Authz.require(Permission.APPROVE));
    }

    @PostMapping("/remediations/{id}/undo")
    public ChangeSet undo(@PathVariable String id) {
        return changes.undo(id, Authz.require(Permission.REMEDIATE));
    }
}
