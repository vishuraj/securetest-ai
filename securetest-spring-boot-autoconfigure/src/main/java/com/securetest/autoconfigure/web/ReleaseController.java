package com.securetest.autoconfigure.web;

import com.securetest.autoconfigure.release.ReleaseService;
import com.securetest.autoconfigure.security.Authz;
import com.securetest.autoconfigure.security.Rbac.Permission;
import com.securetest.autoconfigure.security.SecureTestPrincipal;
import com.securetest.autoconfigure.service.AuditService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Release readiness: checks, checklist, waivers and role-based sign-off. */
@RestController
@RequestMapping("${securetest.dashboard.path:/securetest}/api/v1")
public class ReleaseController {

    private final ReleaseService releases;
    private final AuditService audit;

    public ReleaseController(ReleaseService releases, AuditService audit) {
        this.releases = releases;
        this.audit = audit;
    }

    private Map<String, Object> view(ReleaseService.Release r) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("release", r);
        m.put("readiness", releases.readiness(r));
        return m;
    }

    @GetMapping("/releases")
    public List<Map<String, Object>> list(SecureTestPrincipal principal) {
        Authz.require(principal, Permission.VIEW);
        return releases.list().stream().map(this::view).toList();
    }

    @PostMapping("/releases")
    public ResponseEntity<Map<String, Object>> create(@RequestBody ReleaseService.ReleaseRequest body, SecureTestPrincipal principal) {
        SecureTestPrincipal p = Authz.require(principal, Permission.CONFIGURE);
        ReleaseService.Release r = releases.create(body, p.name());
        audit.record(p, "release.created", r.id, "OK", Map.of("version", r.version));
        return ResponseEntity.status(201).body(view(r));
    }

    @GetMapping("/releases/{id}")
    public Map<String, Object> get(@PathVariable String id, SecureTestPrincipal principal) {
        Authz.require(principal, Permission.VIEW);
        return view(releases.get(id));
    }

    public record WaiverRequest(String reason) { }

    @PostMapping("/releases/{id}/checks/{checkId}/waiver")
    public Map<String, Object> waive(@PathVariable String id, @PathVariable String checkId, @RequestBody WaiverRequest body, SecureTestPrincipal principal) {
        SecureTestPrincipal p = Authz.require(principal, Permission.APPROVE);
        ReleaseService.Release r = releases.waive(id, checkId, body == null ? null : body.reason(), p.name());
        audit.record(p, "release.waiver", id, "OK", Map.of("check", checkId, "reason", body.reason()));
        return view(r);
    }

    public record ItemUpdate(Boolean done) { }

    @PutMapping("/releases/{id}/items/{itemId}")
    public Map<String, Object> tick(@PathVariable String id, @PathVariable String itemId, @RequestBody ItemUpdate body, SecureTestPrincipal principal) {
        SecureTestPrincipal p = Authz.require(principal, Permission.EXECUTE);
        return view(releases.tick(id, itemId, body != null && Boolean.TRUE.equals(body.done()), p.name()));
    }

    public record SignoffRequest(String role, String decision, String comment) { }

    @PostMapping("/releases/{id}/signoffs")
    public Map<String, Object> signoff(@PathVariable String id, @RequestBody SignoffRequest body, SecureTestPrincipal principal) {
        SecureTestPrincipal p = Authz.require(principal, Permission.VIEW);
        ReleaseService.Release r = releases.signoff(id, body.role(), body.decision(), body.comment(), p);
        audit.record(p, "release.signoff", id, body.decision(), Map.of("role", String.valueOf(body.role()), "status", r.status));
        return view(r);
    }

    @PostMapping("/releases/{id}/released")
    public Map<String, Object> released(@PathVariable String id, SecureTestPrincipal principal) {
        SecureTestPrincipal p = Authz.require(principal, Permission.APPROVE);
        ReleaseService.Release r = releases.markReleased(id);
        audit.record(p, "release.released", id, "OK", Map.of("version", r.version));
        return view(r);
    }

    @PostMapping("/releases/{id}/reopen")
    public Map<String, Object> reopen(@PathVariable String id, SecureTestPrincipal principal) {
        SecureTestPrincipal p = Authz.require(principal, Permission.CONFIGURE);
        return view(releases.reopen(id));
    }
}
