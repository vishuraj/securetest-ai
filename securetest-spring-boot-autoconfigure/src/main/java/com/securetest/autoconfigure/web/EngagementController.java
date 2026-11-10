package com.securetest.autoconfigure.web;

import com.securetest.autoconfigure.pentest.ChecklistTemplates;
import com.securetest.autoconfigure.pentest.EngagementService;
import com.securetest.autoconfigure.security.ApiException;
import com.securetest.autoconfigure.security.Authz;
import com.securetest.autoconfigure.security.Rbac.Permission;
import com.securetest.autoconfigure.security.SecureTestPrincipal;
import com.securetest.autoconfigure.service.AuditService;
import com.securetest.autoconfigure.service.ModuleService;
import com.securetest.core.model.ModuleCatalog;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Pentest / VAPT engagements. Available when the Pentest / VAPT module is on. */
@RestController
@RequestMapping("${securetest.dashboard.path:/securetest}/api/v1")
public class EngagementController {

    private final EngagementService engagements;
    private final ModuleService modules;
    private final AuditService audit;

    public EngagementController(EngagementService engagements, ModuleService modules, AuditService audit) {
        this.engagements = engagements;
        this.modules = modules;
        this.audit = audit;
    }

    private void enabled() {
        if (!modules.isEnabled(ModuleCatalog.PENTEST)) throw ApiException.conflict("The Pentest / VAPT module is disabled. Enable it in the dashboard.");
    }

    @GetMapping("/engagements/methodologies")
    public Map<String, String> methodologies(SecureTestPrincipal principal) {
        Authz.require(principal, Permission.VIEW);
        return ChecklistTemplates.METHODOLOGIES;
    }

    @GetMapping("/engagements")
    public List<Map<String, Object>> list(SecureTestPrincipal principal) {
        Authz.require(principal, Permission.VIEW);
        enabled();
        return engagements.list().stream().map(e -> {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("id", e.id);
            m.put("name", e.name);
            m.put("type", e.type);
            m.put("status", e.status);
            m.put("lead", e.lead);
            m.put("startDate", e.startDate);
            m.put("endDate", e.endDate);
            m.put("progress", engagements.progress(e.id));
            return m;
        }).toList();
    }

    @PostMapping("/engagements")
    public ResponseEntity<EngagementService.Engagement> create(@RequestBody EngagementService.EngagementRequest body, SecureTestPrincipal principal) {
        SecureTestPrincipal p = Authz.require(principal, Permission.CONFIGURE);
        enabled();
        EngagementService.Engagement e = engagements.create(body, p.name());
        audit.record(p, "engagement.created", e.id, "OK", Map.of("name", e.name, "scope", String.join(", ", e.scope)));
        return ResponseEntity.status(201).body(e);
    }

    @GetMapping("/engagements/{id}")
    public Map<String, Object> get(@PathVariable String id, SecureTestPrincipal principal) {
        Authz.require(principal, Permission.VIEW);
        enabled();
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("engagement", engagements.get(id));
        m.put("progress", engagements.progress(id));
        m.put("findings", engagements.findingsOf(id));
        return m;
    }

    @PatchMapping("/engagements/{id}")
    public EngagementService.Engagement update(@PathVariable String id, @RequestBody EngagementService.EngagementRequest body, SecureTestPrincipal principal) {
        SecureTestPrincipal p = Authz.require(principal, Permission.CONFIGURE);
        enabled();
        return engagements.update(id, body, p.name());
    }

    public record StatusChange(String status) { }

    @PostMapping("/engagements/{id}/status")
    public EngagementService.Engagement status(@PathVariable String id, @RequestBody StatusChange body, SecureTestPrincipal principal) {
        SecureTestPrincipal p = Authz.require(principal, Permission.CONFIGURE);
        enabled();
        EngagementService.Engagement e = engagements.transition(id, body == null ? null : body.status(), p.name());
        audit.record(p, "engagement.status", id, "OK", Map.of("status", e.status));
        return e;
    }

    public record CheckUpdate(String state, String note, List<String> findingIds) { }

    @PutMapping("/engagements/{id}/checklist/{itemId}")
    public EngagementService.Engagement check(@PathVariable String id, @PathVariable String itemId, @RequestBody CheckUpdate body,
                                              SecureTestPrincipal principal) {
        SecureTestPrincipal p = Authz.require(principal, Permission.EXECUTE);
        enabled();
        return engagements.check(id, itemId, body.state(), body.note(), body.findingIds(), p.name());
    }
}
