package com.securetest.autoconfigure.web;

import com.securetest.autoconfigure.asm.AttackSurfaceScanner;
import com.securetest.autoconfigure.asm.AttackSurfaceService;
import com.securetest.autoconfigure.security.ApiException;
import com.securetest.autoconfigure.security.Authz;
import com.securetest.autoconfigure.security.Rbac.Permission;
import com.securetest.autoconfigure.security.SecureTestPrincipal;
import com.securetest.autoconfigure.service.AuditService;
import com.securetest.autoconfigure.service.ModuleService;
import com.securetest.autoconfigure.service.WorkspaceServices.ScheduleService;
import com.securetest.core.model.ModuleCatalog;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** External attack surface: the asset register and its monitoring schedule. */
@RestController
@RequestMapping("${securetest.dashboard.path:/securetest}/api/v1")
public class AttackSurfaceController {

    private final AttackSurfaceService inventory;
    private final ModuleService modules;
    private final ScheduleService schedules;
    private final AuditService audit;

    public AttackSurfaceController(AttackSurfaceService inventory, ModuleService modules, ScheduleService schedules, AuditService audit) {
        this.inventory = inventory;
        this.modules = modules;
        this.schedules = schedules;
        this.audit = audit;
    }

    private void enabled() {
        if (!modules.isEnabled(ModuleCatalog.ATTACK_SURFACE)) throw ApiException.conflict("The Attack Surface module is disabled. Enable it in the dashboard.");
    }

    @GetMapping("/attack-surface")
    public Map<String, Object> overview(SecureTestPrincipal principal) {
        Authz.require(principal, Permission.VIEW);
        enabled();
        List<AttackSurfaceService.Asset> all = inventory.list();
        Instant soon = Instant.now().plus(Duration.ofDays(30));
        Map<String, Object> totals = new LinkedHashMap<>();
        totals.put("registered", all.stream().filter(a -> "MANUAL".equals(a.source)).count());
        totals.put("discovered", all.stream().filter(a -> "DISCOVERED".equals(a.source)).count());
        totals.put("live", all.stream().filter(a -> a.resolves).count());
        totals.put("expiringCertificates", all.stream().filter(a -> a.certificateExpires != null && a.certificateExpires.isBefore(soon)).count());
        totals.put("sensitive", all.stream().filter(a -> a.tags.contains("sensitive")).count());
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("totals", totals);
        m.put("assets", all);
        m.put("monitoring", schedules.list().stream().filter(s -> AttackSurfaceScanner.ID.equals(s.scannerId) || "dependency-scan".equals(s.scannerId)).toList());
        return m;
    }

    public record AssetRequest(String host, String kind, String owner) { }

    @PostMapping("/attack-surface/assets")
    public ResponseEntity<AttackSurfaceService.Asset> register(@RequestBody AssetRequest body, SecureTestPrincipal principal) {
        SecureTestPrincipal p = Authz.require(principal, Permission.CONFIGURE);
        enabled();
        AttackSurfaceService.Asset a = inventory.register(body.host(), body.kind(), body.owner(), p.name());
        audit.record(p, "asset.registered", a.host, "OK", Map.of("kind", a.kind));
        return ResponseEntity.status(201).body(a);
    }

    @DeleteMapping("/attack-surface/assets/{host}")
    public Map<String, Object> remove(@PathVariable String host, SecureTestPrincipal principal) {
        SecureTestPrincipal p = Authz.require(principal, Permission.CONFIGURE);
        enabled();
        inventory.remove(host);
        audit.record(p, "asset.removed", host, "OK", Map.of());
        return Map.of("removed", host);
    }

    public record MonitoringRequest(String cron) { }

    /** Continuous monitoring: a daily attack-surface scan (and a daily dependency check when that scanner exists). */
    @PostMapping("/attack-surface/monitoring")
    public List<Object> monitor(@RequestBody(required = false) MonitoringRequest body, SecureTestPrincipal principal) {
        SecureTestPrincipal p = Authz.require(principal, Permission.CONFIGURE);
        enabled();
        String cron = body == null || body.cron() == null || body.cron().isBlank() ? "0 0 6 * * *" : body.cron();
        List<Object> created = new ArrayList<>();
        boolean exists = schedules.list().stream().anyMatch(s -> AttackSurfaceScanner.ID.equals(s.scannerId));
        if (!exists) created.add(schedules.create(AttackSurfaceScanner.ID, null, cron, p));
        audit.record(p, "attack-surface.monitoring", "schedule", "OK", Map.of("cron", cron));
        return created;
    }
}
