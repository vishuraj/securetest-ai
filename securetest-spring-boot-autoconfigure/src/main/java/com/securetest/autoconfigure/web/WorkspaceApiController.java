package com.securetest.autoconfigure.web;

import com.fasterxml.jackson.databind.JsonNode;
import com.securetest.adapters.builtin.RuntimeAlertScanner;
import com.securetest.autoconfigure.SecureTestProperties;
import com.securetest.autoconfigure.security.ApiException;
import com.securetest.autoconfigure.security.Authz;
import com.securetest.autoconfigure.security.Rbac.Permission;
import com.securetest.autoconfigure.security.RequestInfo;
import com.securetest.autoconfigure.security.SecureTestPrincipal;
import com.securetest.autoconfigure.service.AuditService;
import com.securetest.autoconfigure.service.FindingService;
import com.securetest.autoconfigure.service.ModuleService;
import com.securetest.autoconfigure.service.PlatformServices.CompatibilityService;
import com.securetest.autoconfigure.service.PlatformServices.ControlPlaneClient;
import com.securetest.autoconfigure.service.ScannerRegistry;
import com.securetest.autoconfigure.service.WorkspaceServices.TestManagementService;
import com.securetest.autoconfigure.support.SecretResolver;
import com.securetest.core.model.Finding;
import com.securetest.core.model.ModuleCatalog;
import com.securetest.core.spi.ScannerDescriptor;
import com.securetest.core.util.Redactor;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Manual / exploratory testing, integrations status and alert ingestion. */
@RestController
@RequestMapping("${securetest.dashboard.path:/securetest}/api/v1")
public class WorkspaceApiController {

    private final TestManagementService tests;
    private final ScannerRegistry registry;
    private final CompatibilityService compatibility;
    private final ControlPlaneClient controlPlane;
    private final SecureTestProperties props;
    private final SecretResolver secrets;
    private final FindingService findings;
    private final ModuleService modules;
    private final AuditService audit;

    public WorkspaceApiController(TestManagementService tests, ScannerRegistry registry, CompatibilityService compatibility,
                                  ControlPlaneClient controlPlane, SecureTestProperties props, SecretResolver secrets,
                                  FindingService findings, ModuleService modules, AuditService audit) {
        this.tests = tests;
        this.registry = registry;
        this.compatibility = compatibility;
        this.controlPlane = controlPlane;
        this.props = props;
        this.secrets = secrets;
        this.findings = findings;
        this.modules = modules;
        this.audit = audit;
    }

    // ------------------------------------------------------------------ manual & exploratory testing

    @GetMapping("/testing/cases")
    public Map<String, Object> cases(SecureTestPrincipal principal) {
        Authz.require(principal, Permission.VIEW);
        return Map.of("cases", tests.cases(), "summary", tests.summary());
    }

    @PostMapping("/testing/cases")
    public TestManagementService.TestCase saveCase(@RequestBody TestManagementService.TestCase body, SecureTestPrincipal principal) {
        SecureTestPrincipal p = Authz.require(principal, Permission.EXECUTE);
        TestManagementService.TestCase c = tests.saveCase(body, p.name());
        audit.record(p, "testcase.saved", c.id, "OK", Map.of());
        return c;
    }

    @PostMapping("/testing/cases/{id}/executions")
    public TestManagementService.TestCase execute(@PathVariable String id, @RequestBody Map<String, String> body, SecureTestPrincipal principal) {
        SecureTestPrincipal p = Authz.require(principal, Permission.EXECUTE);
        TestManagementService.TestCase c = tests.execute(id, body.getOrDefault("status", ""), body.get("notes"), body.get("evidence"), p.name());
        audit.record(p, "testcase.executed", id, c.status, Map.of());
        return c;
    }

    @DeleteMapping("/testing/cases/{id}")
    public void deleteCase(@PathVariable String id, SecureTestPrincipal principal) {
        SecureTestPrincipal p = Authz.require(principal, Permission.CONFIGURE);
        tests.deleteCase(id);
        audit.record(p, "testcase.deleted", id, "OK", Map.of());
    }

    @GetMapping("/testing/sessions")
    public List<TestManagementService.Session> sessions(SecureTestPrincipal principal) {
        Authz.require(principal, Permission.VIEW);
        return tests.sessions();
    }

    @PostMapping("/testing/sessions")
    public TestManagementService.Session saveSession(@RequestBody TestManagementService.Session body, SecureTestPrincipal principal) {
        SecureTestPrincipal p = Authz.require(principal, Permission.EXECUTE);
        return tests.saveSession(body, p.name());
    }

    @PutMapping("/testing/sessions/{id}")
    public TestManagementService.Session updateSession(@PathVariable String id, @RequestBody TestManagementService.Session body, SecureTestPrincipal principal) {
        SecureTestPrincipal p = Authz.require(principal, Permission.EXECUTE);
        body.id = id;
        return tests.saveSession(body, p.name());
    }

    // ------------------------------------------------------------------ integrations

    @GetMapping("/integrations")
    public Map<String, Object> integrations(SecureTestPrincipal principal) {
        Authz.require(principal, Permission.VIEW);
        List<Map<String, Object>> adapters = new ArrayList<>();
        for (ScannerDescriptor d : registry.descriptors(null)) {
            Map<String, Object> a = new LinkedHashMap<>();
            a.put("id", d.getId());
            a.put("name", d.getName());
            a.put("module", d.getModuleId());
            a.put("tool", d.getToolName());
            a.put("location", d.getLocation());
            a.put("mode", d.getMode());
            adapters.add(a);
        }
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("adapters", adapters);
        m.put("tools", compatibility.tools());
        m.put("controlPlane", controlPlane.status());
        m.put("webhooks", props.getNotifications().getWebhooks().stream().map(w -> Map.of("name", w.getName(), "format", w.getFormat(), "events", w.getEvents())).toList());
        m.put("eventIngestion", Map.of("enabled", props.getSecurity().getIngestTokenRef() != null,
                "path", props.normalizedPath() + "/api/v1/integrations/events", "header", "X-SecureTest-Token",
                "formats", List.of("falco", "wazuh", "generic")));
        m.put("compatibilityMatrix", Map.of(
                "SonarQube", "9.9 LTA, 10.x, SonarCloud (Web API)",
                "Trivy", "0.50+ (JSON schema v2)",
                "OWASP ZAP", "2.14+ (JSON API)",
                "Checkov", "3.x",
                "Prowler", "4.x / 5.x (OCSF JSON)",
                "Apache JMeter", "5.6+",
                "OSV", "api.osv.dev v1",
                "Falco / Wazuh", "Falco 0.37+ JSON output, Wazuh 4.x alerts.json"));
        return m;
    }

    /** Machine-to-machine ingestion of runtime security alerts (Falco HTTP output, Wazuh integrator, SIEM webhook). */
    @PostMapping("/integrations/events")
    public Map<String, Object> ingest(@RequestHeader(value = "X-SecureTest-Token", required = false) String token,
                                      @RequestBody JsonNode body, RequestInfo info) {
        String expected = secrets.resolve(props.getSecurity().getIngestTokenRef());
        if (expected == null || expected.isBlank()) throw ApiException.notFound("Event ingestion is not configured");
        if (token == null || !MessageDigest.isEqual(expected.getBytes(StandardCharsets.UTF_8), token.getBytes(StandardCharsets.UTF_8))) {
            audit.record("webhook", info.remoteAddress(), "events.ingest", "integrations", "DENIED", Map.of());
            throw new ApiException(401, "unauthenticated", "Invalid ingestion token");
        }
        if (!modules.isEnabled(ModuleCatalog.ADVANCED_SECURITY)) throw ApiException.conflict("The Advanced Security module is disabled.");
        List<JsonNode> events = new ArrayList<>();
        if (body.isArray()) body.forEach(events::add); else events.add(body);
        if (events.size() > 500) throw ApiException.badRequest("At most 500 events per request");
        List<Finding> converted = new ArrayList<>();
        for (JsonNode e : events) {
            Finding f = e.has("rule") && e.has("priority") ? RuntimeAlertScanner.falco(e)
                    : e.has("rule") && e.path("rule").has("level") ? RuntimeAlertScanner.wazuh(e) : RuntimeAlertScanner.generic(e);
            if (f == null) continue;
            f.moduleId = ModuleCatalog.ADVANCED_SECURITY;
            f.category = "Runtime alert";
            f.complianceTags.add("OWASP-A09");
            f.complianceTags.add("SOC2-CC7.2");
            f.evidence = Redactor.redact(f.evidence);
            converted.add(f);
        }
        List<Finding> stored = findings.ingestExternal("webhook", converted);
        audit.record("webhook", info.remoteAddress(), "events.ingest", "integrations", "OK", Map.of("received", String.valueOf(events.size()), "stored", String.valueOf(stored.size())));
        return Map.of("received", events.size(), "stored", stored.size());
    }
}
