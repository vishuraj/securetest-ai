package com.securetest.autoconfigure.web;

import com.securetest.autoconfigure.SecureTestProperties;
import com.securetest.autoconfigure.security.ApiException;
import com.securetest.autoconfigure.security.Authz;
import com.securetest.autoconfigure.security.Rbac.Permission;
import com.securetest.autoconfigure.security.SecureTestPrincipal;
import com.securetest.autoconfigure.service.AuditService;
import com.securetest.autoconfigure.service.FindingService;
import com.securetest.autoconfigure.service.JobService;
import com.securetest.autoconfigure.service.ModuleService;
import com.securetest.autoconfigure.service.NotificationService;
import com.securetest.autoconfigure.service.PlatformServices.CompatibilityService;
import com.securetest.autoconfigure.service.PlatformServices.ControlPlaneClient;
import com.securetest.autoconfigure.service.ScannerRegistry;
import com.securetest.autoconfigure.service.TelemetryService;
import com.securetest.autoconfigure.support.AppContext;
import com.securetest.autoconfigure.support.LocalStore;
import com.securetest.core.model.Enums.JobStatus;
import com.securetest.core.model.Enums.ModuleState;
import com.securetest.core.model.ModuleCatalog;
import com.securetest.core.model.ModuleCatalog.ModuleInfo;
import com.securetest.core.model.ScanJob;
import com.securetest.core.model.Severity;
import com.securetest.core.spi.PreflightCheck;
import com.securetest.core.spi.ScannerDescriptor;
import com.securetest.core.util.Redactor;
import org.springframework.context.ApplicationContext;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.lang.reflect.Parameter;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeMap;

/** Overview, health, metrics, modules, scanners, settings, release gate and the API's own OpenAPI document. */
@RestController
@RequestMapping("${securetest.dashboard.path:/securetest}/api/v1")
public class CoreApiController {

    private final SecureTestProperties props;
    private final AppContext app;
    private final ModuleService modules;
    private final ScannerRegistry registry;
    private final JobService jobs;
    private final FindingService findings;
    private final TelemetryService telemetry;
    private final CompatibilityService compatibility;
    private final ControlPlaneClient controlPlane;
    private final NotificationService notifications;
    private final AuditService audit;
    private final LocalStore store;
    private final ApplicationContext context;

    public CoreApiController(SecureTestProperties props, AppContext app, ModuleService modules, ScannerRegistry registry, JobService jobs,
                             FindingService findings, TelemetryService telemetry, CompatibilityService compatibility,
                             ControlPlaneClient controlPlane, NotificationService notifications, AuditService audit, LocalStore store,
                             ApplicationContext context) {
        this.props = props;
        this.app = app;
        this.modules = modules;
        this.registry = registry;
        this.jobs = jobs;
        this.findings = findings;
        this.telemetry = telemetry;
        this.compatibility = compatibility;
        this.controlPlane = controlPlane;
        this.notifications = notifications;
        this.audit = audit;
        this.store = store;
        this.context = context;
    }

    @GetMapping("/me")
    public Map<String, Object> me(SecureTestPrincipal principal) {
        SecureTestPrincipal p = Authz.require(principal, null);
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("name", p.name());
        m.put("roles", p.roles());
        m.put("permissions", p.permissions());
        m.put("authMethod", p.authMethod());
        m.put("policy", Map.of(
                "allowAutoRemediation", props.getSecurity().isAllowAutoRemediation(),
                "requireApprovalForActiveScans", props.getSecurity().isRequireApprovalForActiveScans(),
                "allowExternalIntelligence", props.getSecurity().isAllowExternalIntelligence(),
                "productionLike", app.productionLike(),
                "aiEnabled", props.getAi().isEnabled() && props.getAi().isDataProcessingApproved(),
                "aiModel", props.getAi().getModel()));
        m.put("ideLinkTemplate", props.getWorkspace().getIdeLinkTemplate());
        return m;
    }

    @GetMapping("/overview")
    public Map<String, Object> overview(SecureTestPrincipal principal) {
        Authz.require(principal, Permission.VIEW);
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("application", app.info());
        m.put("sourceRoot", app.sourceRoot().map(Object::toString).orElse(null));
        m.put("health", telemetry.health());
        m.put("runtime", telemetry.snapshot(false));
        m.put("modules", moduleViews());
        m.put("findings", findings.summary());
        m.put("recentScans", jobs.list(null, null, 0, 8).items());
        m.put("lastScan", jobs.all().stream().filter(j -> j.endedAt != null).map(j -> j.endedAt).max(Comparator.naturalOrder()).orElse(null));
        m.put("compatibility", compatibility.checks().stream().filter(c -> !c.level().equals("OK")).toList());
        m.put("alerts", telemetry.alerts());
        m.put("notifications", notifications.recent().stream().limit(10).toList());
        m.put("gate", gate(principal));
        m.put("awaitingApproval", jobs.all().stream().filter(j -> j.status == JobStatus.AWAITING_APPROVAL).count());
        return m;
    }

    @GetMapping("/health")
    public Map<String, Object> health(SecureTestPrincipal principal) {
        Authz.require(principal, Permission.VIEW);
        Map<String, Object> self = new LinkedHashMap<>();
        self.put("status", "UP");
        self.put("storageWritable", store.writable());
        self.put("activeJobs", jobs.activeCount());
        self.put("scanners", registry.size());
        self.put("controlPlane", controlPlane.status());
        return Map.of("application", telemetry.health(), "securetest", self);
    }

    @GetMapping("/metrics")
    public Map<String, Object> metrics(@RequestParam(defaultValue = "false") boolean history, SecureTestPrincipal principal) {
        Authz.require(principal, Permission.VIEW);
        Map<String, Object> m = new LinkedHashMap<>(telemetry.snapshot(true));
        m.put("samplingEnabled", modules.isEnabled(ModuleCatalog.METRICS));
        if (history) m.put("history", telemetry.history());
        m.put("alerts", telemetry.alerts());
        return m;
    }

    @GetMapping(value = "/metrics/prometheus", produces = MediaType.TEXT_PLAIN_VALUE)
    public String prometheus(SecureTestPrincipal principal) {
        Authz.require(principal, Permission.VIEW);
        if (!modules.isEnabled(ModuleCatalog.METRICS)) throw ApiException.conflict("Enable the Runtime Metrics module to export metrics.");
        return telemetry.prometheus();
    }

    @GetMapping("/compatibility")
    public Map<String, Object> compatibility(SecureTestPrincipal principal) {
        Authz.require(principal, Permission.VIEW);
        return Map.of("checks", compatibility.checks(), "tools", compatibility.tools());
    }

    // ------------------------------------------------------------------ modules

    @GetMapping("/modules")
    public List<Map<String, Object>> modules(SecureTestPrincipal principal) {
        Authz.require(principal, Permission.VIEW);
        return moduleViews();
    }

    public record ModuleUpdate(Boolean enabled, Map<String, String> settings) { }

    @PutMapping("/modules/{moduleId}/configuration")
    public Map<String, Object> updateModule(@PathVariable String moduleId, @RequestBody ModuleUpdate body, SecureTestPrincipal principal) {
        SecureTestPrincipal p = Authz.require(principal, Permission.CONFIGURE);
        boolean before = modules.isEnabled(moduleId);
        ModuleService.Toggle t = modules.set(moduleId, body.enabled(), body.settings(), p.name());
        boolean after = modules.isEnabled(moduleId);
        if (before && !after) jobs.onModuleDisabled(moduleId, p);
        telemetry.reconcile();
        audit.record(p, "module.configured", moduleId, "OK",
                Map.of("enabled", before + " -> " + after, "version", String.valueOf(t.version)));
        return moduleView(ModuleCatalog.find(moduleId).orElseThrow());
    }

    private List<Map<String, Object>> moduleViews() {
        return ModuleCatalog.MODULES.stream().map(this::moduleView).toList();
    }

    private Map<String, Object> moduleView(ModuleInfo info) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("id", info.id());
        m.put("name", info.name());
        m.put("summary", info.summary());
        m.put("help", info.help());
        m.put("enabled", modules.isEnabled(info.id()));
        m.put("locked", modules.isLocked(info.id()));
        m.put("toggleSource", modules.source(info.id()));
        m.put("state", state(info.id()));
        m.put("scanners", registry.descriptors(info.id()).stream().map(ScannerDescriptor::getId).toList());
        Optional<ScanJob> last = jobs.latestForModule(info.id());
        m.put("lastRun", last.orElse(null));
        m.put("lastSuccess", jobs.all().stream().filter(j -> info.id().equals(j.moduleId) && j.status == JobStatus.COMPLETED)
                .map(j -> j.endedAt).max(Comparator.naturalOrder()).orElse(null));
        m.put("lastFailure", jobs.all().stream().filter(j -> info.id().equals(j.moduleId) && j.status == JobStatus.FAILED)
                .map(j -> j.endedAt).max(Comparator.naturalOrder()).orElse(null));
        m.put("openFindings", findings.openCounts(info.id()));
        m.put("settings", modules.settings(info.id()));
        return m;
    }

    private ModuleState state(String id) {
        if (!modules.isEnabled(id)) return ModuleState.DISABLED;
        if (Set.of(ModuleCatalog.MIGRATION).contains(id) && app.sourceRoot().isEmpty()) return ModuleState.NOT_CONFIGURED;
        List<ScanJob> mine = jobs.all().stream().filter(j -> id.equals(j.moduleId)).toList();
        if (mine.stream().anyMatch(j -> j.status == JobStatus.RUNNING)) return ModuleState.RUNNING;
        if (mine.stream().anyMatch(j -> j.status == JobStatus.QUEUED || j.status == JobStatus.AWAITING_APPROVAL)) return ModuleState.QUEUED;
        Map<Severity, Integer> open = findings.openCounts(id);
        if (open.getOrDefault(Severity.CRITICAL, 0) + open.getOrDefault(Severity.HIGH, 0) > 0) return ModuleState.NEEDS_ATTENTION;
        Optional<ScanJob> last = mine.stream().max(Comparator.comparing(j -> j.createdAt));
        if (last.isPresent() && last.get().status == JobStatus.FAILED) return ModuleState.FAILED;
        if (last.isPresent() && last.get().status == JobStatus.COMPLETED) return ModuleState.COMPLETED;
        return ModuleState.READY;
    }

    // ------------------------------------------------------------------ scanners

    @GetMapping("/scanners")
    public List<Map<String, Object>> scanners(@RequestParam(required = false) String module, SecureTestPrincipal principal) {
        Authz.require(principal, Permission.VIEW);
        List<Map<String, Object>> out = new ArrayList<>();
        for (ScannerDescriptor d : registry.descriptors(module)) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("descriptor", d);
            m.put("lastRun", jobs.latest(d.getId(), null).orElse(null));
            m.put("lastCompleted", jobs.latest(d.getId(), JobStatus.COMPLETED).orElse(null));
            out.add(m);
        }
        return out;
    }

    @PostMapping("/scanners/{scannerId}/preflight")
    public List<PreflightCheck> preflight(@PathVariable String scannerId, @RequestBody(required = false) Map<String, String> options, SecureTestPrincipal principal) {
        Authz.require(principal, Permission.EXECUTE);
        return jobs.preflight(scannerId, options == null ? Map.of() : options);
    }

    // ------------------------------------------------------------------ settings, gate, notifications

    @GetMapping("/settings")
    public Map<String, Object> settings(SecureTestPrincipal principal) {
        Authz.require(principal, Permission.VIEW);
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("mode", props.getMode());
        var d = props.getDashboard();
        m.put("dashboard", Map.of("path", props.normalizedPath(), "bindAddress", d.getBindAddress(),
                "authentication", Map.of("enabled", d.getAuthentication().isEnabled(), "provider", d.getAuthentication().getProvider(),
                        "users", d.getAuthentication().getUsers().stream().map(u -> Map.of("username", String.valueOf(u.getUsername()), "roles", u.getRoles())).toList(),
                        "roleMapping", d.getAuthentication().getRoleMapping())));
        Map<String, Object> mods = new LinkedHashMap<>();
        for (ModuleInfo info : ModuleCatalog.MODULES) {
            mods.put(info.id(), Map.of("enabled", modules.isEnabled(info.id()), "locked", modules.isLocked(info.id()), "source", modules.source(info.id())));
        }
        m.put("modules", mods);
        var e = props.getExecution();
        m.put("execution", Map.of("mode", e.getMode(), "maxConcurrentJobs", e.getMaxConcurrentJobs(), "maxQueuedJobs", e.getMaxQueuedJobs(),
                "jobTimeout", e.getJobTimeout().toString(), "allowedCommands", e.getAllowedCommands(), "validationCommand", e.getValidationCommand(),
                "gitEnabled", e.isGitEnabled()));
        var r = props.getData().getRetention();
        m.put("data", Map.of("storageDir", store.dir().toString(), "persist", props.getData().isPersist(),
                "retention", Map.of("findings", r.getFindings().toString(), "jobs", r.getJobs().toString(), "reports", r.getReports().toString(),
                        "rawMetrics", r.getRawMetrics().toString(), "audit", r.getAudit().toString())));
        var s = props.getSecurity();
        m.put("security", Map.of("redactSecrets", s.isRedactSecrets(), "enforceTargetAllowlist", s.isEnforceTargetAllowlist(),
                "targetAllowlist", s.getTargetAllowlist(), "allowAutoRemediation", s.isAllowAutoRemediation(),
                "requireApprovalForActiveScans", s.isRequireApprovalForActiveScans(), "allowExternalIntelligence", s.isAllowExternalIntelligence(),
                "ingestToken", s.getIngestTokenRef() == null ? "not configured" : Redactor.mask(s.getIngestTokenRef()), "apiRateLimit", s.getApiRateLimit()));
        m.put("workspace", Map.of("sourceRoot", app.sourceRoot().map(Object::toString).orElse("not configured"),
                "repositoryUrl", String.valueOf(props.getWorkspace().getRepositoryUrl()), "ideLinkTemplate", String.valueOf(props.getWorkspace().getIdeLinkTemplate())));
        m.put("telemetry", Map.of("sampleInterval", props.getTelemetry().getSampleInterval().toString(), "historySize", props.getTelemetry().getHistorySize(),
                "cpuAlertThreshold", props.getTelemetry().getCpuAlertThreshold(), "heapAlertThreshold", props.getTelemetry().getHeapAlertThreshold()));
        m.put("reports", Map.of("organization", props.getReports().getOrganization(), "classification", props.getReports().getClassification(),
                "timezone", String.valueOf(props.getReports().getTimezone())));
        m.put("notifications", props.getNotifications().getWebhooks().stream().map(w -> Map.of("name", w.getName(), "format", w.getFormat(),
                "events", w.getEvents(), "url", Redactor.isReference(w.getUrl()) ? w.getUrl() : "••••")).toList());
        m.put("policy", Map.of("failOn", props.getPolicy().getFailOn(), "maxCritical", props.getPolicy().getMaxCritical(),
                "maxHigh", props.getPolicy().getMaxHigh(), "slaDays", props.getPolicy().getSlaDays(), "maxSuppressionDays", props.getPolicy().getMaxSuppressionDays()));
        m.put("controlPlane", controlPlane.status());
        var ai = props.getAi();
        m.put("ai", Map.of("enabled", ai.isEnabled(), "dataProcessingApproved", ai.isDataProcessingApproved(), "provider", ai.getProvider(),
                "model", ai.getModel(), "effort", ai.getEffort(), "apiKey", Redactor.isReference(ai.getApiKeyRef()) ? ai.getApiKeyRef() : "••••",
                "contextLines", ai.getContextLines(), "dailyRequestLimit", ai.getDailyRequestLimit(), "refusalFallback", ai.isRefusalFallback(),
                "active", context.getBean(com.securetest.ai.AiRemediator.class).status()));
        var email = props.getNotifications().getEmail();
        m.put("email", Map.of("enabled", email.isEnabled(), "mailSenderAvailable", notifications.emailAvailable(),
                "from", email.getFrom(), "recipients", email.getTo().size(), "events", email.getEvents()));
        m.put("application", Map.of("environment", app.environmentName(), "criticality", props.getApplication().getCriticality(),
                "productionLike", app.productionLike()));
        return m;
    }

    /** CI/CD release gate: GET returns PASS/FAIL against policy thresholds. */
    @GetMapping("/gate")
    public Map<String, Object> gate(SecureTestPrincipal principal) {
        Authz.require(principal, Permission.VIEW);
        Map<Severity, Integer> open = findings.openCounts(null);
        int crit = open.getOrDefault(Severity.CRITICAL, 0);
        int high = open.getOrDefault(Severity.HIGH, 0);
        List<String> reasons = new ArrayList<>();
        if (crit > props.getPolicy().getMaxCritical()) reasons.add(crit + " open critical finding(s) (max " + props.getPolicy().getMaxCritical() + ")");
        Severity failOn = Severity.valueOf(props.getPolicy().getFailOn());
        if (failOn.rank() <= Severity.HIGH.rank() && high > props.getPolicy().getMaxHigh()) reasons.add(high + " open high finding(s) (max " + props.getPolicy().getMaxHigh() + ")");
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("status", reasons.isEmpty() ? "PASS" : "FAIL");
        m.put("reasons", reasons);
        m.put("open", open);
        m.put("evaluatedAt", Instant.now());
        return m;
    }

    @GetMapping("/notifications")
    public List<NotificationService.Notice> notifications(SecureTestPrincipal principal) {
        Authz.require(principal, Permission.VIEW);
        return notifications.recent();
    }

    // ------------------------------------------------------------------ OpenAPI for this API

    @GetMapping("/openapi.json")
    public Map<String, Object> openapi(SecureTestPrincipal principal) {
        Authz.require(principal, Permission.VIEW);
        Map<String, Object> paths = new TreeMap<>();
        for (EndpointCatalog.Endpoint e : context.getBean(EndpointCatalog.class).endpoints()) {
            @SuppressWarnings("unchecked")
            Map<String, Object> item = (Map<String, Object>) paths.computeIfAbsent(e.path(), k -> new LinkedHashMap<>());
            Map<String, Object> op = new LinkedHashMap<>();
            op.put("operationId", e.method().getName());
            op.put("summary", humanize(e.method().getName()));
            op.put("tags", List.of(e.beanType().getSimpleName().replace("ApiController", "")));
            List<Map<String, Object>> params = new ArrayList<>();
            for (Parameter prm : e.method().getParameters()) {
                var pv = prm.getAnnotation(PathVariable.class);
                var rp = prm.getAnnotation(RequestParam.class);
                if (pv != null) params.add(Map.of("name", prm.getName(), "in", "path", "required", true, "schema", Map.of("type", "string")));
                if (rp != null) params.add(Map.of("name", rp.value().isEmpty() ? prm.getName() : rp.value(), "in", "query", "required", rp.required(), "schema", Map.of("type", "string")));
                if (prm.getAnnotation(RequestBody.class) != null) op.put("requestBody", Map.of("content", Map.of("application/json", Map.of("schema", Map.of("type", "object")))));
            }
            if (!params.isEmpty()) op.put("parameters", params);
            op.put("responses", Map.of("200", Map.of("description", "OK"), "401", Map.of("description", "Unauthenticated"),
                    "403", Map.of("description", "Forbidden / CSRF header missing"), "422", Map.of("description", "Validation or preflight failure")));
            item.put(e.httpMethod().toLowerCase(), op);
        }
        Map<String, Object> doc = new LinkedHashMap<>();
        doc.put("openapi", "3.0.3");
        doc.put("info", Map.of("title", "SecureTest AI API", "version", "v1",
                "description", "Mutating requests require header " + "X-SecureTest-Request: 1. Long-running operations return a job id; poll its status URL."));
        doc.put("paths", paths);
        doc.put("components", Map.of("securitySchemes", Map.of("basic", Map.of("type", "http", "scheme", "basic"))));
        return doc;
    }

    private static String humanize(String name) {
        String s = name.replaceAll("([A-Z])", " $1").toLowerCase();
        return Character.toUpperCase(s.charAt(0)) + s.substring(1);
    }
}
