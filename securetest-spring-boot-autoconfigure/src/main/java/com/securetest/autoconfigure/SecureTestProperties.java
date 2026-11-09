package com.securetest.autoconfigure;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * All SecureTest configuration (SRS FR-006, Appendix A). Secure defaults: every optional module,
 * external integration, auto-remediation and telemetry export is OFF; the dashboard is loopback-only.
 */
@ConfigurationProperties(prefix = "securetest")
public class SecureTestProperties {

    /** Master switch. When false nothing is registered. */
    private boolean enabled = true;
    /** embedded | connected (registers with a control plane). */
    private String mode = "embedded";
    private Dashboard dashboard = new Dashboard();
    private ControlPlane controlPlane = new ControlPlane();
    /** Per-module settings keyed by module id (health, metrics, testing, code-quality, ...). */
    private Map<String, Module> modules = new LinkedHashMap<>();
    private Execution execution = new Execution();
    private Data data = new Data();
    private Security security = new Security();
    private Workspace workspace = new Workspace();
    private Telemetry telemetry = new Telemetry();
    private Reports reports = new Reports();
    private Notifications notifications = new Notifications();
    private Policy policy = new Policy();
    private Application application = new Application();
    private Ai ai = new Ai();

    /** AI-assisted remediation (SRS 9.2). Off by default; needs BOTH enabled and data-processing-approved. */
    public static class Ai {
        private boolean enabled = false;
        /** Explicit acknowledgement that redacted code snippets may be sent to the provider. */
        private boolean dataProcessingApproved = false;
        private String provider = "anthropic";
        private String model = "claude-opus-5-5";
        /** low | medium | high | xhigh | max */
        private String effort = "high";
        private String apiKeyRef = "env://ANTHROPIC_API_KEY";
        private String baseUrl;
        /** Lines of context sent on each side of the flagged lines. */
        private int contextLines = 40;
        private int dailyRequestLimit = 50;
        /** Server-side refusal fallback (beta) so a safety decline is retried on a suitable model. */
        private boolean refusalFallback = true;

        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean enabled) { this.enabled = enabled; }
        public boolean isDataProcessingApproved() { return dataProcessingApproved; }
        public void setDataProcessingApproved(boolean v) { this.dataProcessingApproved = v; }
        public String getProvider() { return provider; }
        public void setProvider(String provider) { this.provider = provider; }
        public String getModel() { return model; }
        public void setModel(String model) { this.model = model; }
        public String getEffort() { return effort; }
        public void setEffort(String effort) { this.effort = effort; }
        public String getApiKeyRef() { return apiKeyRef; }
        public void setApiKeyRef(String apiKeyRef) { this.apiKeyRef = apiKeyRef; }
        public String getBaseUrl() { return baseUrl; }
        public void setBaseUrl(String baseUrl) { this.baseUrl = baseUrl; }
        public int getContextLines() { return contextLines; }
        public void setContextLines(int contextLines) { this.contextLines = contextLines; }
        public int getDailyRequestLimit() { return dailyRequestLimit; }
        public void setDailyRequestLimit(int v) { this.dailyRequestLimit = v; }
        public boolean isRefusalFallback() { return refusalFallback; }
        public void setRefusalFallback(boolean v) { this.refusalFallback = v; }
    }

    public static class Dashboard {
        /** Unset = enabled except when a 'prod'/'production' profile is active. */
        private Boolean enabled;
        private String path = "/securetest";
        /** 127.0.0.1 (default) rejects non-loopback clients. Use 0.0.0.0 only with authentication and TLS. */
        private String bindAddress = "127.0.0.1";
        private Authentication authentication = new Authentication();

        public Boolean getEnabled() { return enabled; }
        public void setEnabled(Boolean enabled) { this.enabled = enabled; }
        public String getPath() { return path; }
        public void setPath(String path) { this.path = path; }
        public String getBindAddress() { return bindAddress; }
        public void setBindAddress(String bindAddress) { this.bindAddress = bindAddress; }
        public Authentication getAuthentication() { return authentication; }
        public void setAuthentication(Authentication authentication) { this.authentication = authentication; }
    }

    public static class Authentication {
        private boolean enabled = true;
        /**
         * local-dev: loopback clients act as a local administrator (development profile).
         * basic: users below with HTTP Basic.
         * container: the host application's authentication (e.g. Spring Security / OIDC); roles via role-mapping.
         * oidc: SecureTest's own OpenID Connect sign-in (authorization code + PKCE); roles from a token claim.
         */
        private String provider = "local-dev";
        private Oidc oidc = new Oidc();
        private List<User> users = new ArrayList<>();
        /** Host role → SecureTest role (VIEWER, DEVELOPER, QA, SECURITY, DEVOPS, OWNER, ADMIN). */
        private Map<String, String> roleMapping = new LinkedHashMap<>();

        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean enabled) { this.enabled = enabled; }
        public String getProvider() { return provider; }
        public void setProvider(String provider) { this.provider = provider; }
        public List<User> getUsers() { return users; }
        public void setUsers(List<User> users) { this.users = users; }
        public Map<String, String> getRoleMapping() { return roleMapping; }
        public void setRoleMapping(Map<String, String> roleMapping) { this.roleMapping = roleMapping; }
        public Oidc getOidc() { return oidc; }
        public void setOidc(Oidc oidc) { this.oidc = oidc; }
    }

    /** OpenID Connect settings for provider=oidc (Keycloak, Entra ID, Okta, Auth0, Google...). */
    public static class Oidc {
        /** Issuer URL; discovery is read from {issuer}/.well-known/openid-configuration. */
        private String issuerUri;
        private String clientId;
        /** Secret reference for confidential clients (omit for public clients using PKCE only). */
        private String clientSecretRef;
        private String scopes = "openid profile email";
        /** Claim holding roles/groups; dot path allowed (e.g. realm_access.roles for Keycloak). */
        private String rolesClaim = "roles";
        private String usernameClaim = "preferred_username";
        /** Role given to authenticated users with no mapped role; empty = deny. */
        private String defaultRole;
        /** Override when behind a proxy that rewrites host/scheme. */
        private String redirectUri;
        private Duration sessionTimeout = Duration.ofHours(8);

        public String getIssuerUri() { return issuerUri; }
        public void setIssuerUri(String issuerUri) { this.issuerUri = issuerUri; }
        public String getClientId() { return clientId; }
        public void setClientId(String clientId) { this.clientId = clientId; }
        public String getClientSecretRef() { return clientSecretRef; }
        public void setClientSecretRef(String clientSecretRef) { this.clientSecretRef = clientSecretRef; }
        public String getScopes() { return scopes; }
        public void setScopes(String scopes) { this.scopes = scopes; }
        public String getRolesClaim() { return rolesClaim; }
        public void setRolesClaim(String rolesClaim) { this.rolesClaim = rolesClaim; }
        public String getUsernameClaim() { return usernameClaim; }
        public void setUsernameClaim(String usernameClaim) { this.usernameClaim = usernameClaim; }
        public String getDefaultRole() { return defaultRole; }
        public void setDefaultRole(String defaultRole) { this.defaultRole = defaultRole; }
        public String getRedirectUri() { return redirectUri; }
        public void setRedirectUri(String redirectUri) { this.redirectUri = redirectUri; }
        public Duration getSessionTimeout() { return sessionTimeout; }
        public void setSessionTimeout(Duration sessionTimeout) { this.sessionTimeout = sessionTimeout; }
    }

    public static class User {
        private String username;
        /** {sha256}hex, {env}VARIABLE, or {noop}plain (development only). */
        private String password;
        private List<String> roles = new ArrayList<>(List.of("VIEWER"));

        public String getUsername() { return username; }
        public void setUsername(String username) { this.username = username; }
        public String getPassword() { return password; }
        public void setPassword(String password) { this.password = password; }
        public List<String> getRoles() { return roles; }
        public void setRoles(List<String> roles) { this.roles = roles; }
    }

    public static class ControlPlane {
        private boolean enabled = false;
        private String url;
        private String enrollmentTokenRef;
        private Duration heartbeat = Duration.ofSeconds(60);

        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean enabled) { this.enabled = enabled; }
        public String getUrl() { return url; }
        public void setUrl(String url) { this.url = url; }
        public String getEnrollmentTokenRef() { return enrollmentTokenRef; }
        public void setEnrollmentTokenRef(String enrollmentTokenRef) { this.enrollmentTokenRef = enrollmentTokenRef; }
        public Duration getHeartbeat() { return heartbeat; }
        public void setHeartbeat(Duration heartbeat) { this.heartbeat = heartbeat; }
    }

    public static class Module {
        /** Default state; null = catalog default (only 'health' is on). */
        private Boolean enabled;
        /** Policy lock: dashboard users cannot change the toggle. */
        private boolean locked;
        /** Performance only: allow the built-in load generator to run inside this JVM. */
        private boolean allowEmbeddedLoadGeneration;
        /** Performance only: maximum virtual users per test (resource budget). */
        private int maxConcurrency = 50;

        public Boolean getEnabled() { return enabled; }
        public void setEnabled(Boolean enabled) { this.enabled = enabled; }
        public boolean isLocked() { return locked; }
        public void setLocked(boolean locked) { this.locked = locked; }
        public boolean isAllowEmbeddedLoadGeneration() { return allowEmbeddedLoadGeneration; }
        public void setAllowEmbeddedLoadGeneration(boolean v) { this.allowEmbeddedLoadGeneration = v; }
        public int getMaxConcurrency() { return maxConcurrency; }
        public void setMaxConcurrency(int maxConcurrency) { this.maxConcurrency = maxConcurrency; }
    }

    public static class Execution {
        /** local = embedded executor (bounded); remote-worker is reserved for the control plane edition. */
        private String mode = "local";
        private Duration connectTimeout = Duration.ofSeconds(5);
        private Duration jobTimeout = Duration.ofMinutes(30);
        private int maxConcurrentJobs = 2;
        private int maxQueuedJobs = 20;
        /** Executables external adapters may start (e.g. trivy, checkov, jmeter, mvn, gradle). Empty = none. */
        private List<String> allowedCommands = new ArrayList<>();
        /** Command used to validate applied remediations / migrations. */
        private List<String> validationCommand = new ArrayList<>(List.of("mvn", "-B", "-q", "verify"));
        private boolean gitEnabled = true;
        /** Cancel running jobs when their module is disabled (otherwise they finish, new ones are blocked). */
        private boolean cancelRunningOnDisable = false;

        public String getMode() { return mode; }
        public void setMode(String mode) { this.mode = mode; }
        public Duration getConnectTimeout() { return connectTimeout; }
        public void setConnectTimeout(Duration connectTimeout) { this.connectTimeout = connectTimeout; }
        public Duration getJobTimeout() { return jobTimeout; }
        public void setJobTimeout(Duration jobTimeout) { this.jobTimeout = jobTimeout; }
        public int getMaxConcurrentJobs() { return maxConcurrentJobs; }
        public void setMaxConcurrentJobs(int maxConcurrentJobs) { this.maxConcurrentJobs = maxConcurrentJobs; }
        public int getMaxQueuedJobs() { return maxQueuedJobs; }
        public void setMaxQueuedJobs(int maxQueuedJobs) { this.maxQueuedJobs = maxQueuedJobs; }
        public List<String> getAllowedCommands() { return allowedCommands; }
        public void setAllowedCommands(List<String> allowedCommands) { this.allowedCommands = allowedCommands; }
        public List<String> getValidationCommand() { return validationCommand; }
        public void setValidationCommand(List<String> validationCommand) { this.validationCommand = validationCommand; }
        public boolean isGitEnabled() { return gitEnabled; }
        public void setGitEnabled(boolean gitEnabled) { this.gitEnabled = gitEnabled; }
        public boolean isCancelRunningOnDisable() { return cancelRunningOnDisable; }
        public void setCancelRunningOnDisable(boolean v) { this.cancelRunningOnDisable = v; }
    }

    public static class Data {
        /** Default: ${user.home}/.securetest/${spring.application.name}. */
        private String storageDir;
        private boolean persist = true;
        private Retention retention = new Retention();

        public String getStorageDir() { return storageDir; }
        public void setStorageDir(String storageDir) { this.storageDir = storageDir; }
        public boolean isPersist() { return persist; }
        public void setPersist(boolean persist) { this.persist = persist; }
        public Retention getRetention() { return retention; }
        public void setRetention(Retention retention) { this.retention = retention; }
    }

    public static class Retention {
        private Duration findings = Duration.ofDays(365);
        private Duration jobs = Duration.ofDays(365);
        private Duration reports = Duration.ofDays(180);
        private Duration rawMetrics = Duration.ofDays(14);
        private Duration audit = Duration.ofDays(730);
        private boolean workerWorkspaceCleanup = true;

        public Duration getFindings() { return findings; }
        public void setFindings(Duration findings) { this.findings = findings; }
        public Duration getJobs() { return jobs; }
        public void setJobs(Duration jobs) { this.jobs = jobs; }
        public Duration getReports() { return reports; }
        public void setReports(Duration reports) { this.reports = reports; }
        public Duration getRawMetrics() { return rawMetrics; }
        public void setRawMetrics(Duration rawMetrics) { this.rawMetrics = rawMetrics; }
        public Duration getAudit() { return audit; }
        public void setAudit(Duration audit) { this.audit = audit; }
        public boolean isWorkerWorkspaceCleanup() { return workerWorkspaceCleanup; }
        public void setWorkerWorkspaceCleanup(boolean v) { this.workerWorkspaceCleanup = v; }
    }

    public static class Security {
        private boolean redactSecrets = true;
        private boolean enforceTargetAllowlist = true;
        /** Authorized targets: self, host names, *.domain wildcards, CIDR blocks. */
        private List<String> targetAllowlist = new ArrayList<>(List.of("self"));
        private boolean allowAutoRemediation = false;
        private boolean requireApprovalForActiveScans = true;
        /** Allow sending package coordinates to public vulnerability databases (OSV). */
        private boolean allowExternalIntelligence = false;
        /** Secret reference of the token required by the event-ingestion webhook. Unset = endpoint disabled. */
        private String ingestTokenRef;
        /** Requests per second per client for the dashboard API. */
        private int apiRateLimit = 30;

        public boolean isRedactSecrets() { return redactSecrets; }
        public void setRedactSecrets(boolean redactSecrets) { this.redactSecrets = redactSecrets; }
        public boolean isEnforceTargetAllowlist() { return enforceTargetAllowlist; }
        public void setEnforceTargetAllowlist(boolean v) { this.enforceTargetAllowlist = v; }
        public List<String> getTargetAllowlist() { return targetAllowlist; }
        public void setTargetAllowlist(List<String> targetAllowlist) { this.targetAllowlist = targetAllowlist; }
        public boolean isAllowAutoRemediation() { return allowAutoRemediation; }
        public void setAllowAutoRemediation(boolean v) { this.allowAutoRemediation = v; }
        public boolean isRequireApprovalForActiveScans() { return requireApprovalForActiveScans; }
        public void setRequireApprovalForActiveScans(boolean v) { this.requireApprovalForActiveScans = v; }
        public boolean isAllowExternalIntelligence() { return allowExternalIntelligence; }
        public void setAllowExternalIntelligence(boolean v) { this.allowExternalIntelligence = v; }
        public String getIngestTokenRef() { return ingestTokenRef; }
        public void setIngestTokenRef(String ingestTokenRef) { this.ingestTokenRef = ingestTokenRef; }
        public int getApiRateLimit() { return apiRateLimit; }
        public void setApiRateLimit(int apiRateLimit) { this.apiRateLimit = apiRateLimit; }
    }

    public static class Workspace {
        /** Source repository root. Unset = the working directory when it contains a build file. */
        private String sourceRoot;
        private String repositoryUrl;
        /** IDE deep link, e.g. idea://open?file={absPath}&line={line} or vscode://file/{absPath}:{line}. */
        private String ideLinkTemplate;

        public String getSourceRoot() { return sourceRoot; }
        public void setSourceRoot(String sourceRoot) { this.sourceRoot = sourceRoot; }
        public String getRepositoryUrl() { return repositoryUrl; }
        public void setRepositoryUrl(String repositoryUrl) { this.repositoryUrl = repositoryUrl; }
        public String getIdeLinkTemplate() { return ideLinkTemplate; }
        public void setIdeLinkTemplate(String ideLinkTemplate) { this.ideLinkTemplate = ideLinkTemplate; }
    }

    public static class Telemetry {
        private Duration sampleInterval = Duration.ofSeconds(15);
        private int historySize = 240;
        private double cpuAlertThreshold = 90;
        private double heapAlertThreshold = 90;
        private double errorRateAlertThreshold = 5;

        public Duration getSampleInterval() { return sampleInterval; }
        public void setSampleInterval(Duration sampleInterval) { this.sampleInterval = sampleInterval; }
        public int getHistorySize() { return historySize; }
        public void setHistorySize(int historySize) { this.historySize = historySize; }
        public double getCpuAlertThreshold() { return cpuAlertThreshold; }
        public void setCpuAlertThreshold(double v) { this.cpuAlertThreshold = v; }
        public double getHeapAlertThreshold() { return heapAlertThreshold; }
        public void setHeapAlertThreshold(double v) { this.heapAlertThreshold = v; }
        public double getErrorRateAlertThreshold() { return errorRateAlertThreshold; }
        public void setErrorRateAlertThreshold(double v) { this.errorRateAlertThreshold = v; }
    }

    public static class Reports {
        private String organization = "SecureTest AI";
        private String classification = "INTERNAL";
        /** IANA zone for report timestamps; default = system zone. */
        private String timezone;

        public String getOrganization() { return organization; }
        public void setOrganization(String organization) { this.organization = organization; }
        public String getClassification() { return classification; }
        public void setClassification(String classification) { this.classification = classification; }
        public String getTimezone() { return timezone; }
        public void setTimezone(String timezone) { this.timezone = timezone; }
    }

    public static class Notifications {
        private List<Webhook> webhooks = new ArrayList<>();
        private Email email = new Email();

        public List<Webhook> getWebhooks() { return webhooks; }
        public void setWebhooks(List<Webhook> webhooks) { this.webhooks = webhooks; }
        public Email getEmail() { return email; }
        public void setEmail(Email email) { this.email = email; }
    }

    /** E-mail notifications through the application's spring.mail.* (spring-boot-starter-mail) configuration. */
    public static class Email {
        private boolean enabled = false;
        private String from = "securetest@localhost";
        private List<String> to = new ArrayList<>();
        private List<String> events = new ArrayList<>(List.of("finding.critical", "scan.failed", "approval.required", "alert.threshold"));

        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean enabled) { this.enabled = enabled; }
        public String getFrom() { return from; }
        public void setFrom(String from) { this.from = from; }
        public List<String> getTo() { return to; }
        public void setTo(List<String> to) { this.to = to; }
        public List<String> getEvents() { return events; }
        public void setEvents(List<String> events) { this.events = events; }
    }

    public static class Webhook {
        private String name = "webhook";
        /** URL or secret reference resolving to the URL. */
        private String url;
        /** slack | teams | generic */
        private String format = "slack";
        /** scan.completed, scan.failed, finding.critical, report.ready, alert.threshold, approval.required */
        private List<String> events = new ArrayList<>(List.of("scan.failed", "finding.critical", "alert.threshold", "approval.required"));

        public String getName() { return name; }
        public void setName(String name) { this.name = name; }
        public String getUrl() { return url; }
        public void setUrl(String url) { this.url = url; }
        public String getFormat() { return format; }
        public void setFormat(String format) { this.format = format; }
        public List<String> getEvents() { return events; }
        public void setEvents(List<String> events) { this.events = events; }
    }

    public static class Policy {
        /** Release gate fails when open findings at/above this priority exceed the limits below. */
        private String failOn = "HIGH";
        private int maxCritical = 0;
        private int maxHigh = 0;
        /** Days to remediate per priority (SLA report). */
        private Map<String, Integer> slaDays = new LinkedHashMap<>(Map.of("CRITICAL", 7, "HIGH", 30, "MEDIUM", 90, "LOW", 180, "INFO", 365));
        private int maxSuppressionDays = 365;

        public String getFailOn() { return failOn; }
        public void setFailOn(String failOn) { this.failOn = failOn; }
        public int getMaxCritical() { return maxCritical; }
        public void setMaxCritical(int maxCritical) { this.maxCritical = maxCritical; }
        public int getMaxHigh() { return maxHigh; }
        public void setMaxHigh(int maxHigh) { this.maxHigh = maxHigh; }
        public Map<String, Integer> getSlaDays() { return slaDays; }
        public void setSlaDays(Map<String, Integer> slaDays) { this.slaDays = slaDays; }
        public int getMaxSuppressionDays() { return maxSuppressionDays; }
        public void setMaxSuppressionDays(int v) { this.maxSuppressionDays = v; }
    }

    public static class Application {
        private String serviceId;
        /** Overrides the environment name; default = first active profile or "local". */
        private String environment;
        /** low | medium | high business criticality (feeds priority). */
        private String criticality = "medium";

        public String getServiceId() { return serviceId; }
        public void setServiceId(String serviceId) { this.serviceId = serviceId; }
        public String getEnvironment() { return environment; }
        public void setEnvironment(String environment) { this.environment = environment; }
        public String getCriticality() { return criticality; }
        public void setCriticality(String criticality) { this.criticality = criticality; }
    }

    public boolean isEnabled() { return enabled; }
    public void setEnabled(boolean enabled) { this.enabled = enabled; }
    public String getMode() { return mode; }
    public void setMode(String mode) { this.mode = mode; }
    public Dashboard getDashboard() { return dashboard; }
    public void setDashboard(Dashboard dashboard) { this.dashboard = dashboard; }
    public ControlPlane getControlPlane() { return controlPlane; }
    public void setControlPlane(ControlPlane controlPlane) { this.controlPlane = controlPlane; }
    public Map<String, Module> getModules() { return modules; }
    public void setModules(Map<String, Module> modules) { this.modules = modules; }
    public Execution getExecution() { return execution; }
    public void setExecution(Execution execution) { this.execution = execution; }
    public Data getData() { return data; }
    public void setData(Data data) { this.data = data; }
    public Security getSecurity() { return security; }
    public void setSecurity(Security security) { this.security = security; }
    public Workspace getWorkspace() { return workspace; }
    public void setWorkspace(Workspace workspace) { this.workspace = workspace; }
    public Telemetry getTelemetry() { return telemetry; }
    public void setTelemetry(Telemetry telemetry) { this.telemetry = telemetry; }
    public Reports getReports() { return reports; }
    public void setReports(Reports reports) { this.reports = reports; }
    public Notifications getNotifications() { return notifications; }
    public void setNotifications(Notifications notifications) { this.notifications = notifications; }
    public Policy getPolicy() { return policy; }
    public void setPolicy(Policy policy) { this.policy = policy; }
    public Application getApplication() { return application; }
    public void setApplication(Application application) { this.application = application; }

    public Ai getAi() { return ai; }
    public void setAi(Ai ai) { this.ai = ai; }

    public Module module(String id) {
        return modules.getOrDefault(id, new Module());
    }

    public String normalizedPath() {
        String p = dashboard.getPath() == null || dashboard.getPath().isBlank() ? "/securetest" : dashboard.getPath().trim();
        if (!p.startsWith("/")) p = "/" + p;
        while (p.endsWith("/") && p.length() > 1) p = p.substring(0, p.length() - 1);
        return p;
    }
}
