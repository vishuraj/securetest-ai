package com.securetest.autoconfigure;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.securetest.adapters.builtin.ActiveProbeScanner;
import com.securetest.adapters.builtin.ApiContractScanner;
import com.securetest.adapters.builtin.DependencyScanner;
import com.securetest.adapters.builtin.HttpSecurityScanner;
import com.securetest.adapters.builtin.IacScanner;
import com.securetest.adapters.builtin.LoadTestScanner;
import com.securetest.adapters.builtin.PortScanner;
import com.securetest.adapters.builtin.RuntimeAlertScanner;
import com.securetest.adapters.builtin.SecretsScanner;
import com.securetest.adapters.builtin.StaticAnalysisScanner;
import com.securetest.adapters.builtin.TestResultsScanner;
import com.securetest.adapters.builtin.TestRunnerScanner;
import com.securetest.adapters.builtin.TlsScanner;
import com.securetest.adapters.external.CheckovAdapter;
import com.securetest.adapters.external.JMeterAdapter;
import com.securetest.adapters.external.ProwlerAdapter;
import com.securetest.adapters.external.SonarQubeAdapter;
import com.securetest.adapters.external.TrivyAdapter;
import com.securetest.adapters.external.ZapAdapter;
import com.securetest.adapters.fix.DependencyUpgradeFix;
import com.securetest.adapters.fix.LineReplaceFix;
import com.securetest.autoconfigure.service.AuditService;
import com.securetest.autoconfigure.service.ChangeSetService;
import com.securetest.autoconfigure.service.ComplianceService;
import com.securetest.autoconfigure.service.ConfigPostureScanner;
import com.securetest.autoconfigure.service.FindingService;
import com.securetest.autoconfigure.service.JobService;
import com.securetest.autoconfigure.service.MigrationService;
import com.securetest.autoconfigure.service.ModuleService;
import com.securetest.autoconfigure.service.NotificationService;
import com.securetest.autoconfigure.service.PlatformServices.CompatibilityService;
import com.securetest.autoconfigure.service.PlatformServices.ControlPlaneClient;
import com.securetest.autoconfigure.service.PlatformServices.Housekeeping;
import com.securetest.autoconfigure.service.RemediationService;
import com.securetest.autoconfigure.service.ReportService;
import com.securetest.autoconfigure.service.ScannerRegistry;
import com.securetest.autoconfigure.service.TelemetryService;
import com.securetest.autoconfigure.service.WorkspaceServices.ProfileService;
import com.securetest.autoconfigure.service.WorkspaceServices.ScheduleService;
import com.securetest.autoconfigure.service.WorkspaceServices.TestManagementService;
import com.securetest.autoconfigure.support.AppContext;
import com.securetest.autoconfigure.support.Extensions.HealthSource;
import com.securetest.autoconfigure.support.Extensions.MeterSource;
import com.securetest.autoconfigure.support.LocalStore;
import com.securetest.autoconfigure.support.SecretResolver;
import com.securetest.autoconfigure.reactive.ReactiveWebConfiguration;
import com.securetest.autoconfigure.servlet.ServletWebConfiguration;
import com.securetest.autoconfigure.web.CoreApiController;
import com.securetest.autoconfigure.web.FindingApiController;
import com.securetest.autoconfigure.web.GovernanceApiController;
import com.securetest.autoconfigure.web.ScanApiController;
import com.securetest.autoconfigure.web.WorkspaceApiController;
import com.securetest.core.model.ModuleCatalog;
import com.securetest.core.spi.FixProvider;
import com.securetest.core.spi.Scanner;
import com.securetest.migration.ChangeSetEngine;
import com.securetest.migration.GitWorkspace;
import com.securetest.migration.MigrationEngine;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.info.BuildProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Conditional;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.core.Ordered;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.Environment;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;

/**
 * Entry point: everything SecureTest needs is registered here by conditional auto-configuration (FR-001, FR-003).
 * Adding the starter to any Spring Boot web application (Spring MVC or WebFlux) is enough to get the dashboard at
 * {@code /securetest}. Web-stack specifics live in {@link ServletWebConfiguration} and {@link ReactiveWebConfiguration}.
 */
@AutoConfiguration
@ConditionalOnWebApplication
@ConditionalOnProperty(prefix = "securetest", name = "enabled", havingValue = "true", matchIfMissing = true)
@Conditional(DashboardEnabledCondition.class)
@EnableConfigurationProperties(SecureTestProperties.class)
@Import({CoreApiController.class, ScanApiController.class, FindingApiController.class, GovernanceApiController.class,
        WorkspaceApiController.class, com.securetest.autoconfigure.web.FleetApiController.class, ServletWebConfiguration.class, ReactiveWebConfiguration.class, SecureTestAutoConfiguration.Scanners.class,
        SecureTestAutoConfiguration.ActuatorBridge.class, SecureTestAutoConfiguration.MicrometerBridge.class,
        SecureTestAutoConfiguration.MailBridgeConfig.class, SecureTestAutoConfiguration.SpringCloudDiscovery.class})
public class SecureTestAutoConfiguration {

    // ------------------------------------------------------------------ infrastructure

    @Bean
    SecretResolver secureTestSecretResolver(Environment env, ObjectProvider<SecretResolver.SecretManagerBridge> bridge) {
        return new SecretResolver(env, bridge.getIfAvailable());
    }

    @Bean
    AppContext secureTestAppContext(Environment env, SecureTestProperties props, ObjectProvider<BuildProperties> build) {
        BuildProperties b = build.getIfAvailable();
        return new AppContext(env, props, b != null ? b.getVersion() : env.getProperty("info.app.version", "unknown"));
    }

    @Bean(destroyMethod = "shutdown")
    LocalStore secureTestStore(SecureTestProperties props, Environment env) {
        String dir = props.getData().getStorageDir();
        if (dir == null || dir.isBlank()) {
            String app = env.getProperty("spring.application.name", "application").replaceAll("[^\\w.-]", "_");
            dir = Path.of(System.getProperty("user.home"), ".securetest", app).toString();
        }
        ObjectMapper mapper = new ObjectMapper().findAndRegisterModules()
                .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS)
                .disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);
        return new LocalStore(Path.of(dir), props.getData().isPersist(), mapper);
    }

    @Bean
    GitWorkspace secureTestGit(SecureTestProperties props) {
        return new GitWorkspace(props.getExecution().isGitEnabled());
    }

    @Bean
    AuditService secureTestAudit(LocalStore store) { return new AuditService(store); }

    @Bean
    com.securetest.autoconfigure.support.AppRole secureTestAppRole(SecureTestProperties props) {
        return com.securetest.autoconfigure.support.AppRole.resolve(props.getRole(),
                name -> org.springframework.util.ClassUtils.isPresent(name, SecureTestAutoConfiguration.class.getClassLoader()));
    }

    @Bean
    ModuleService secureTestModules(SecureTestProperties props, LocalStore store, com.securetest.autoconfigure.support.AppRole role) {
        return new ModuleService(props, store, role);
    }

    @Bean(destroyMethod = "shutdown")
    com.securetest.autoconfigure.fleet.FleetService secureTestFleet(SecureTestProperties props, AppContext app,
            com.securetest.autoconfigure.support.AppRole role, com.securetest.autoconfigure.service.StatusService status,
            TelemetryService telemetry, FindingService findings, SecretResolver secrets, Environment env,
            ObjectProvider<com.securetest.autoconfigure.fleet.FleetDiscovery> discovery) {
        return new com.securetest.autoconfigure.fleet.FleetService(props, app, role, status, telemetry, findings, secrets, env,
                discovery.orderedStream().toList(),
                name -> org.springframework.util.ClassUtils.isPresent(name, SecureTestAutoConfiguration.class.getClassLoader()));
    }

    @Bean
    com.securetest.autoconfigure.service.StatusService secureTestStatus(SecureTestProperties props, AppContext app, ModuleService modules,
                                                                      ScannerRegistry registry, JobService jobs, FindingService findings) {
        return new com.securetest.autoconfigure.service.StatusService(props, app, modules, registry, jobs, findings);
    }

    @Bean
    FindingService secureTestFindings(SecureTestProperties props, AppContext app, LocalStore store) { return new FindingService(props, app, store); }

    @Bean(destroyMethod = "shutdown")
    NotificationService secureTestNotifications(SecureTestProperties props, SecretResolver secrets, LocalStore store,
                                                ObjectProvider<com.securetest.autoconfigure.support.Extensions.MailBridge> mail) {
        if (props.getNotifications().getEmail().isEnabled() && mail.getIfAvailable() == null) {
            org.slf4j.LoggerFactory.getLogger("SecureTest").warn("SecureTest: e-mail notifications are enabled but no MailSender is configured (add spring-boot-starter-mail and spring.mail.*).");
        }
        return new NotificationService(props, secrets, store.mapper(), mail.getIfAvailable());
    }

    @Bean
    ScannerRegistry secureTestScannerRegistry(List<Scanner> scanners) { return new ScannerRegistry(scanners); }

    @Bean(destroyMethod = "shutdown")
    JobService secureTestJobs(SecureTestProperties props, ScannerRegistry registry, ModuleService modules, FindingService findings,
                              AuditService audit, NotificationService notifications, AppContext app, SecretResolver secrets,
                              LocalStore store, GitWorkspace git) {
        return new JobService(props, registry, modules, findings, audit, notifications, app, secrets, store, git);
    }

    @Bean
    ChangeSetService secureTestChangeSets(SecureTestProperties props, AppContext app, AuditService audit, LocalStore store, GitWorkspace git) {
        return new ChangeSetService(props, app, new ChangeSetEngine(store.subdir("changesets"), git), audit, store);
    }

    @Bean
    LineReplaceFix secureTestLineReplaceFix() { return new LineReplaceFix(); }

    @Bean
    DependencyUpgradeFix secureTestDependencyUpgradeFix() { return new DependencyUpgradeFix(); }

    @Bean
    com.securetest.ai.AiRemediator secureTestAiRemediator(SecureTestProperties props, SecretResolver secrets) {
        SecureTestProperties.Ai ai = props.getAi();
        com.securetest.ai.ModelClient client = null;
        if (ai.isEnabled() && ai.isDataProcessingApproved()) {
            String key = secrets.resolve(ai.getApiKeyRef());
            if (key == null || key.isBlank()) {
                org.slf4j.LoggerFactory.getLogger("SecureTest").warn("SecureTest: securetest.ai.enabled=true but the API key reference {} did not resolve; AI fixes stay off.", ai.getApiKeyRef());
            } else if ("anthropic".equalsIgnoreCase(ai.getProvider())) {
                client = new com.securetest.ai.ClaudeModelClient(key, ai.getBaseUrl(), ai.getModel(), ai.getEffort(), ai.isRefusalFallback());
            }
        }
        return new com.securetest.ai.AiRemediator(client, new com.securetest.ai.AiRemediator.Settings(
                ai.isEnabled() && client != null, ai.isDataProcessingApproved(), Math.max(5, Math.min(200, ai.getContextLines())), Math.max(1, ai.getDailyRequestLimit())));
    }

    @Bean
    RemediationService secureTestRemediation(FindingService findings, ChangeSetService changes, List<FixProvider> providers,
                                             com.securetest.ai.AiRemediator ai, AuditService audit) {
        return new RemediationService(findings, changes, providers, ai, audit);
    }

    @Bean
    MigrationService secureTestMigrations(ChangeSetService changes, AuditService audit, LocalStore store, GitWorkspace git) {
        return new MigrationService(new MigrationEngine(git), changes, audit, store);
    }

    @Bean
    ComplianceService secureTestCompliance(FindingService findings, JobService jobs, LocalStore store) {
        return new ComplianceService(findings, jobs, store);
    }

    @Bean(destroyMethod = "shutdown")
    ReportService secureTestReports(SecureTestProperties props, AppContext app, FindingService findings, JobService jobs,
                                    ComplianceService compliance, MigrationService migrations, ChangeSetService changes,
                                    ModuleService modules, AuditService audit, NotificationService notifications, LocalStore store) {
        return new ReportService(props, app, findings, jobs, compliance, migrations, changes, modules, audit, notifications, store);
    }

    @Bean(destroyMethod = "shutdown")
    TelemetryService secureTestTelemetry(SecureTestProperties props, ModuleService modules, NotificationService notifications,
                                         AuditService audit, ObjectProvider<HealthSource> health, ObjectProvider<MeterSource> meters) {
        return new TelemetryService(props, modules, notifications, audit, health.getIfAvailable(), meters.getIfAvailable());
    }

    @Bean
    ProfileService secureTestProfiles(LocalStore store, ScannerRegistry registry) { return new ProfileService(store, registry); }

    @Bean
    ScheduleService secureTestSchedules(LocalStore store, ScannerRegistry registry, ProfileService profiles, JobService jobs) {
        ScheduleService s = new ScheduleService(store, registry, profiles);
        s.bind(jobs);
        return s;
    }

    @Bean
    TestManagementService secureTestTestManagement(LocalStore store) { return new TestManagementService(store); }

    @Bean
    CompatibilityService secureTestCompatibility(SecureTestProperties props, AppContext app) { return new CompatibilityService(props, app); }

    @Bean(destroyMethod = "shutdown")
    ControlPlaneClient secureTestControlPlane(SecureTestProperties props, AppContext app, SecretResolver secrets, LocalStore store) {
        return new ControlPlaneClient(props, app, secrets, store.mapper());
    }

    @Bean(destroyMethod = "shutdown")
    Housekeeping secureTestHousekeeping(SecureTestProperties props, FindingService findings, JobService jobs, ReportService reports,
                                        AuditService audit, ScheduleService schedules) {
        return new Housekeeping(props, findings, jobs, reports, audit, schedules);
    }

    // ------------------------------------------------------------------ web

    @Bean
    com.securetest.autoconfigure.security.InitialAdminCredential secureTestInitialAdmin(LocalStore store) {
        return new com.securetest.autoconfigure.security.InitialAdminCredential(store.dir());
    }

    @Bean
    com.securetest.autoconfigure.security.DashboardGate secureTestDashboardGate(SecureTestProperties props, SecretResolver secrets, AuditService audit,
                                                                               com.securetest.autoconfigure.security.InitialAdminCredential initialAdmin, AppContext app) {
        var auth = props.getDashboard().getAuthentication();
        com.securetest.autoconfigure.security.OidcAuthenticator oidc = null;
        if ("oidc".equalsIgnoreCase(auth.getProvider())) {
            if (auth.getOidc().getIssuerUri() == null || auth.getOidc().getClientId() == null) {
                throw new IllegalStateException("securetest.dashboard.authentication.provider=oidc needs oidc.issuer-uri and oidc.client-id");
            }
            oidc = new com.securetest.autoconfigure.security.OidcAuthenticator(auth.getOidc(), auth.getRoleMapping(), secrets);
        }
        return new com.securetest.autoconfigure.security.DashboardGate(props, secrets, oidc, audit, initialAdmin, app::productionLike);
    }

    @Bean
    SecureTestLifecycle secureTestLifecycle(SecureTestProperties props, AppContext app, ControlPlaneClient controlPlane,
                                            ScannerRegistry registry, ModuleService modules,
                                            com.securetest.autoconfigure.security.DashboardGate gate,
                                            com.securetest.autoconfigure.security.InitialAdminCredential initialAdmin) {
        return new SecureTestLifecycle(props, app, controlPlane, registry, modules, gate, initialAdmin);
    }

    // ------------------------------------------------------------------ scanners (ports & adapters)

    @Configuration(proxyBeanMethods = false)
    static class Scanners {
        @Bean StaticAnalysisScanner secureTestStaticAnalysis() { return new StaticAnalysisScanner(); }
        @Bean SonarQubeAdapter secureTestSonar() { return new SonarQubeAdapter(); }
        @Bean DependencyScanner secureTestDependencies() { return new DependencyScanner(); }
        @Bean SecretsScanner secureTestSecrets() { return new SecretsScanner(); }
        @Bean TrivyAdapter secureTestTrivy() { return new TrivyAdapter(); }
        @Bean TestResultsScanner secureTestTestResults() { return new TestResultsScanner(); }
        @Bean TestRunnerScanner secureTestTestRunner() { return new TestRunnerScanner(); }
        @Bean ApiContractScanner secureTestApiContract() { return new ApiContractScanner(); }
        @Bean HttpSecurityScanner secureTestHttpSecurity() { return new HttpSecurityScanner(); }
        @Bean ActiveProbeScanner secureTestActiveProbe() { return new ActiveProbeScanner(); }
        @Bean ZapAdapter secureTestZap() { return new ZapAdapter(); }
        @Bean LoadTestScanner secureTestLoadTest() { return new LoadTestScanner(); }
        @Bean JMeterAdapter secureTestJMeter() { return new JMeterAdapter(); }
        @Bean TlsScanner secureTestTls() { return new TlsScanner(); }
        @Bean com.securetest.adapters.external.PlaywrightAdapter secureTestPlaywright() { return new com.securetest.adapters.external.PlaywrightAdapter(); }
        @Bean PortScanner secureTestPorts() { return new PortScanner(); }
        @Bean IacScanner secureTestIac() { return new IacScanner(); }
        @Bean CheckovAdapter secureTestCheckov() { return new CheckovAdapter(); }
        @Bean ProwlerAdapter secureTestProwler() { return new ProwlerAdapter(); }
        @Bean TrivyAdapter secureTestTrivyImage() { return new TrivyAdapter(ModuleCatalog.CLOUD_SECURITY, "trivy-image"); }
        @Bean RuntimeAlertScanner secureTestRuntimeAlerts() { return new RuntimeAlertScanner(); }

        @Bean
        ConfigPostureScanner secureTestConfigPosture(ConfigurableEnvironment env, SecureTestProperties props) {
            return new ConfigPostureScanner(env, props);
        }
    }

    // ------------------------------------------------------------------ optional bridges

    @Configuration(proxyBeanMethods = false)
    @ConditionalOnClass(name = "org.springframework.boot.actuate.health.HealthEndpoint")
    static class ActuatorBridge {
        @Bean
        HealthSource secureTestActuatorHealth(ObjectProvider<org.springframework.boot.actuate.health.HealthEndpoint> endpoint) {
            return () -> {
                var ep = endpoint.getIfAvailable();
                if (ep == null) return Map.of("status", "UP", "detail", "Application responding; Actuator health endpoint not enabled");
                var h = ep.health();
                Map<String, Object> m = new java.util.LinkedHashMap<>();
                m.put("status", h.getStatus().getCode());
                if (h instanceof org.springframework.boot.actuate.health.CompositeHealth c) {
                    Map<String, String> comps = new java.util.LinkedHashMap<>();
                    c.getComponents().forEach((k, v) -> comps.put(k, v.getStatus().getCode()));
                    m.put("components", comps);
                }
                return m;
            };
        }
    }

    @Configuration(proxyBeanMethods = false)
    @ConditionalOnClass(name = "org.springframework.mail.MailSender")
    static class MailBridgeConfig {
        @Bean
        com.securetest.autoconfigure.support.Extensions.MailBridge secureTestMailBridge(ObjectProvider<org.springframework.mail.MailSender> sender) {
            return (from, to, subject, body) -> {
                org.springframework.mail.MailSender s = sender.getIfAvailable();
                if (s == null) throw new IllegalStateException("No MailSender bean (configure spring.mail.host)");
                org.springframework.mail.SimpleMailMessage m = new org.springframework.mail.SimpleMailMessage();
                m.setFrom(from);
                m.setTo(to.toArray(String[]::new));
                m.setSubject(subject);
                m.setText(body);
                s.send(m);
            };
        }
    }

    @Configuration(proxyBeanMethods = false)
    @ConditionalOnClass(name = "io.micrometer.core.instrument.MeterRegistry")
    static class MicrometerBridge {
        @Bean
        MeterSource secureTestMicrometer(ObjectProvider<io.micrometer.core.instrument.MeterRegistry> registry) {
            return new MeterSource() {
                @Override
                public List<Map<String, Object>> customMeters() {
                    var r = registry.getIfAvailable();
                    if (r == null) return List.of();
                    List<String> std = List.of("jvm.", "process.", "system.", "http.", "tomcat.", "executor.", "disk.", "application.",
                            "logback.", "hikaricp.", "jdbc.", "spring.", "tasks.", "cache.");
                    return r.getMeters().stream().filter(m -> std.stream().noneMatch(p -> m.getId().getName().startsWith(p))).limit(100).map(m -> {
                        Map<String, Object> o = new java.util.LinkedHashMap<>();
                        o.put("name", m.getId().getName());
                        o.put("type", m.getId().getType().name());
                        o.put("tags", m.getId().getTags().stream().map(t -> t.getKey() + "=" + t.getValue()).toList());
                        Map<String, Double> values = new java.util.LinkedHashMap<>();
                        m.measure().forEach(ms -> values.put(ms.getStatistic().name(), ms.getValue()));
                        o.put("values", values);
                        return o;
                    }).toList();
                }

                @Override
                public Map<String, Object> httpServerRequests() {
                    var r = registry.getIfAvailable();
                    if (r == null) return Map.of();
                    long count = 0;
                    long errors = 0;
                    double totalMs = 0;
                    double maxMs = 0;
                    for (var t : r.find("http.server.requests").timers()) {
                        count += t.count();
                        totalMs += t.totalTime(java.util.concurrent.TimeUnit.MILLISECONDS);
                        maxMs = Math.max(maxMs, t.max(java.util.concurrent.TimeUnit.MILLISECONDS));
                        if ("SERVER_ERROR".equals(t.getId().getTag("outcome"))) errors += t.count();
                    }
                    return Map.of("count", count, "errors", errors, "meanMs", count == 0 ? 0 : Math.round(totalMs / count * 10) / 10.0, "maxMs", maxMs);
                }
            };
        }
    }

    /** Spring Cloud service discovery (Eureka, Consul, Kubernetes...) for the "All services" view; only when the app has Spring Cloud. */
    @Configuration(proxyBeanMethods = false)
    @ConditionalOnClass(name = "org.springframework.cloud.client.discovery.DiscoveryClient")
    static class SpringCloudDiscovery {

        @Bean
        com.securetest.autoconfigure.fleet.FleetDiscovery secureTestSpringCloudDiscovery(
                ObjectProvider<org.springframework.cloud.client.discovery.DiscoveryClient> client) {
            return new com.securetest.autoconfigure.fleet.FleetDiscovery() {
                private com.securetest.autoconfigure.fleet.SpringCloudFleetDiscovery delegate() {
                    org.springframework.cloud.client.discovery.DiscoveryClient c = client.getIfAvailable();
                    return c == null ? null : new com.securetest.autoconfigure.fleet.SpringCloudFleetDiscovery(c);
                }

                @Override
                public String description() {
                    var d = delegate();
                    return d == null ? "Spring Cloud service discovery (no client)" : d.description();
                }

                @Override
                public java.util.List<Instance> instances() {
                    var d = delegate();
                    return d == null ? java.util.List.of() : d.instances();
                }
            };
        }
    }
}
