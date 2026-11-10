package com.securetest.autoconfigure.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.securetest.autoconfigure.SecureTestProperties;
import com.securetest.autoconfigure.support.AppContext;
import com.securetest.autoconfigure.support.SecretResolver;
import com.securetest.core.util.AllowlistCommandRunner;
import com.securetest.core.util.MavenVersion;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringBootVersion;
import org.springframework.core.SpringVersion;
import org.springframework.util.ClassUtils;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/** Compatibility diagnostics, control-plane registration and housekeeping. */
public final class PlatformServices {
    private PlatformServices() { }

    // =====================================================================================  compatibility (FR-007, SRS 14)

    public static class CompatibilityService {
        public record Check(String name, String level, String detail) { }

        private final SecureTestProperties props;
        private final AppContext app;

        public CompatibilityService(SecureTestProperties props, AppContext app) {
            this.props = props;
            this.app = app;
        }

        public List<Check> checks() {
            List<Check> out = new ArrayList<>();
            int java = Runtime.version().feature();
            out.add(new Check("Java runtime", java >= 17 ? "OK" : "ERROR", "Java " + System.getProperty("java.version") + " (requires 17+)"));
            String boot = SpringBootVersion.getVersion();
            String level;
            if (boot == null) level = "WARN";
            else if (MavenVersion.major(boot) == 3 || MavenVersion.major(boot) == 4 && MavenVersion.minor(boot) <= 1) level = "OK";
            else if (MavenVersion.major(boot) >= 4) level = "WARN";
            else level = "ERROR";
            out.add(new Check("Spring Boot", level, "Spring Boot " + boot + ("OK".equals(level) ? " (tested 3.0–4.1, Spring MVC and WebFlux)"
                    : "WARN".equals(level) ? " is newer than the tested 3.0–4.1 range; core features are expected to work"
                    : " is not supported: SecureTest needs Spring Boot 3.0+ (jakarta.*)")));
            out.add(new Check("Spring Framework", "OK", "Spring Framework " + SpringVersion.getVersion()));
            boolean servlet = ClassUtils.isPresent("jakarta.servlet.Servlet", null) && ClassUtils.isPresent("org.springframework.web.servlet.DispatcherServlet", null);
            out.add(new Check("Web stack", "OK", servlet ? "Spring MVC (jakarta.servlet)" : "Spring WebFlux (reactive)"));
            out.add(new Check("Actuator", ClassUtils.isPresent("org.springframework.boot.actuate.health.HealthEndpoint", null) ? "OK" : "INFO",
                    ClassUtils.isPresent("org.springframework.boot.actuate.health.HealthEndpoint", null) ? "Health indicators bridged (status only)"
                            : "Not present: JVM metrics only. Add spring-boot-starter-actuator for health indicators."));
            out.add(new Check("Micrometer", ClassUtils.isPresent("io.micrometer.core.instrument.MeterRegistry", null) ? "OK" : "INFO",
                    ClassUtils.isPresent("io.micrometer.core.instrument.MeterRegistry", null) ? "Custom meters visible" : "Not present"));
            out.add(new Check("Source workspace", app.sourceRoot().isPresent() ? "OK" : "WARN",
                    app.sourceRoot().map(Object::toString).orElse("Not configured: source-based modules (code quality, secrets, IaC, migration) are unavailable")));
            var auth = props.getDashboard().getAuthentication();
            boolean open = !auth.isEnabled() && !"127.0.0.1".equals(props.getDashboard().getBindAddress());
            out.add(new Check("Dashboard access", open ? "WARN" : "OK",
                    "bind-address=" + props.getDashboard().getBindAddress() + ", authentication=" + (auth.isEnabled() ? auth.getProvider() : "disabled")
                            + (open ? " (authentication disabled: only same-machine, non-production requests are served)" : "")));
            if (app.productionLike()) out.add(new Check("Production profile", "WARN", "Production-like profile active: source changes are disabled; keep the dashboard protected."));
            return out;
        }

        public Map<String, Object> tools() {
            AllowlistCommandRunner runner = new AllowlistCommandRunner(new HashSet<>(props.getExecution().getAllowedCommands()));
            Map<String, Object> m = new LinkedHashMap<>();
            for (String tool : List.of("git", "trivy", "checkov", "prowler", "jmeter", "mvn", "gradle")) {
                m.put(tool, Map.of("installed", runner.locate(tool).isPresent(), "allowlisted", runner.isAllowed(tool) || tool.equals("git")));
            }
            return m;
        }
    }

    // =====================================================================================  control plane (connected mode)

    /** Registers this application with an enterprise control plane. Never blocks startup (FR-008). */
    public static class ControlPlaneClient {
        private static final Logger log = LoggerFactory.getLogger(ControlPlaneClient.class);

        private final SecureTestProperties props;
        private final AppContext app;
        private final SecretResolver secrets;
        private final ObjectMapper mapper;
        private final ScheduledExecutorService exec = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "securetest-control-plane");
            t.setDaemon(true);
            return t;
        });
        private final Map<String, Object> status = new LinkedHashMap<>();

        public ControlPlaneClient(SecureTestProperties props, AppContext app, SecretResolver secrets, ObjectMapper mapper) {
            this.props = props;
            this.app = app;
            this.secrets = secrets;
            this.mapper = mapper;
            status.put("enabled", props.getControlPlane().isEnabled());
        }

        public void start(List<String> capabilities) {
            if (!props.getControlPlane().isEnabled() || props.getControlPlane().getUrl() == null) return;
            long period = Math.max(15, props.getControlPlane().getHeartbeat().toSeconds());
            exec.scheduleWithFixedDelay(() -> register(capabilities), 5, period, TimeUnit.SECONDS);
        }

        private void register(List<String> capabilities) {
            synchronized (status) {
                status.put("lastAttempt", Instant.now().toString());
            }
            try {
                String token = secrets.resolve(props.getControlPlane().getEnrollmentTokenRef());
                var info = app.info();
                Map<String, Object> body = new LinkedHashMap<>();
                body.put("serviceId", info.serviceId());
                body.put("application", info.name());
                body.put("environment", info.environment());
                body.put("version", info.version());
                body.put("runtime", Map.of("java", info.javaVersion(), "springBoot", info.springBootVersion()));
                body.put("agentVersion", "1.0.0");
                body.put("capabilities", capabilities);
                HttpRequest.Builder rb = HttpRequest.newBuilder(URI.create(props.getControlPlane().getUrl().replaceAll("/$", "") + "/api/v1/agents/register"))
                        .timeout(Duration.ofSeconds(10)).header("Content-Type", "application/json")
                        .POST(HttpRequest.BodyPublishers.ofString(mapper.writeValueAsString(body)));
                if (token != null) rb.header("Authorization", "Bearer " + token);
                HttpResponse<String> r = HttpClient.newBuilder().connectTimeout(props.getExecution().getConnectTimeout()).build()
                        .send(rb.build(), HttpResponse.BodyHandlers.ofString());
                synchronized (status) {
                    status.put("lastStatus", r.statusCode());
                    if (r.statusCode() < 300) {
                        status.put("registered", true);
                        status.put("lastSuccess", Instant.now().toString());
                        status.remove("error");
                    } else {
                        status.put("error", "HTTP " + r.statusCode());
                    }
                }
            } catch (Exception e) {
                synchronized (status) {
                    status.put("error", e.getClass().getSimpleName() + ": " + e.getMessage());
                }
                log.debug("SecureTest control plane unavailable: {}", e.getMessage());
            }
        }

        public Map<String, Object> status() {
            synchronized (status) {
                Map<String, Object> m = new LinkedHashMap<>(status);
                m.put("url", props.getControlPlane().getUrl());
                m.put("mode", props.getMode());
                return m;
            }
        }

        public void shutdown() { exec.shutdownNow(); }
    }

    // =====================================================================================  housekeeping (retention, schedules)

    public static class Housekeeping {
        private static final Logger log = LoggerFactory.getLogger(Housekeeping.class);
        private final ScheduledExecutorService exec = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "securetest-housekeeping");
            t.setDaemon(true);
            t.setPriority(Thread.MIN_PRIORITY);
            return t;
        });

        public Housekeeping(SecureTestProperties props, FindingService findings, JobService jobs, ReportService reports, AuditService audit,
                            WorkspaceServices.ScheduleService schedules) {
            var r = props.getData().getRetention();
            exec.scheduleWithFixedDelay(schedules::tick, 30, 30, TimeUnit.SECONDS);
            exec.scheduleWithFixedDelay(() -> {
                try {
                    int f = findings.housekeeping(r.getFindings());
                    int j = jobs.housekeeping(r.getJobs());
                    int rep = reports.housekeeping(r.getReports());
                    int a = audit.purgeOlderThan(r.getAudit());
                    if (f + j + rep + a > 0) {
                        audit.record("system", null, "retention.purge", "data", "OK",
                                Map.of("findings", String.valueOf(f), "jobs", String.valueOf(j), "reports", String.valueOf(rep), "auditInMemory", String.valueOf(a)));
                    }
                } catch (RuntimeException e) {
                    log.warn("SecureTest housekeeping failed: {}", e.getMessage());
                }
            }, 1, 60, TimeUnit.MINUTES);
        }

        public void shutdown() { exec.shutdownNow(); }
    }
}
