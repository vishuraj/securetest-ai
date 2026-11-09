package com.securetest.autoconfigure.service;

import com.securetest.autoconfigure.SecureTestProperties;
import com.securetest.core.model.Enums.Confidence;
import com.securetest.core.model.Finding;
import com.securetest.core.model.ModuleCatalog;
import com.securetest.core.model.Severity;
import com.securetest.core.spi.ScanContext;
import com.securetest.core.spi.Scanner;
import com.securetest.core.spi.ScannerDescriptor;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.EnumerablePropertySource;
import org.springframework.core.env.PropertySource;
import org.springframework.util.ClassUtils;

import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * In-process configuration posture check (compliance module): reads the effective Spring configuration and
 * flags insecure settings. Only property NAMES and non-secret values are reported, never secret values.
 */
public class ConfigPostureScanner implements Scanner {

    public static final String ID = "config-posture";

    private final ConfigurableEnvironment env;
    private final SecureTestProperties props;

    public ConfigPostureScanner(ConfigurableEnvironment env, SecureTestProperties props) {
        this.env = env;
        this.props = props;
    }

    @Override
    public ScannerDescriptor descriptor() {
        return ScannerDescriptor.builder(ID, ModuleCatalog.COMPLIANCE, "Configuration posture")
                .purpose("Inspects the running application's effective configuration: Actuator exposure, error details, H2 console, "
                        + "session cookie flags, devtools, debug logging, plain-text secrets in config files and SecureTest's own exposure.")
                .access("Reads Spring Environment property names/values in memory. Secret values are never displayed.")
                .duration("< 1 second")
                .build();
    }

    @Override
    public void scan(ScanContext ctx) {
        String exposure = env.getProperty("management.endpoints.web.exposure.include", "health");
        List<String> exposed = Arrays.stream(exposure.split(",")).map(String::trim).toList();
        if (exposed.contains("*")) {
            report(ctx, "CFG-ACTUATOR-ALL", "All Actuator endpoints are exposed over HTTP", Severity.HIGH,
                    "management.endpoints.web.exposure.include=* exposes env, heapdump, configprops, loggers and more.",
                    "Expose only what is needed, e.g. management.endpoints.web.exposure.include=health,info,prometheus, and secure the rest.",
                    "management.endpoints.web.exposure.include=" + exposure, "OWASP-A05", "ASVS-14.3", "CIS-APP-HARDENING", "PCI-2.2");
        } else {
            for (String sensitive : List.of("env", "heapdump", "configprops", "threaddump", "loggers", "shutdown", "jolokia")) {
                if (exposed.contains(sensitive)) {
                    report(ctx, "CFG-ACTUATOR-" + sensitive.toUpperCase(Locale.ROOT), "Sensitive Actuator endpoint '" + sensitive + "' is exposed",
                            sensitive.equals("heapdump") || sensitive.equals("env") || sensitive.equals("shutdown") ? Severity.HIGH : Severity.MEDIUM,
                            "This endpoint reveals internals or allows runtime changes.", "Remove it from the web exposure list or protect it with authentication.",
                            "management.endpoints.web.exposure.include=" + exposure, "OWASP-A05", "ASVS-14.3");
                }
            }
        }
        if ("always".equalsIgnoreCase(env.getProperty("management.endpoint.health.show-details"))) {
            report(ctx, "CFG-HEALTH-DETAILS", "Health endpoint shows details to everyone", Severity.LOW,
                    "Component details (database, disk, versions) are visible without authentication.", "Use show-details=when-authorized.",
                    "management.endpoint.health.show-details=always", "OWASP-A05");
        }
        if ("always".equalsIgnoreCase(env.getProperty("server.error.include-stacktrace"))) {
            report(ctx, "CFG-STACKTRACE", "Stack traces are included in error responses", Severity.MEDIUM,
                    "Error pages leak class names, library versions and code paths.", "Set server.error.include-stacktrace=never.",
                    "server.error.include-stacktrace=always", "OWASP-A05", "ASVS-7.4", "CWE-209");
        }
        if ("always".equalsIgnoreCase(env.getProperty("server.error.include-message"))) {
            report(ctx, "CFG-ERROR-MESSAGE", "Exception messages are included in error responses", Severity.LOW,
                    "Exception messages may contain internal data.", "Set server.error.include-message=never.", "server.error.include-message=always", "OWASP-A05");
        }
        if (env.getProperty("spring.h2.console.enabled", Boolean.class, false)) {
            report(ctx, "CFG-H2-CONSOLE", "H2 web console is enabled", Severity.HIGH,
                    "The H2 console allows arbitrary SQL and, in some versions, code execution.", "Disable spring.h2.console.enabled outside local development.",
                    "spring.h2.console.enabled=true", "OWASP-A05", "CIS-APP-HARDENING");
        }
        if (Boolean.FALSE.equals(env.getProperty("server.servlet.session.cookie.http-only", Boolean.class))) {
            report(ctx, "CFG-COOKIE-HTTPONLY", "Session cookie HttpOnly disabled", Severity.MEDIUM, "Scripts can read the session cookie.",
                    "Remove server.servlet.session.cookie.http-only=false.", "server.servlet.session.cookie.http-only=false", "OWASP-A05", "ASVS-3.4");
        }
        boolean ssl = env.getProperty("server.ssl.enabled", Boolean.class, false);
        if (!Boolean.TRUE.equals(env.getProperty("server.servlet.session.cookie.secure", Boolean.class)) && ctx.application().activeProfiles().stream().anyMatch(p -> p.startsWith("prod"))) {
            report(ctx, "CFG-COOKIE-SECURE", "Session cookie Secure flag not enforced in production", Severity.MEDIUM,
                    "Cookies may be sent over plain HTTP.", "Set server.servlet.session.cookie.secure=true (and terminate TLS).",
                    "server.servlet.session.cookie.secure unset", "OWASP-A02", "ASVS-3.4", "PCI-4.2");
        }
        if (!ssl && ctx.application().activeProfiles().stream().anyMatch(p -> p.startsWith("prod"))
                && env.getProperty("server.forward-headers-strategy") == null) {
            report(ctx, "CFG-TLS", "No TLS termination detected for production profile", Severity.INFO,
                    "Neither server.ssl nor forwarded headers are configured. TLS may be terminated by a proxy; verify.",
                    "Terminate TLS at the app (server.ssl.*) or at a proxy and set server.forward-headers-strategy=native.",
                    "server.ssl.enabled=false", "PCI-4.2", "ASVS-9.1");
        }
        if (ClassUtils.isPresent("org.springframework.boot.devtools.RemoteSpringApplication", getClass().getClassLoader())) {
            report(ctx, "CFG-DEVTOOLS", "spring-boot-devtools is on the runtime classpath", Severity.MEDIUM,
                    "Devtools enables restart/remote features meant only for development.", "Declare devtools as optional / developmentOnly so it is excluded from packaged apps.",
                    "org.springframework.boot:spring-boot-devtools", "OWASP-A05", "CIS-APP-HARDENING");
        }
        if (env.getProperty("debug", Boolean.class, false) || "trace".equalsIgnoreCase(env.getProperty("logging.level.root"))
                || "debug".equalsIgnoreCase(env.getProperty("logging.level.root"))) {
            report(ctx, "CFG-DEBUG-LOGGING", "Debug/trace logging enabled at root level", Severity.LOW,
                    "Verbose logs can contain personal data, tokens and SQL parameters.", "Use INFO at root and enable DEBUG only for specific packages temporarily.",
                    "logging.level.root / debug", "OWASP-A09", "GDPR-32", "PCI-3.3");
        }
        if (env.getProperty("spring.jpa.show-sql", Boolean.class, false)) {
            report(ctx, "CFG-SHOW-SQL", "SQL statements are printed to stdout", Severity.LOW,
                    "spring.jpa.show-sql bypasses the logging framework and may print personal data.", "Disable show-sql; use logger org.hibernate.SQL when needed.",
                    "spring.jpa.show-sql=true", "OWASP-A09", "GDPR-32");
        }
        if (!ClassUtils.isPresent("org.springframework.security.web.SecurityFilterChain", getClass().getClassLoader())) {
            Finding f = report(ctx, "CFG-NO-SECURITY", "No authentication framework detected", Severity.MEDIUM,
                    "Spring Security is not on the classpath. Unless authentication is enforced elsewhere (gateway), endpoints are public.",
                    "Add spring-boot-starter-security or confirm that an upstream gateway enforces authentication.", "spring-security absent",
                    "OWASP-A01", "OWASP-A07", "ASVS-4.1", "SOC2-CC6.1", "PCI-8.2");
            f.confidence = Confidence.LOW;
        }
        plainTextSecrets(ctx);
        // SecureTest's own exposure (SRS 9.1)
        SecureTestProperties.Dashboard d = props.getDashboard();
        boolean loopback = d.getBindAddress() == null || d.getBindAddress().startsWith("127.") || d.getBindAddress().equals("::1") || d.getBindAddress().equals("localhost");
        if (!loopback && (!d.getAuthentication().isEnabled() || "local-dev".equals(d.getAuthentication().getProvider()))) {
            report(ctx, "CFG-SECURETEST-EXPOSED", "SecureTest dashboard is network-exposed without real authentication", Severity.HIGH,
                    "The dashboard is an administration surface.", "Use basic or container authentication with TLS, or keep bind-address=127.0.0.1.",
                    "securetest.dashboard.bind-address=" + d.getBindAddress(), "OWASP-A01", "OWASP-A07");
        }
        if (!props.getSecurity().isEnforceTargetAllowlist()) {
            report(ctx, "CFG-SECURETEST-ALLOWLIST", "SecureTest target allowlist enforcement is disabled", Severity.MEDIUM,
                    "Scans can be pointed at arbitrary hosts.", "Set securetest.security.enforce-target-allowlist=true.",
                    "securetest.security.enforce-target-allowlist=false", "OWASP-A10");
        }
        ctx.putResult("actuatorExposure", exposed);
    }

    private void plainTextSecrets(ScanContext ctx) {
        Map<String, String> hits = new LinkedHashMap<>();
        for (PropertySource<?> ps : env.getPropertySources()) {
            String source = ps.getName();
            if (!(ps instanceof EnumerablePropertySource<?> eps) || !source.contains("application")) continue; // config files only
            for (String name : eps.getPropertyNames()) {
                String lower = name.toLowerCase(Locale.ROOT);
                if (!(lower.contains("password") || lower.contains("secret") || lower.endsWith("token") || lower.contains("api-key") || lower.contains("apikey"))) continue;
                if (lower.startsWith("securetest.")) continue;
                Object raw = eps.getProperty(name);
                String v = raw == null ? "" : raw.toString();
                if (v.isBlank() || v.startsWith("${") || v.contains("://") || v.startsWith("{cipher}")) continue;
                hits.putIfAbsent(name, source.replaceAll(".*\\[(.*)].*", "$1"));
            }
        }
        hits.forEach((name, file) -> report(ctx, "CFG-PLAINTEXT-SECRET", "Plain-text secret in configuration: " + name, Severity.HIGH,
                "The property '" + name + "' has a literal value in " + file + ". Anyone with access to the artifact or repository can read it.",
                "Replace with a placeholder such as ${DB_PASSWORD} resolved from the environment or a secret manager.",
                name + " (value hidden) in " + file, "OWASP-A07", "ASVS-2.10", "CIS-SECRETS", "PCI-8.3", "SOC2-CC6.1"));
    }

    private Finding report(ScanContext ctx, String rule, String title, Severity s, String desc, String fix, String evidence, String... tags) {
        Finding f = Finding.of(ModuleCatalog.COMPLIANCE, ID, rule, title, s).description(desc).remediation(fix).evidence(evidence)
                .asset(ctx.application().name()).category("Configuration").confidence(Confidence.HIGH).tags(tags);
        ctx.report(f);
        return f;
    }
}
