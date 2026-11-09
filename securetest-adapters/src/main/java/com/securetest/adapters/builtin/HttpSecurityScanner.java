package com.securetest.adapters.builtin;

import com.securetest.adapters.support.ScanSupport;
import com.securetest.core.model.Enums.Confidence;
import com.securetest.core.model.Enums.FieldType;
import com.securetest.core.model.Finding;
import com.securetest.core.model.ModuleCatalog;
import com.securetest.core.model.Severity;
import com.securetest.core.spi.FieldSpec;
import com.securetest.core.spi.HttpProbe.HttpResult;
import com.securetest.core.spi.PreflightCheck;
import com.securetest.core.spi.ScanContext;
import com.securetest.core.spi.Scanner;
import com.securetest.core.spi.ScannerDescriptor;
import com.securetest.core.util.Redactor;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;

/**
 * Passive web/API posture checks (SRS 5.7): security headers, cookies, CORS, information disclosure,
 * exposed management/documentation endpoints and error handling. Sends only ordinary GET/OPTIONS requests.
 */
public class HttpSecurityScanner implements Scanner {

    public static final String ID = "builtin-http-security";

    private record Exposure(String path, Severity severity, String title, String marker, String tag) { }

    private static final List<Exposure> EXPOSURES = List.of(
            new Exposure("/actuator/env", Severity.CRITICAL, "Actuator /env exposes configuration and secrets", "propertySources", "OWASP-A05"),
            new Exposure("/actuator/heapdump", Severity.CRITICAL, "Actuator heap dump is downloadable", null, "OWASP-A05"),
            new Exposure("/actuator/configprops", Severity.HIGH, "Actuator /configprops exposes configuration", "contexts", "OWASP-A05"),
            new Exposure("/actuator/threaddump", Severity.MEDIUM, "Actuator thread dump is exposed", "threads", "OWASP-A05"),
            new Exposure("/actuator/loggers", Severity.MEDIUM, "Actuator /loggers is exposed (log levels can be changed)", "levels", "OWASP-A05"),
            new Exposure("/actuator/mappings", Severity.LOW, "Actuator /mappings reveals all routes", "contexts", "OWASP-A05"),
            new Exposure("/actuator/beans", Severity.LOW, "Actuator /beans reveals internal structure", "contexts", "OWASP-A05"),
            new Exposure("/jolokia", Severity.HIGH, "Jolokia JMX bridge is exposed", "agent", "OWASP-A05"),
            new Exposure("/h2-console", Severity.HIGH, "H2 database console is reachable", "H2", "OWASP-A05"),
            new Exposure("/.git/config", Severity.CRITICAL, "Git repository metadata is served", "[core]", "OWASP-A05"),
            new Exposure("/.env", Severity.CRITICAL, ".env file is served", "=", "OWASP-A05"),
            new Exposure("/server-status", Severity.MEDIUM, "Server status page is exposed", "Server", "OWASP-A05"),
            new Exposure("/v3/api-docs", Severity.INFO, "OpenAPI definition is publicly reachable", "openapi", "OWASP-API9"),
            new Exposure("/swagger-ui/index.html", Severity.INFO, "Swagger UI is publicly reachable", "swagger", "OWASP-API9")
    );

    @Override
    public ScannerDescriptor descriptor() {
        return ScannerDescriptor.builder(ID, ModuleCatalog.API_SECURITY, "Passive web & API security checks")
                .purpose("Checks security headers, cookie flags, CORS policy, version disclosure, exposed Actuator/debug/documentation "
                        + "endpoints and error-page information leakage. Passive: ordinary GET/OPTIONS requests only.")
                .access("HTTP requests to the allowlisted target (about 25 requests).")
                .requiresTarget()
                .field(FieldSpec.required("baseUrl", "Target base URL", FieldType.URL, "self", "'self' = this application."))
                .field(FieldSpec.optional("paths", "Pages to inspect", FieldType.LIST, "/", "Comma-separated paths whose headers are checked."))
                .field(FieldSpec.flag("checkExposures", "Probe well-known sensitive paths", true, "Actuator, .git, .env, H2 console, Swagger…"))
                .field(FieldSpec.number("rate", "Requests per second", 5, 1, 20, ""))
                .build();
    }

    @Override
    public List<PreflightCheck> preflight(ScanContext ctx) {
        List<PreflightCheck> out = new ArrayList<>();
        try {
            String base = base(ctx);
            ctx.targets().requireAllowedUrl(base);
            out.add(PreflightCheck.ok("Target allowlist", base + " is authorized"));
            HttpResult r = ctx.http().get(base + "/");
            out.add(PreflightCheck.ok("Connectivity", "HTTP " + r.status() + " in " + r.durationMs() + " ms"));
        } catch (Exception e) {
            out.add(PreflightCheck.error("Connectivity", e.getMessage()));
        }
        return out;
    }

    static String base(ScanContext ctx) {
        String b = ctx.option("baseUrl", "self");
        if (b.equalsIgnoreCase("self")) b = ctx.targets().selfBaseUrl();
        return b.endsWith("/") ? b.substring(0, b.length() - 1) : b;
    }

    @Override
    public void scan(ScanContext ctx) throws Exception {
        String base = base(ctx);
        boolean https = base.toLowerCase(Locale.ROOT).startsWith("https");
        List<String> paths = List.of(ctx.option("paths", "/").split(","));
        int step = 0;
        for (String raw : paths) {
            ctx.checkCancelled();
            String path = raw.trim().isEmpty() ? "/" : raw.trim();
            String url = base + (path.startsWith("/") ? path : "/" + path);
            HttpResult r = ctx.http().get(url, Map.of("Accept", "text/html,application/json"));
            headers(ctx, url, r, https);
            cookies(ctx, url, r, https);
            cors(ctx, url);
            ctx.progress(10 + 30 * ++step / paths.size(), "Checked " + url);
        }
        // HTTP methods
        HttpResult opt = ctx.http().send("OPTIONS", base + "/", Map.of(), null);
        String allow = opt.header("Allow");
        if (allow != null && allow.toUpperCase(Locale.ROOT).contains("TRACE")) {
            ctx.report(base(Finding.of(ModuleCatalog.API_SECURITY, ID, "HTTP-TRACE", "HTTP TRACE method advertised", Severity.LOW), base)
                    .description("TRACE can be abused for cross-site tracing.").evidence("OPTIONS / -> Allow: " + allow)
                    .remediation("Disable TRACE on the server/proxy.").tags("OWASP-A05", "CWE-693"));
        }
        // error handling
        String probe = base + "/securetest-probe-" + UUID.randomUUID().toString().substring(0, 8) + "?q=%27%22";
        HttpResult err = ctx.http().get(probe, Map.of("Accept", "text/html"));
        String body = err.body();
        if (body.contains("at org.springframework") || body.contains("at java.") || body.contains("Exception:") && body.contains("\tat ")) {
            ctx.report(base(Finding.of(ModuleCatalog.API_SECURITY, ID, "INFO-STACKTRACE", "Stack trace disclosed in error response", Severity.MEDIUM), probe)
                    .description("Error responses include Java stack traces, revealing frameworks, versions and internal structure.")
                    .evidence(Redactor.redact(ScanSupport.truncate(body, 1500)))
                    .remediation("Set server.error.include-stacktrace=never and server.error.include-message=never; use a generic error handler.")
                    .tags("OWASP-A05", "ASVS-7.4", "CWE-209"));
        } else if (body.contains("Whitelabel Error Page")) {
            ctx.report(base(Finding.of(ModuleCatalog.API_SECURITY, ID, "INFO-WHITELABEL", "Default Whitelabel error page reveals Spring Boot", Severity.INFO), probe)
                    .description("The default error page fingerprints the framework.").remediation("Provide a custom error page/handler.")
                    .tags("OWASP-A05"));
        }
        ctx.progress(50, "Checking sensitive endpoints");
        if (ctx.boolOption("checkExposures", true)) {
            int i = 0;
            for (Exposure e : EXPOSURES) {
                ctx.checkCancelled();
                String url = base + e.path();
                HttpResult r = ctx.http().get(url);
                boolean exposed = r.status() == 200 && (e.marker() == null || r.body().contains(e.marker()));
                if (exposed) {
                    ctx.report(base(Finding.of(ModuleCatalog.API_SECURITY, ID, "EXPOSED" + e.path().replace('/', '-').toUpperCase(Locale.ROOT), e.title(), e.severity()), url)
                            .description("GET " + e.path() + " returned 200 without authentication.")
                            .evidence("GET " + url + " -> " + r.status() + " (" + r.body().length() + " bytes)")
                            .remediation(e.path().startsWith("/actuator")
                                    ? "Expose only health/info: management.endpoints.web.exposure.include=health,info, and protect the rest with Spring Security."
                                    : e.severity() == Severity.INFO ? "Confirm that public API documentation is intended in this environment; disable it in production (springdoc.api-docs.enabled=false)."
                                    : "Block this path at the server/proxy and remove the file or feature from the deployment.")
                            .exposure("internet").tags(e.tag(), "ASVS-14.3", "CIS-APP-HARDENING"));
                }
                ctx.progress(50 + 45 * ++i / EXPOSURES.size(), "Checked " + e.path());
            }
        }
    }

    private static Finding base(Finding f, String url) {
        return f.asset(url).category("Web security").confidence(Confidence.HIGH);
    }

    private static void headers(ScanContext ctx, String url, HttpResult r, boolean https) {
        record H(String name, Severity sev, String why, String fix, String tag) { }
        String csp = r.header("Content-Security-Policy");
        List<H> required = new ArrayList<>(List.of(
                new H("Content-Security-Policy", Severity.MEDIUM, "Without CSP, injected scripts run unrestricted (XSS impact).",
                        "Add a Content-Security-Policy, e.g. default-src 'self'; frame-ancestors 'none'.", "ASVS-14.4"),
                new H("X-Content-Type-Options", Severity.LOW, "Browsers may MIME-sniff responses into executable content.",
                        "Send X-Content-Type-Options: nosniff (Spring Security does this by default).", "ASVS-14.4"),
                new H("Referrer-Policy", Severity.LOW, "Full URLs (possibly with tokens) can leak to third parties via Referer.",
                        "Send Referrer-Policy: strict-origin-when-cross-origin or no-referrer.", "ASVS-14.4")));
        if (csp == null || !csp.contains("frame-ancestors")) {
            required.add(new H("X-Frame-Options", Severity.MEDIUM, "The page can be framed by other sites (clickjacking).",
                    "Send X-Frame-Options: DENY or CSP frame-ancestors 'none'.", "ASVS-14.4"));
        }
        if (https) {
            required.add(new H("Strict-Transport-Security", Severity.MEDIUM, "Browsers may be downgraded to HTTP by an attacker.",
                    "Send Strict-Transport-Security: max-age=31536000; includeSubDomains.", "PCI-4.2"));
        }
        for (H h : required) {
            if (r.header(h.name()) == null) {
                ctx.report(base(Finding.of(ModuleCatalog.API_SECURITY, ID, "HDR-" + h.name().toUpperCase(Locale.ROOT), "Missing " + h.name() + " header", h.sev()), url)
                        .description(h.why()).remediation(h.fix()).evidence("GET " + url + " -> " + r.status() + "; header absent")
                        .tags("OWASP-A05", h.tag(), "CWE-693"));
            }
        }
        for (String h : List.of("Server", "X-Powered-By", "X-AspNet-Version", "X-Application-Context")) {
            String v = r.header(h);
            if (v != null && v.matches(".*\\d.*")) {
                ctx.report(base(Finding.of(ModuleCatalog.API_SECURITY, ID, "HDR-DISCLOSURE-" + h.toUpperCase(Locale.ROOT), "Version disclosed in " + h + " header", Severity.LOW), url)
                        .description("Exact product versions help attackers select exploits.").evidence(h + ": " + v)
                        .remediation("Remove or genericize the header (e.g. server.server-header= for Tomcat).").tags("OWASP-A05", "CWE-200"));
            }
        }
    }

    private static void cookies(ScanContext ctx, String url, HttpResult r, boolean https) {
        for (String c : r.headerValues("Set-Cookie")) {
            String name = c.split("=", 2)[0].trim();
            String lc = c.toLowerCase(Locale.ROOT);
            List<String> missing = new ArrayList<>();
            if (!lc.contains("httponly")) missing.add("HttpOnly");
            if (https && !lc.contains("secure")) missing.add("Secure");
            if (!lc.contains("samesite")) missing.add("SameSite");
            if (!missing.isEmpty()) {
                ctx.report(base(Finding.of(ModuleCatalog.API_SECURITY, ID, "COOKIE-FLAGS", "Cookie '" + name + "' is missing " + String.join(", ", missing),
                        missing.contains("HttpOnly") || missing.contains("Secure") ? Severity.MEDIUM : Severity.LOW), url)
                        .description("Missing cookie attributes allow theft via XSS (HttpOnly), transmission over HTTP (Secure) or CSRF (SameSite).")
                        .evidence("Set-Cookie: " + Redactor.redact(name + "=" + Redactor.MASK + c.substring(c.indexOf(';') < 0 ? c.length() : c.indexOf(';'))))
                        .remediation("Configure server.servlet.session.cookie.http-only=true, secure=true and same-site=lax|strict.")
                        .tags("OWASP-A05", "ASVS-3.4", "PCI-6.2.4"));
            }
        }
    }

    private static void cors(ScanContext ctx, String url) throws Exception {
        String evil = "https://securetest-cors-check.invalid";
        HttpResult r = ctx.http().get(url, Map.of("Origin", evil));
        String acao = r.header("Access-Control-Allow-Origin");
        boolean creds = "true".equalsIgnoreCase(r.header("Access-Control-Allow-Credentials"));
        if (acao == null) return;
        Severity sev = null;
        String title = null;
        if (acao.equals(evil)) {
            sev = creds ? Severity.HIGH : Severity.MEDIUM;
            title = "CORS reflects arbitrary origins" + (creds ? " with credentials" : "");
        } else if (acao.equals("*")) {
            sev = creds ? Severity.HIGH : Severity.LOW;
            title = "CORS allows any origin (*)";
        } else if (acao.equals("null")) {
            sev = Severity.MEDIUM;
            title = "CORS allows the 'null' origin";
        }
        if (sev != null) {
            ctx.report(base(Finding.of(ModuleCatalog.API_SECURITY, ID, "CORS-PERMISSIVE", title, sev), url)
                    .description("Any website can read responses from this endpoint in a victim's browser" + (creds ? ", including authenticated data." : "."))
                    .evidence("Origin: " + evil + " -> Access-Control-Allow-Origin: " + acao + (creds ? ", Access-Control-Allow-Credentials: true" : ""))
                    .remediation("Allow only explicit trusted origins; never combine wildcard or reflected origins with credentials.")
                    .tags("OWASP-A05", "ASVS-14.5", "CWE-942"));
        }
    }
}
