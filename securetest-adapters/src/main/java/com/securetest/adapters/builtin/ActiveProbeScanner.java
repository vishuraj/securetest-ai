package com.securetest.adapters.builtin;

import com.securetest.adapters.support.ScanSupport;
import com.securetest.core.model.Enums.Confidence;
import com.securetest.core.model.Enums.FieldType;
import com.securetest.core.model.Enums.ScanMode;
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

import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Active, non-destructive DAST probes (SRS 5.7): SQL injection error signatures, reflected XSS,
 * path traversal, missing rate limiting and TRACE. Requires allowlist, confirmation and approval.
 * Only GET requests are sent; no state-changing methods are used.
 */
public class ActiveProbeScanner implements Scanner {

    public static final String ID = "builtin-active-probe";

    private static final Pattern SQL_ERRORS = Pattern.compile(
            "(SQLSyntaxErrorException|You have an error in your SQL syntax|syntax error at or near|unterminated quoted string|ORA-\\d{5}|"
                    + "SQLITE_ERROR|PSQLException|Microsoft OLE DB Provider for SQL Server|Unclosed quotation mark|JdbcSQLSyntaxErrorException|"
                    + "org\\.hibernate\\.QueryException|BadSqlGrammarException)", Pattern.CASE_INSENSITIVE);

    @Override
    public ScannerDescriptor descriptor() {
        return ScannerDescriptor.builder(ID, ModuleCatalog.API_SECURITY, "Active injection & abuse probes")
                .purpose("Sends crafted but non-destructive GET requests to the listed endpoints to detect SQL injection error signatures, "
                        + "reflected XSS, path traversal, missing rate limiting and TRACE support.")
                .access("Crafted HTTP GET requests to allowlisted targets only. Never sends POST/PUT/DELETE.")
                .mode(ScanMode.ACTIVE).requiresTarget()
                .duration("1–5 minutes").resources("Low on the scanner; generates unusual requests and log noise on the target")
                .prerequisite("Written authorization to test the target")
                .prerequisite("Approval by a user with APPROVE permission when securetest.security.require-approval-for-active-scans=true")
                .field(FieldSpec.required("baseUrl", "Target base URL", FieldType.URL, "self", "Must be on the target allowlist."))
                .field(FieldSpec.required("endpoints", "Endpoints with parameters", FieldType.TEXTAREA, "/api/items?id=1",
                        "One per line, with sample query parameters to fuzz, e.g. /api/users?name=alice"))
                .field(FieldSpec.secret("authorization", "Authorization header value", false, "Optional secret reference for authenticated testing."))
                .field(FieldSpec.optional("rateLimitPath", "Rate-limit check path", FieldType.TEXT, "", "Endpoint expected to throttle (e.g. /login). Empty = skip."))
                .field(FieldSpec.number("burst", "Rate-limit burst size", 30, 5, 100, "Requests sent quickly to the rate-limit path."))
                .field(FieldSpec.number("rate", "Requests per second (fuzzing)", 5, 1, 20, ""))
                .build();
    }

    @Override
    public List<PreflightCheck> preflight(ScanContext ctx) {
        List<PreflightCheck> out = new ArrayList<>();
        try {
            String base = HttpSecurityScanner.base(ctx);
            ctx.targets().requireAllowedUrl(base);
            out.add(PreflightCheck.ok("Target allowlist", base + " is authorized"));
            out.add(PreflightCheck.warn("Impact", "Active probes create error log entries and may trigger WAF/IDS alerts on the target."));
        } catch (Exception e) {
            out.add(PreflightCheck.error("Target allowlist", e.getMessage()));
        }
        return out;
    }

    @Override
    public void scan(ScanContext ctx) throws Exception {
        String base = HttpSecurityScanner.base(ctx);
        String auth = ctx.secret("authorization");
        Map<String, String> headers = new LinkedHashMap<>();
        if (auth != null && !auth.isBlank()) headers.put("Authorization", auth);
        List<String> endpoints = ctx.option("endpoints", "").lines().map(String::trim).filter(s -> !s.isEmpty()).limit(50).toList();
        int done = 0;
        for (String ep : endpoints) {
            ctx.checkCancelled();
            URI u = URI.create(base + (ep.startsWith("/") ? ep : "/" + ep));
            Map<String, String> params = query(u.getRawQuery());
            String path = base + u.getRawPath();
            HttpResult baseline = ctx.http().get(u.toString(), headers);
            for (String param : params.keySet()) {
                probe(ctx, path, params, param, "'\"", headers, baseline, "sqli");
                probe(ctx, path, params, param, "<stx" + (char) ('a' + done % 26) + "9>\"'", headers, baseline, "xss");
                probe(ctx, path, params, param, "../../../../../../etc/passwd", headers, baseline, "traversal");
            }
            ctx.progress(5 + 75 * ++done / Math.max(1, endpoints.size()), "Probed " + ep);
        }
        String rl = ctx.option("rateLimitPath", "");
        if (!rl.isBlank()) rateLimit(ctx, base + (rl.startsWith("/") ? rl : "/" + rl), ctx.intOption("burst", 30, 5, 100), headers);
        HttpResult trace = ctx.http().send("TRACE", base + "/", Map.of("X-SecureTest-Trace", "probe"), null);
        if (trace.status() == 200 && trace.body().contains("X-SecureTest-Trace")) {
            ctx.report(Finding.of(ModuleCatalog.API_SECURITY, ID, "ACTIVE-TRACE", "HTTP TRACE echoes request headers", Severity.LOW)
                    .description("TRACE echoes headers, enabling cross-site tracing in some setups.")
                    .evidence("TRACE / -> 200 with echoed header").remediation("Disable TRACE.").asset(base)
                    .category("Web security").confidence(Confidence.HIGH).tags("OWASP-A05"));
        }
    }

    private void probe(ScanContext ctx, String path, Map<String, String> params, String param, String payload,
                       Map<String, String> headers, HttpResult baseline, String kind) throws Exception {
        Map<String, String> p = new LinkedHashMap<>(params);
        p.put(param, payload);
        StringBuilder q = new StringBuilder();
        p.forEach((k, v) -> q.append(q.length() == 0 ? "?" : "&").append(k).append('=').append(URLEncoder.encode(v, StandardCharsets.UTF_8)));
        String url = path + q;
        HttpResult r = ctx.http().get(url, headers);
        String body = r.body();
        switch (kind) {
            case "sqli" -> {
                var m = SQL_ERRORS.matcher(body);
                if (m.find() && !SQL_ERRORS.matcher(baseline.body()).find()) {
                    ctx.report(f("ACTIVE-SQLI", "Possible SQL injection in parameter '" + param + "'", Severity.HIGH, url, r, m.group())
                            .description("A quote character in '" + param + "' produced a database error message, indicating the value reaches SQL unescaped.")
                            .remediation("Use parameterized queries / JPA bind parameters and never concatenate input into SQL. Do not return DB errors to clients.")
                            .tags("OWASP-A03", "ASVS-5.3", "PCI-6.2.4", "CWE-89"));
                }
            }
            case "xss" -> {
                String ct = r.header("Content-Type");
                if (ct != null && ct.toLowerCase(Locale.ROOT).contains("text/html") && body.contains(payload.substring(0, 7))
                        && body.contains(payload)) {
                    ctx.report(f("ACTIVE-XSS", "Reflected XSS in parameter '" + param + "'", Severity.MEDIUM, url, r, payload)
                            .description("Input from '" + param + "' is reflected into an HTML response without encoding.")
                            .remediation("Encode output contextually (Thymeleaf th:text, OWASP Java Encoder) and add a Content-Security-Policy.")
                            .tags("OWASP-A03", "ASVS-5.3", "CWE-79"));
                }
            }
            case "traversal" -> {
                if (body.contains("root:x:0:0") || body.contains("[boot loader]")) {
                    ctx.report(f("ACTIVE-TRAVERSAL", "Path traversal in parameter '" + param + "'", Severity.CRITICAL, url, r, "root:x:0:0")
                            .description("A ../ sequence in '" + param + "' returned the contents of a system file.")
                            .remediation("Resolve file names against a fixed directory, normalize and verify the result stays within it; prefer IDs over file names.")
                            .tags("OWASP-A01", "ASVS-12.3", "CWE-22"));
                }
            }
            default -> { }
        }
    }

    private void rateLimit(ScanContext ctx, String url, int burst, Map<String, String> headers) throws Exception {
        int throttled = 0;
        int ok = 0;
        for (int i = 0; i < burst; i++) {
            ctx.checkCancelled();
            HttpResult r = ctx.http().get(url, headers);
            if (r.status() == 429) throttled++;
            else if (r.status() < 500) ok++;
        }
        ctx.progress(95, "Rate-limit check: " + throttled + " throttled of " + burst);
        if (throttled == 0) {
            ctx.report(Finding.of(ModuleCatalog.API_SECURITY, ID, "ACTIVE-NO-RATELIMIT", "No rate limiting observed on " + URI.create(url).getPath(), Severity.LOW)
                    .description(burst + " rapid requests were all accepted (" + ok + " non-error responses); no HTTP 429 was returned.")
                    .remediation("Add rate limiting (gateway, Bucket4j, Resilience4j RateLimiter) for authentication and expensive endpoints.")
                    .evidence(burst + " requests at the configured pace, 0 × 429").asset(url).category("Abuse protection")
                    .confidence(Confidence.LOW).tags("OWASP-API4", "ASVS-11.1", "CWE-770"));
        }
    }

    private static Finding f(String rule, String title, Severity s, String url, HttpResult r, String marker) {
        return Finding.of(ModuleCatalog.API_SECURITY, ID, rule, title, s).asset(url).category("Injection").confidence(Confidence.MEDIUM)
                .evidence("GET " + url + " -> " + r.status() + "\nMatched: " + marker + "\n---\n"
                        + Redactor.redact(ScanSupport.truncate(r.body(), 1200)));
    }

    private static Map<String, String> query(String raw) {
        Map<String, String> m = new LinkedHashMap<>();
        if (raw == null) return m;
        for (String kv : raw.split("&")) {
            String[] p = kv.split("=", 2);
            if (!p[0].isEmpty()) m.put(p[0], p.length > 1 ? java.net.URLDecoder.decode(p[1], StandardCharsets.UTF_8) : "");
        }
        return m;
    }
}
