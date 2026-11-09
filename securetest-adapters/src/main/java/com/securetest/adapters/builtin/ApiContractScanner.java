package com.securetest.adapters.builtin;

import com.fasterxml.jackson.databind.JsonNode;
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
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Functional + contract + auth tests generated from an OpenAPI definition (SRS 5.4 API testing, 5.7).
 * Only safe (GET/HEAD) operations are exercised.
 */
public class ApiContractScanner implements Scanner {

    public static final String ID = "builtin-api-contract";

    @Override
    public ScannerDescriptor descriptor() {
        return ScannerDescriptor.builder(ID, ModuleCatalog.TESTING, "API tests from OpenAPI")
                .purpose("Imports the OpenAPI definition, calls every safe GET operation, validates status codes, content types and required "
                        + "response properties, and checks that secured operations reject unauthenticated calls.")
                .access("Sends GET requests to the allowlisted target. No data is modified.")
                .requiresTarget()
                .field(FieldSpec.required("baseUrl", "Target base URL", FieldType.URL, "self", "'self' means this application. Must be on the target allowlist."))
                .field(FieldSpec.optional("openApiPath", "OpenAPI document path", FieldType.TEXT, "/v3/api-docs", "Path or absolute URL of the OpenAPI JSON."))
                .field(FieldSpec.secret("authorization", "Authorization header value", false,
                        "Optional, e.g. a reference env://API_TEST_TOKEN resolving to 'Bearer …'. Used for authenticated calls."))
                .field(FieldSpec.number("maxRequests", "Maximum requests", 100, 1, 1000, ""))
                .field(FieldSpec.number("rate", "Requests per second", 5, 1, 50, ""))
                .build();
    }

    @Override
    public List<PreflightCheck> preflight(ScanContext ctx) {
        List<PreflightCheck> out = new ArrayList<>();
        try {
            String base = base(ctx);
            ctx.targets().requireAllowedUrl(base);
            out.add(PreflightCheck.ok("Target allowlist", base + " is authorized"));
            HttpResult r = ctx.http().get(specUrl(ctx, base));
            out.add(r.status() == 200 ? PreflightCheck.ok("OpenAPI document", "Retrieved (" + r.body().length() + " bytes)")
                    : PreflightCheck.error("OpenAPI document", "HTTP " + r.status() + " from " + specUrl(ctx, base)
                    + ". Add springdoc-openapi or point to the correct path."));
        } catch (Exception e) {
            out.add(PreflightCheck.error("Connectivity", e.getMessage()));
        }
        return out;
    }

    private static String base(ScanContext ctx) {
        String b = ctx.option("baseUrl", "self");
        if (b.equalsIgnoreCase("self")) b = ctx.targets().selfBaseUrl();
        return b.endsWith("/") ? b.substring(0, b.length() - 1) : b;
    }

    private static String specUrl(ScanContext ctx, String base) {
        String p = ctx.option("openApiPath", "/v3/api-docs");
        return p.startsWith("http") ? p : base + (p.startsWith("/") ? p : "/" + p);
    }

    @Override
    public void scan(ScanContext ctx) throws Exception {
        String base = base(ctx);
        HttpResult specResp = ctx.http().get(specUrl(ctx, base));
        if (specResp.status() != 200) throw new IllegalStateException("OpenAPI document returned HTTP " + specResp.status());
        JsonNode spec = ScanSupport.JSON.readTree(specResp.body());
        String serverPrefix = "";
        JsonNode servers = spec.path("servers");
        if (servers.isArray() && servers.size() > 0) {
            String url = servers.get(0).path("url").asText("");
            if (url.startsWith("/")) serverPrefix = url.equals("/") ? "" : url;
        }
        boolean globalSecurity = spec.path("security").isArray() && spec.path("security").size() > 0;
        String auth = ctx.secret("authorization");
        int max = ctx.intOption("maxRequests", 100, 1, 1000);
        int sent = 0;
        List<Map<String, Object>> results = new ArrayList<>();
        int passed = 0;
        int failed = 0;
        Iterator<Map.Entry<String, JsonNode>> paths = spec.path("paths").fields();
        List<Map.Entry<String, JsonNode>> all = new ArrayList<>();
        paths.forEachRemaining(all::add);
        int idx = 0;
        for (Map.Entry<String, JsonNode> pe : all) {
            ctx.checkCancelled();
            idx++;
            JsonNode op = pe.getValue().path("get");
            if (op.isMissingNode() || sent >= max) continue;
            String path = fillPathParams(pe.getKey(), op, pe.getValue());
            if (path == null) continue; // required query params we cannot satisfy safely
            String url = base + serverPrefix + path;
            Map<String, String> headers = new LinkedHashMap<>();
            headers.put("Accept", "application/json");
            if (auth != null && !auth.isBlank()) headers.put("Authorization", auth);
            HttpResult r = ctx.http().get(url, headers);
            sent++;
            List<String> problems = new ArrayList<>();
            JsonNode responses = op.path("responses");
            String code = String.valueOf(r.status());
            if (r.status() >= 500) problems.add("Server error " + r.status());
            else if (!responses.has(code) && !responses.has("default") && !responses.has(code.charAt(0) + "XX")) {
                problems.add("Undocumented status " + r.status());
            }
            JsonNode schema = responses.path(code).path("content").path("application/json").path("schema");
            if (r.success() && !schema.isMissingNode()) {
                String ct = r.header("Content-Type");
                if (ct == null || !ct.contains("json")) problems.add("Expected JSON but Content-Type is " + ct);
                else problems.addAll(validate(spec, schema, r.body()));
            }
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("method", "GET");
            row.put("path", path);
            row.put("status", r.status());
            row.put("ms", r.durationMs());
            row.put("result", problems.isEmpty() ? "PASS" : "FAIL");
            row.put("problems", problems);
            results.add(row);
            if (problems.isEmpty()) passed++; else failed++;
            if (!problems.isEmpty()) {
                Severity sev = r.status() >= 500 ? Severity.HIGH : Severity.MEDIUM;
                ctx.report(Finding.of(ModuleCatalog.TESTING, ID, r.status() >= 500 ? "API-5XX" : "API-CONTRACT", "API contract violation: GET " + pe.getKey(), sev)
                        .description(String.join("; ", problems))
                        .evidence("GET " + url + " -> " + r.status() + "\n" + Redactor.redact(ScanSupport.truncate(r.body(), 1500)))
                        .remediation("Align the implementation with the OpenAPI contract (status codes, content type and required fields), or update the contract.")
                        .asset(url).category("API test").confidence(Confidence.HIGH).tags("ASVS-13.1", "OWASP-API8"));
            }
            // negative auth test
            boolean secured = op.has("security") ? op.path("security").size() > 0 : globalSecurity;
            if (secured && sent < max) {
                HttpResult anon = ctx.http().get(url, Map.of("Accept", "application/json"));
                sent++;
                if (anon.success()) {
                    ctx.report(Finding.of(ModuleCatalog.TESTING, ID, "API-AUTH-MISSING", "Secured operation answered without credentials: GET " + pe.getKey(), Severity.HIGH)
                            .description("The OpenAPI contract declares a security requirement, but an unauthenticated request returned " + anon.status() + ".")
                            .evidence("GET " + url + " (no Authorization header) -> " + anon.status())
                            .remediation("Enforce authentication on this endpoint (e.g. Spring Security authorizeHttpRequests) and add a test for 401/403.")
                            .asset(url).category("Authentication").confidence(Confidence.HIGH).exposure("internal")
                            .tags("OWASP-A01", "OWASP-API2", "ASVS-4.1", "PCI-8.2"));
                }
            }
            ctx.progress(5 + 90 * idx / Math.max(1, all.size()), "Tested " + sent + " request(s)");
        }
        ctx.putResult("apiTests", Map.of("operations", all.size(), "requests", sent, "passed", passed, "failed", failed));
        ctx.putResult("apiResults", results);
    }

    private static String fillPathParams(String template, JsonNode op, JsonNode pathItem) {
        String path = template;
        List<JsonNode> params = new ArrayList<>();
        op.path("parameters").forEach(params::add);
        pathItem.path("parameters").forEach(params::add);
        StringBuilder query = new StringBuilder();
        for (JsonNode p : params) {
            String in = p.path("in").asText();
            String name = p.path("name").asText();
            String example = p.has("example") ? p.get("example").asText() : p.path("schema").has("example") ? p.path("schema").get("example").asText()
                    : p.path("schema").path("default").asText(null);
            if (in.equals("path")) {
                String v = example != null ? example : (p.path("schema").path("type").asText().equals("string") ? "test" : "1");
                path = path.replace("{" + name + "}", java.net.URLEncoder.encode(v, java.nio.charset.StandardCharsets.UTF_8));
            } else if (in.equals("query") && p.path("required").asBoolean(false)) {
                if (example == null) return null;
                query.append(query.length() == 0 ? '?' : '&').append(name).append('=')
                     .append(java.net.URLEncoder.encode(example, java.nio.charset.StandardCharsets.UTF_8));
            }
        }
        return path.contains("{") ? null : path + query;
    }

    private static List<String> validate(JsonNode spec, JsonNode schema, String body) {
        List<String> problems = new ArrayList<>();
        JsonNode json;
        try {
            json = ScanSupport.JSON.readTree(body);
        } catch (Exception e) {
            problems.add("Response is not valid JSON");
            return problems;
        }
        JsonNode s = resolve(spec, schema);
        if ("array".equals(s.path("type").asText())) {
            if (!json.isArray()) problems.add("Expected an array");
            else if (json.size() > 0) checkObject(spec, resolve(spec, s.path("items")), json.get(0), problems);
        } else {
            checkObject(spec, s, json, problems);
        }
        return problems;
    }

    private static void checkObject(JsonNode spec, JsonNode s, JsonNode json, List<String> problems) {
        if (!"object".equals(s.path("type").asText()) && !s.has("properties")) return;
        if (!json.isObject()) {
            problems.add("Expected a JSON object");
            return;
        }
        for (JsonNode req : s.path("required")) {
            if (!json.has(req.asText())) problems.add("Missing required property '" + req.asText() + "'");
        }
    }

    private static JsonNode resolve(JsonNode spec, JsonNode schema) {
        JsonNode s = schema;
        for (int i = 0; i < 5 && s.has("$ref"); i++) {
            String ref = s.get("$ref").asText();
            if (!ref.startsWith("#/")) break;
            JsonNode n = spec;
            for (String part : ref.substring(2).split("/")) n = n.path(part);
            s = n;
        }
        return s;
    }
}
