package com.securetest.adapters.external;

import com.fasterxml.jackson.databind.JsonNode;
import com.securetest.adapters.support.ScanSupport;
import com.securetest.core.model.Enums.Confidence;
import com.securetest.core.model.Enums.ExecutionLocation;
import com.securetest.core.model.Enums.FieldType;
import com.securetest.core.model.Enums.ScanMode;
import com.securetest.core.model.Finding;
import com.securetest.core.model.ModuleCatalog;
import com.securetest.core.model.Severity;
import com.securetest.core.spi.FieldSpec;
import com.securetest.core.spi.PreflightCheck;
import com.securetest.core.spi.ScanContext;
import com.securetest.core.spi.Scanner;
import com.securetest.core.spi.ScannerDescriptor;
import com.securetest.core.util.Redactor;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/** OWASP ZAP adapter using the ZAP API of a separately running ZAP daemon (SRS 5.7). */
public class ZapAdapter implements Scanner {

    public static final String ID = "owasp-zap";

    @Override
    public ScannerDescriptor descriptor() {
        return ScannerDescriptor.builder(ID, ModuleCatalog.API_SECURITY, "OWASP ZAP DAST")
                .purpose("Drives a running OWASP ZAP daemon: spiders the target, waits for passive analysis and optionally runs an active scan, "
                        + "then imports ZAP alerts with evidence, CWE/WASC ids and solutions.")
                .access("ZAP crawls the allowlisted target and, if active scanning is enabled, sends attack payloads. Run against test environments only.")
                .mode(ScanMode.ACTIVE).location(ExecutionLocation.EXTERNAL_TOOL).tool("OWASP ZAP", "daemon").requiresTarget()
                .duration("5–60 minutes").resources("ZAP process; traffic on the target")
                .prerequisite("ZAP running in daemon mode, e.g. zap.sh -daemon -port 8090 -config api.key=...")
                .prerequisite("Both the ZAP API host and the target are on the allowlist")
                .field(FieldSpec.required("zapUrl", "ZAP API URL", FieldType.URL, "http://localhost:8090", ""))
                .field(FieldSpec.secret("apiKey", "ZAP API key", false, "Reference such as env://ZAP_API_KEY."))
                .field(FieldSpec.required("target", "Target URL", FieldType.URL, "self", "'self' = this application."))
                .field(FieldSpec.flag("activeScan", "Run active scan", false, "Sends attack payloads. Requires approval."))
                .field(FieldSpec.number("maxMinutes", "Maximum minutes", 20, 1, 240, ""))
                .field(FieldSpec.number("maxChildren", "Spider max children", 50, 0, 10000, "0 = unlimited"))
                .build();
    }

    private static String zap(ScanContext ctx) {
        String z = ctx.option("zapUrl", "http://localhost:8090");
        return z.endsWith("/") ? z.substring(0, z.length() - 1) : z;
    }

    private static String target(ScanContext ctx) {
        String t = ctx.option("target", "self");
        return t.equalsIgnoreCase("self") ? ctx.targets().selfBaseUrl() : t;
    }

    private JsonNode call(ScanContext ctx, String path) throws Exception {
        String key = ctx.secret("apiKey");
        Map<String, String> h = key == null || key.isBlank() ? Map.of() : Map.of("X-ZAP-API-Key", key);
        var r = ctx.http().get(zap(ctx) + path, h);
        if (r.status() != 200) throw new IllegalStateException("ZAP API " + path.split("\\?")[0] + " returned HTTP " + r.status());
        return ScanSupport.JSON.readTree(r.body());
    }

    @Override
    public List<PreflightCheck> preflight(ScanContext ctx) {
        List<PreflightCheck> out = new ArrayList<>();
        try {
            ctx.targets().requireAllowedUrl(target(ctx));
            out.add(PreflightCheck.ok("Target allowlist", target(ctx)));
            out.add(PreflightCheck.ok("ZAP", "ZAP " + call(ctx, "/JSON/core/view/version/").path("version").asText()));
        } catch (Exception e) {
            out.add(PreflightCheck.error("ZAP", e.getMessage()));
        }
        return out;
    }

    @Override
    public void scan(ScanContext ctx) throws Exception {
        String target = ctx.targets().requireAllowedUrl(target(ctx)).toString();
        String enc = URLEncoder.encode(target, StandardCharsets.UTF_8);
        String version = call(ctx, "/JSON/core/view/version/").path("version").asText();
        long deadline = System.currentTimeMillis() + ctx.intOption("maxMinutes", 20, 1, 240) * 60_000L;
        String spider = call(ctx, "/JSON/spider/action/scan/?url=" + enc + "&recurse=true&maxChildren=" + ctx.intOption("maxChildren", 50, 0, 10000)).path("scan").asText();
        int status = 0;
        while (status < 100 && System.currentTimeMillis() < deadline) {
            ctx.checkCancelled();
            Thread.sleep(2000);
            status = call(ctx, "/JSON/spider/view/status/?scanId=" + spider).path("status").asInt();
            ctx.progress(status / 4, "Spider " + status + "%");
        }
        while (System.currentTimeMillis() < deadline && call(ctx, "/JSON/pscan/view/recordsToScan/").path("recordsToScan").asInt() > 0) {
            ctx.checkCancelled();
            Thread.sleep(2000);
        }
        if (ctx.boolOption("activeScan", false)) {
            String ascan = call(ctx, "/JSON/ascan/action/scan/?url=" + enc + "&recurse=true").path("scan").asText();
            status = 0;
            while (status < 100 && System.currentTimeMillis() < deadline) {
                ctx.checkCancelled();
                Thread.sleep(5000);
                status = call(ctx, "/JSON/ascan/view/status/?scanId=" + ascan).path("status").asInt();
                ctx.progress(25 + status * 65 / 100, "Active scan " + status + "%");
            }
            if (status < 100) {
                call(ctx, "/JSON/ascan/action/stop/?scanId=" + ascan);
                ctx.log("Active scan stopped at the time limit (" + status + "%)");
            }
        }
        Set<String> seen = new HashSet<>();
        for (int start = 0; start < 5000; start += 500) {
            JsonNode alerts = call(ctx, "/JSON/core/view/alerts/?baseurl=" + enc + "&start=" + start + "&count=500").path("alerts");
            if (!alerts.isArray() || alerts.isEmpty()) break;
            for (JsonNode a : alerts) {
                String url = a.path("url").asText();
                String path = url.replaceAll("\\?.*$", "");
                String dedupe = a.path("pluginId").asText() + "|" + path + "|" + a.path("param").asText();
                if (!seen.add(dedupe)) continue;
                String risk = a.path("risk").asText("Informational");
                Severity s = switch (risk.toLowerCase(Locale.ROOT)) {
                    case "high" -> Severity.HIGH;
                    case "medium" -> Severity.MEDIUM;
                    case "low" -> Severity.LOW;
                    default -> Severity.INFO;
                };
                String conf = a.path("confidence").asText("Medium").toLowerCase(Locale.ROOT);
                Finding f = Finding.of(ModuleCatalog.API_SECURITY, ID, "ZAP-" + a.path("pluginId").asText(), a.path("name").asText() + " (" + path + ")", s)
                        .rawSeverity(risk + " / confidence " + a.path("confidence").asText()).toolVersion(version)
                        .description(a.path("description").asText()).remediation(a.path("solution").asText())
                        .evidence(Redactor.redact("URL: " + url + "\nParam: " + a.path("param").asText() + "\nAttack: " + a.path("attack").asText()
                                + "\nEvidence: " + a.path("evidence").asText()))
                        .asset(path).category("DAST")
                        .confidence(conf.contains("high") || conf.contains("confirmed") ? Confidence.HIGH : conf.contains("low") ? Confidence.LOW : Confidence.MEDIUM)
                        .attr("cwe", a.path("cweid").asText()).attr("wasc", a.path("wascid").asText());
                for (String ref : a.path("reference").asText("").split("\\s+")) if (ref.startsWith("http") && f.references.size() < 5) f.references.add(ref);
                f.complianceTags.add("OWASP-A05");
                if (!a.path("cweid").asText("").isBlank()) f.complianceTags.add("CWE-" + a.path("cweid").asText());
                ctx.report(f);
            }
        }
    }
}
