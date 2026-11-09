package com.securetest.adapters.external;

import com.fasterxml.jackson.databind.JsonNode;
import com.securetest.adapters.support.ScanSupport;
import com.securetest.core.model.Enums.Confidence;
import com.securetest.core.model.Enums.ExecutionLocation;
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

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Imports issues, quality gate and measures from SonarQube / SonarCloud (SRS 5.5). */
public class SonarQubeAdapter implements Scanner {

    public static final String ID = "sonarqube";
    private static final String METRICS = "bugs,vulnerabilities,code_smells,coverage,duplicated_lines_density,ncloc,sqale_index,"
            + "sqale_rating,reliability_rating,security_rating,complexity,security_hotspots";

    @Override
    public ScannerDescriptor descriptor() {
        return ScannerDescriptor.builder(ID, ModuleCatalog.CODE_QUALITY, "SonarQube / SonarCloud import")
                .purpose("Reads open issues, the quality gate status and key measures (bugs, vulnerabilities, smells, coverage, duplication, "
                        + "technical debt) for a project from your SonarQube or SonarCloud server.")
                .access("HTTPS GET requests to the Sonar Web API with a user token (Browse permission on the project).")
                .location(ExecutionLocation.REMOTE_SERVICE).tool("SonarQube Web API", "server").requiresTarget()
                .permission("Sonar token with 'Browse' permission on the project (read-only)")
                .prerequisite("Sonar server host on securetest.security.target-allowlist")
                .field(FieldSpec.required("serverUrl", "Server URL", FieldType.URL, "https://sonarcloud.io", ""))
                .field(FieldSpec.required("projectKey", "Project key", FieldType.TEXT, "", ""))
                .field(FieldSpec.optional("branch", "Branch", FieldType.TEXT, "", "Empty = main branch"))
                .field(FieldSpec.secret("token", "User token", true, "Use a reference such as env://SONAR_TOKEN."))
                .field(FieldSpec.number("maxIssues", "Maximum issues", 2000, 1, 10000, ""))
                .build();
    }

    private static Map<String, String> auth(ScanContext ctx) {
        String token = ctx.secret("token");
        Map<String, String> h = new LinkedHashMap<>();
        h.put("Accept", "application/json");
        if (token != null && !token.isBlank()) {
            h.put("Authorization", "Basic " + Base64.getEncoder().encodeToString((token + ":").getBytes(StandardCharsets.UTF_8)));
        }
        return h;
    }

    private static String server(ScanContext ctx) {
        String s = ctx.option("serverUrl", "");
        return s.endsWith("/") ? s.substring(0, s.length() - 1) : s;
    }

    @Override
    public List<PreflightCheck> preflight(ScanContext ctx) {
        List<PreflightCheck> out = new ArrayList<>();
        try {
            HttpResult r = ctx.http().get(server(ctx) + "/api/authentication/validate", auth(ctx));
            boolean valid = r.status() == 200 && r.body().contains("true");
            out.add(valid ? PreflightCheck.ok("Authentication", "Token accepted by " + server(ctx))
                    : PreflightCheck.error("Authentication", "Token rejected (HTTP " + r.status() + ")"));
        } catch (Exception e) {
            out.add(PreflightCheck.error("Connectivity", e.getMessage()));
        }
        return out;
    }

    @Override
    public void scan(ScanContext ctx) throws Exception {
        String server = server(ctx);
        String key = URLEncoder.encode(ctx.option("projectKey", ""), StandardCharsets.UTF_8);
        String branch = ctx.option("branch", "");
        String br = branch.isBlank() ? "" : "&branch=" + URLEncoder.encode(branch, StandardCharsets.UTF_8);
        Map<String, String> h = auth(ctx);
        String version = ScanSupport.truncate(ctx.http().get(server + "/api/server/version", h).body().trim(), 40);

        JsonNode gate = ScanSupport.JSON.readTree(ctx.http().get(server + "/api/qualitygates/project_status?projectKey=" + key + br, h).body());
        JsonNode measures = ScanSupport.JSON.readTree(ctx.http().get(server + "/api/measures/component?component=" + key + br + "&metricKeys=" + METRICS, h).body());
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("qualityGate", gate.path("projectStatus").path("status").asText("NONE"));
        for (JsonNode me : measures.path("component").path("measures")) m.put(me.path("metric").asText(), me.path("value").asText());
        ctx.putResult("sonarMeasures", m);
        if ("ERROR".equals(m.get("qualityGate"))) {
            ctx.report(Finding.of(ModuleCatalog.CODE_QUALITY, ID, "SONAR-QUALITY-GATE", "SonarQube quality gate failed", Severity.HIGH)
                    .description("Failing conditions: " + gate.path("projectStatus").path("conditions").toString())
                    .remediation("Open the project in SonarQube and address the failing gate conditions.").asset(ctx.option("projectKey", ""))
                    .toolVersion(version).category("Quality gate").confidence(Confidence.HIGH).refs(server + "/dashboard?id=" + key));
        }
        int max = ctx.intOption("maxIssues", 2000, 1, 10000);
        int fetched = 0;
        for (int page = 1; fetched < max && page <= 20; page++) {
            ctx.checkCancelled();
            JsonNode res = ScanSupport.JSON.readTree(ctx.http().get(server + "/api/issues/search?componentKeys=" + key + br
                    + "&resolved=false&ps=500&p=" + page, h).body());
            JsonNode issues = res.path("issues");
            if (!issues.isArray() || issues.isEmpty()) break;
            for (JsonNode i : issues) {
                if (fetched++ >= max) break;
                String sev = i.path("severity").asText("MAJOR");
                Severity s = switch (sev) {
                    case "BLOCKER" -> Severity.CRITICAL;
                    case "CRITICAL" -> Severity.HIGH;
                    case "MAJOR" -> Severity.MEDIUM;
                    case "MINOR" -> Severity.LOW;
                    default -> Severity.INFO;
                };
                String comp = i.path("component").asText();
                String file = comp.contains(":") ? comp.substring(comp.indexOf(':') + 1) : comp;
                String type = i.path("type").asText();
                Finding f = Finding.of(ModuleCatalog.CODE_QUALITY, ID, i.path("rule").asText(), i.path("message").asText(), s)
                        .rawSeverity(sev).toolVersion(version).category(type).confidence(Confidence.HIGH).asset(file)
                        .description(type + " reported by SonarQube rule " + i.path("rule").asText() + ".")
                        .remediation("See the rule description for compliant examples.")
                        .effort(i.path("effort").asText(null))
                        .refs(server + "/coding_rules?open=" + i.path("rule").asText() + "&rule_key=" + i.path("rule").asText(),
                                server + "/project/issues?id=" + key + "&open=" + i.path("key").asText());
                if (type.equals("VULNERABILITY")) f.complianceTags.add("OWASP-A04");
                JsonNode tr = i.path("textRange");
                if (tr.has("startLine")) f.location(file, tr.path("startLine").asInt(), tr.path("endLine").asInt());
                ctx.report(f);
            }
            ctx.progress(20 + Math.min(75, fetched * 75 / max), "Imported " + fetched + " issues");
            if (page * 500 >= res.path("paging").path("total").asInt(res.path("total").asInt(0))) break;
        }
    }
}
