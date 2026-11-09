package com.securetest.adapters.external;

import com.fasterxml.jackson.databind.JsonNode;
import com.securetest.adapters.support.ScanSupport;
import com.securetest.core.model.Enums.Confidence;
import com.securetest.core.model.Enums.ExecutionLocation;
import com.securetest.core.model.Enums.FieldType;
import com.securetest.core.model.Finding;
import com.securetest.core.model.ModuleCatalog;
import com.securetest.core.model.Severity;
import com.securetest.core.spi.CommandRunner;
import com.securetest.core.spi.FieldSpec;
import com.securetest.core.spi.PreflightCheck;
import com.securetest.core.spi.ScanContext;
import com.securetest.core.spi.Scanner;
import com.securetest.core.spi.ScannerDescriptor;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

/**
 * Prowler adapter for AWS / Azure / GCP posture (SRS 5.11). Uses the credentials already configured for the
 * Prowler CLI (profile, environment, workload identity); SecureTest never stores raw cloud keys.
 */
public class ProwlerAdapter implements Scanner {

    public static final String ID = "prowler";

    @Override
    public ScannerDescriptor descriptor() {
        return ScannerDescriptor.builder(ID, ModuleCatalog.CLOUD_SECURITY, "Cloud account posture (Prowler)")
                .purpose("Runs Prowler against one cloud account/subscription/project to assess IAM, storage exposure, encryption, logging, "
                        + "network exposure and backups. Failed checks become findings with the cloud resource as asset.")
                .access("Read-only cloud API calls made by Prowler using the selected profile / identity. Every resource type Prowler enumerates is queried.")
                .location(ExecutionLocation.EXTERNAL_TOOL).tool("Prowler", "installed").requiresTarget()
                .duration("10–60 minutes").resources("Separate process; cloud API rate limits apply")
                .permission("AWS: SecurityAudit + ViewOnlyAccess managed policies (read-only)")
                .permission("Azure: Reader + Security Reader at subscription scope; Directory Readers for Entra ID checks")
                .permission("GCP: roles/viewer, roles/iam.securityReviewer, roles/cloudasset.viewer on the project")
                .prerequisite("pip install prowler; add 'prowler' to securetest.execution.allowed-commands")
                .prerequisite("Credentials available to the Prowler CLI (profile, environment or workload identity)")
                .field(FieldSpec.select("provider", "Cloud provider", "aws", List.of("aws", "azure", "gcp"), ""))
                .field(FieldSpec.optional("profile", "AWS profile / Azure auth method / GCP project", FieldType.TEXT, "",
                        "aws: named profile; azure: az-cli-auth|sp-env-auth|managed-identity-auth; gcp: project id"))
                .field(FieldSpec.optional("regions", "Regions (AWS)", FieldType.TEXT, "", "Comma-separated regions; empty = all enabled regions"))
                .field(FieldSpec.optional("severity", "Minimum severity", FieldType.TEXT, "", "Optional: critical high medium low"))
                .field(FieldSpec.number("timeoutMinutes", "Timeout (minutes)", 60, 5, 240, ""))
                .build();
    }

    @Override
    public List<PreflightCheck> preflight(ScanContext ctx) {
        List<PreflightCheck> out = ExternalTools.toolChecks(ctx, "prowler", "Install with 'pip install prowler'.");
        out.add(PreflightCheck.warn("Scope", "Only the account/subscription/project resolved by the selected credentials is assessed. Use read-only roles."));
        return out;
    }

    @Override
    public void scan(ScanContext ctx) throws Exception {
        String provider = ctx.option("provider", "aws").replaceAll("[^a-z]", "");
        String profile = ctx.option("profile", "").replaceAll("[^\\w.@-]", "");
        Path outDir = Files.createTempDirectory("securetest-prowler");
        try {
            List<String> cmd = new ArrayList<>(List.of("prowler", provider, "--output-formats", "json-ocsf", "--output-directory", outDir.toString(), "--no-banner"));
            if (!profile.isBlank()) {
                switch (provider) {
                    case "aws" -> cmd.addAll(List.of("--profile", profile));
                    case "azure" -> cmd.add("--" + profile);
                    case "gcp" -> cmd.addAll(List.of("--project-ids", profile));
                    default -> { }
                }
            }
            String regions = ctx.option("regions", "").replaceAll("[^a-z0-9,-]", "");
            if (provider.equals("aws") && !regions.isBlank()) { cmd.add("--region"); cmd.addAll(List.of(regions.split(","))); }
            String sev = ctx.option("severity", "").replaceAll("[^a-z ]", "");
            if (!sev.isBlank()) { cmd.add("--severity"); cmd.addAll(List.of(sev.split(" "))); }
            ctx.progress(5, "Running prowler " + provider);
            CommandRunner.CommandResult r = ctx.commands().run(cmd, null, Duration.ofMinutes(ctx.intOption("timeoutMinutes", 60, 5, 240)));
            ctx.log("Prowler exit code " + r.exitCode());
            List<Path> files;
            try (Stream<Path> s = Files.walk(outDir)) {
                files = s.filter(p -> p.toString().endsWith(".ocsf.json") || p.toString().endsWith(".json")).toList();
            }
            if (files.isEmpty()) throw new IllegalStateException("Prowler wrote no OCSF output: " + ScanSupport.truncate(r.stderr() + r.stdout(), 800));
            for (Path f : files) {
                ctx.attachArtifact(f.getFileName().toString(), "application/json", Files.readAllBytes(f));
                JsonNode arr = ScanSupport.JSON.readTree(f.toFile());
                if (!arr.isArray()) continue;
                for (JsonNode e : arr) {
                    ctx.checkCancelled();
                    if (!"FAIL".equalsIgnoreCase(e.path("status_code").asText())) continue;
                    String title = e.path("finding_info").path("title").asText(e.path("message").asText("Prowler finding"));
                    String code = e.path("metadata").path("event_code").asText(e.path("finding_info").path("uid").asText());
                    JsonNode res = e.path("resources").isArray() && e.path("resources").size() > 0 ? e.path("resources").get(0) : null;
                    String asset = res == null ? provider : res.path("uid").asText(res.path("name").asText(provider));
                    Finding fi = Finding.of(ModuleCatalog.CLOUD_SECURITY, ID, "PROWLER-" + code, title, Severity.parse(e.path("severity").asText("medium")))
                            .rawSeverity(e.path("severity").asText()).asset(asset).exposure(asset.contains("public") ? "internet" : null)
                            .description(e.path("finding_info").path("desc").asText(e.path("status_detail").asText("")))
                            .remediation(e.path("remediation").path("desc").asText(""))
                            .category("Cloud posture").confidence(Confidence.HIGH).tags("CIS-CLOUD")
                            .attr("region", res == null ? null : res.path("region").asText(null))
                            .attr("provider", provider);
                    e.path("remediation").path("references").forEach(u -> { if (fi.references.size() < 5) fi.references.add(u.asText()); });
                    ctx.report(fi);
                }
            }
        } finally {
            try (Stream<Path> s = Files.walk(outDir)) {
                s.sorted(java.util.Comparator.reverseOrder()).forEach(p -> p.toFile().delete());
            }
        }
    }
}
