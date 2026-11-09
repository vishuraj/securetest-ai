package com.securetest.adapters.external;

import com.fasterxml.jackson.databind.JsonNode;
import com.securetest.adapters.support.ScanSupport;
import com.securetest.core.model.Enums.Confidence;
import com.securetest.core.model.Enums.ExecutionLocation;
import com.securetest.core.model.Finding;
import com.securetest.core.model.ModuleCatalog;
import com.securetest.core.model.Severity;
import com.securetest.core.spi.CommandRunner;
import com.securetest.core.spi.FieldSpec;
import com.securetest.core.spi.PreflightCheck;
import com.securetest.core.spi.ScanContext;
import com.securetest.core.spi.Scanner;
import com.securetest.core.spi.ScannerDescriptor;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

/** Bridgecrew Checkov adapter for Terraform, CloudFormation, Kubernetes, Helm, Dockerfile (SRS 5.11). */
public class CheckovAdapter implements Scanner {

    public static final String ID = "checkov";

    @Override
    public ScannerDescriptor descriptor() {
        return ScannerDescriptor.builder(ID, ModuleCatalog.CLOUD_SECURITY, "Checkov IaC scan")
                .purpose("Runs the installed Checkov CLI over the workspace and imports failed policy checks for Terraform, CloudFormation, "
                        + "Kubernetes, Helm, ARM, Serverless and Dockerfiles.")
                .access("Executes 'checkov' with read access to the source workspace.")
                .location(ExecutionLocation.EXTERNAL_TOOL).tool("Checkov", "installed").requiresSourceRoot()
                .duration("1–5 minutes")
                .prerequisite("pip install checkov; add 'checkov' to securetest.execution.allowed-commands")
                .field(FieldSpec.optional("framework", "Frameworks", com.securetest.core.model.Enums.FieldType.TEXT, "",
                        "Optional comma-separated Checkov frameworks (terraform,kubernetes,dockerfile…)."))
                .field(FieldSpec.number("timeoutMinutes", "Timeout (minutes)", 10, 1, 60, ""))
                .build();
    }

    @Override
    public List<PreflightCheck> preflight(ScanContext ctx) {
        return ExternalTools.toolChecks(ctx, "checkov", "Install with 'pip install checkov'.");
    }

    @Override
    public void scan(ScanContext ctx) throws Exception {
        Path root = ScanSupport.requireSource(ctx);
        String version = ExternalTools.version(ctx, "checkov", "--version");
        List<String> cmd = new ArrayList<>(List.of("checkov", "-d", root.toString(), "-o", "json", "--quiet", "--compact", "--soft-fail"));
        String fw = ctx.option("framework", "").replaceAll("[^a-z_,]", "");
        if (!fw.isBlank()) cmd.addAll(List.of("--framework", fw));
        ctx.progress(10, "Running checkov");
        CommandRunner.CommandResult r = ctx.commands().run(cmd, root, Duration.ofMinutes(ctx.intOption("timeoutMinutes", 10, 1, 60)));
        if (r.stdout().isBlank()) throw new IllegalStateException("Checkov produced no output: " + ScanSupport.truncate(r.stderr(), 500));
        ctx.attachArtifact("checkov-report.json", "application/json", r.stdout().getBytes(StandardCharsets.UTF_8));
        JsonNode out = ScanSupport.JSON.readTree(r.stdout());
        List<JsonNode> reports = new ArrayList<>();
        if (out.isArray()) out.forEach(reports::add); else reports.add(out);
        for (JsonNode rep : reports) {
            for (JsonNode c : rep.path("results").path("failed_checks")) {
                String sevRaw = c.path("severity").isNull() ? "MEDIUM" : c.path("severity").asText("MEDIUM");
                String file = c.path("file_path").asText().replaceFirst("^/", "");
                Finding f = Finding.of(ModuleCatalog.CLOUD_SECURITY, ID, c.path("check_id").asText(), c.path("check_name").asText(), Severity.parse(sevRaw))
                        .rawSeverity(sevRaw).toolVersion(version).asset(c.path("resource").asText(file))
                        .description("Checkov " + rep.path("check_type").asText() + " check failed for resource " + c.path("resource").asText() + ".")
                        .remediation("See the Checkov guideline for the compliant configuration.")
                        .category("IaC policy").confidence(Confidence.HIGH).tags("CIS-CLOUD");
                JsonNode range = c.path("file_line_range");
                if (range.isArray() && range.size() == 2) f.location(file, range.get(0).asInt(), range.get(1).asInt());
                if (c.hasNonNull("guideline")) f.references.add(c.path("guideline").asText());
                ctx.report(f);
            }
        }
    }
}
