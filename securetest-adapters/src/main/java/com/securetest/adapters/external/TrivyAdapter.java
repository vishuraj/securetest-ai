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
import com.securetest.core.util.Redactor;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

/** Aqua Trivy adapter: filesystem, container image and config scanning (SRS 5.6, 5.11). */
public class TrivyAdapter implements Scanner {

    public static final String ID = "trivy";
    private final String moduleId;
    private final String scannerId;

    public TrivyAdapter() { this(ModuleCatalog.VULNERABILITY, ID); }

    /** A second instance is registered for the Cloud/Kubernetes module (image + config scanning). */
    public TrivyAdapter(String moduleId, String scannerId) {
        this.moduleId = moduleId;
        this.scannerId = scannerId;
    }

    @Override
    public ScannerDescriptor descriptor() {
        boolean cloud = moduleId.equals(ModuleCatalog.CLOUD_SECURITY);
        return ScannerDescriptor.builder(scannerId, moduleId, cloud ? "Trivy image & config scan" : "Trivy vulnerability scan")
                .purpose("Runs the locally installed Trivy CLI to find vulnerable OS packages and libraries, misconfigurations and secrets in "
                        + "the workspace or a container image. Results are normalized into SecureTest findings with original Trivy metadata.")
                .access("Executes 'trivy' with read access to the workspace or the image. Trivy may download its vulnerability DB unless offline mode is set.")
                .location(ExecutionLocation.EXTERNAL_TOOL).tool("Aqua Trivy", "installed")
                .duration("1–10 minutes").resources("Separate process; DB cache ~500 MB")
                .prerequisite("trivy installed and listed in securetest.execution.allowed-commands")
                .field(FieldSpec.select("type", "Scan type", cloud ? "image" : "fs", List.of("fs", "image", "config"), "fs = workspace, image = container image, config = IaC"))
                .field(FieldSpec.optional("target", "Target", FieldType.TEXT, "", "Image reference (e.g. myapp:1.2.3) or path. Empty = source workspace."))
                .field(FieldSpec.optional("scanners", "Scanners", FieldType.TEXT, "vuln,secret,misconfig", "Comma-separated Trivy scanners."))
                .field(FieldSpec.flag("offline", "Offline mode (--skip-db-update --offline-scan)", false, "For air-gapped environments with a pre-loaded DB."))
                .field(FieldSpec.number("timeoutMinutes", "Timeout (minutes)", 15, 1, 120, ""))
                .build();
    }

    @Override
    public List<PreflightCheck> preflight(ScanContext ctx) {
        return ExternalTools.toolChecks(ctx, "trivy", "Install from https://trivy.dev.");
    }

    @Override
    public void scan(ScanContext ctx) throws Exception {
        String type = ctx.option("type", "fs");
        String target = ctx.option("target", "");
        Path root = ctx.sourceRoot().orElse(null);
        if (target.isBlank()) {
            if (type.equals("image")) throw new IllegalArgumentException("An image reference is required for image scans.");
            target = ScanSupport.requireSource(ctx).toString();
        }
        if (target.startsWith("-")) throw new IllegalArgumentException("Invalid target.");
        String version = ExternalTools.version(ctx, "trivy", "--version");
        List<String> cmd = new ArrayList<>(List.of("trivy", type, "--format", "json", "--quiet", "--timeout", ctx.intOption("timeoutMinutes", 15, 1, 120) + "m"));
        if (!type.equals("config")) cmd.addAll(List.of("--scanners", ctx.option("scanners", "vuln,secret,misconfig").replaceAll("[^a-z,]", "")));
        if (ctx.boolOption("offline", false)) cmd.addAll(List.of("--skip-db-update", "--offline-scan"));
        cmd.add(target);
        ctx.progress(10, "Running " + String.join(" ", cmd));
        CommandRunner.CommandResult r = ctx.commands().run(cmd, root, Duration.ofMinutes(ctx.intOption("timeoutMinutes", 15, 1, 120) + 1));
        if (r.timedOut()) throw new IllegalStateException("Trivy timed out");
        if (r.stdout().isBlank()) throw new IllegalStateException("Trivy produced no output (exit " + r.exitCode() + "): " + ScanSupport.truncate(r.stderr(), 500));
        ctx.attachArtifact("trivy-report.json", "application/json", r.stdout().getBytes(StandardCharsets.UTF_8));
        ctx.progress(80, "Normalizing results");
        JsonNode report = ScanSupport.JSON.readTree(r.stdout());
        for (JsonNode res : report.path("Results")) {
            String file = res.path("Target").asText();
            for (JsonNode v : res.path("Vulnerabilities")) {
                Severity s = Severity.parse(v.path("Severity").asText());
                Finding f = Finding.of(moduleId, scannerId, v.path("VulnerabilityID").asText(),
                                v.path("VulnerabilityID").asText() + " in " + v.path("PkgName").asText() + " " + v.path("InstalledVersion").asText()
                                        + (v.has("Title") ? ": " + v.path("Title").asText() : ""), s)
                        .rawSeverity(v.path("Severity").asText()).toolVersion(version)
                        .description(ScanSupport.truncate(v.path("Description").asText(""), 4000))
                        .asset(type.equals("image") ? target : file).category("Vulnerable dependency").confidence(Confidence.HIGH)
                        .tags("OWASP-A06", "PCI-6.3.3", "ISO27001-A.8.8");
                f.dependency = new Finding.DependencyInfo(v.path("PkgName").asText(), v.path("InstalledVersion").asText());
                f.dependency.fixedVersion = v.hasNonNull("FixedVersion") ? v.path("FixedVersion").asText().split(",")[0].trim() : null;
                f.dependency.advisoryId = v.path("VulnerabilityID").asText();
                f.dependency.aliases = new ArrayList<>(List.of(v.path("VulnerabilityID").asText()));
                JsonNode nvd = v.path("CVSS").path("nvd");
                if (nvd.has("V3Score")) f.dependency.cvssScore = nvd.path("V3Score").asDouble();
                if (nvd.has("V3Vector")) f.dependency.cvssVector = nvd.path("V3Vector").asText();
                f.dependency.dependencyPath = new ArrayList<>(List.of(file));
                f.remediation(f.dependency.fixedVersion != null ? "Upgrade " + f.dependency.packageName + " to " + f.dependency.fixedVersion + "."
                        : "No fix available yet; evaluate mitigations.");
                if (f.dependency.fixedVersion != null && f.dependency.packageName.contains(":")) f.fix("dependency-upgrade");
                if (v.hasNonNull("PrimaryURL")) f.references.add(v.path("PrimaryURL").asText());
                ctx.report(f);
            }
            for (JsonNode m : res.path("Misconfigurations")) {
                if ("PASS".equals(m.path("Status").asText())) continue;
                Finding f = Finding.of(moduleId, scannerId, m.path("ID").asText(), m.path("Title").asText(), Severity.parse(m.path("Severity").asText()))
                        .rawSeverity(m.path("Severity").asText()).toolVersion(version)
                        .description(m.path("Description").asText("") + " " + m.path("Message").asText(""))
                        .remediation(m.path("Resolution").asText("")).asset(file).category("Misconfiguration").confidence(Confidence.HIGH)
                        .tags("CIS-DOCKER", "CIS-K8S");
                JsonNode cm = m.path("CauseMetadata");
                if (cm.has("StartLine")) f.location(file, cm.path("StartLine").asInt(), cm.path("EndLine").asInt(cm.path("StartLine").asInt()));
                if (m.hasNonNull("PrimaryURL")) f.references.add(m.path("PrimaryURL").asText());
                ctx.report(f);
            }
            for (JsonNode sct : res.path("Secrets")) {
                Finding f = Finding.of(moduleId, scannerId, "TRIVY-SECRET-" + sct.path("RuleID").asText(), "Secret: " + sct.path("Title").asText(),
                                Severity.parse(sct.path("Severity").asText()))
                        .toolVersion(version).description("Trivy detected a secret (" + sct.path("Category").asText() + ").")
                        .evidence(Redactor.redact(sct.path("Match").asText(""))).asset(file).category("Secrets").confidence(Confidence.HIGH)
                        .remediation("Rotate the credential and remove it from the repository history.").tags("CIS-SECRETS", "OWASP-A07");
                if (sct.has("StartLine")) f.location(file, sct.path("StartLine").asInt(), sct.path("EndLine").asInt());
                ctx.report(f);
            }
        }
    }
}
