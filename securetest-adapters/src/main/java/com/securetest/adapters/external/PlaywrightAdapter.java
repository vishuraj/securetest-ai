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
import com.securetest.core.spi.CommandRunner;
import com.securetest.core.spi.FieldSpec;
import com.securetest.core.spi.PreflightCheck;
import com.securetest.core.spi.ScanContext;
import com.securetest.core.spi.Scanner;
import com.securetest.core.spi.ScannerDescriptor;
import com.securetest.core.util.Redactor;
import com.securetest.core.util.SourceFiles;
import com.securetest.core.util.UnifiedDiff;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Browser testing with Playwright (SRS 5.4): runs your Playwright suite across a browser matrix, imports results,
 * failure messages and screenshots as evidence. The base URL must be on the target allowlist.
 */
public class PlaywrightAdapter implements Scanner {

    public static final String ID = "playwright";
    private static final int MAX_ATTACHMENTS = 20;

    @Override
    public ScannerDescriptor descriptor() {
        return ScannerDescriptor.builder(ID, ModuleCatalog.TESTING, "Browser tests (Playwright)")
                .purpose("Runs your Playwright UI journeys against the chosen browsers (Chromium, Firefox, WebKit), then imports pass/fail/flaky "
                        + "results per browser, error messages and failure screenshots as evidence.")
                .access("Executes 'npx playwright test' in the workspace; the browsers visit the base URL, which must be allowlisted.")
                .mode(ScanMode.RESOURCE_INTENSIVE).location(ExecutionLocation.EXTERNAL_TOOL).tool("Playwright", "installed")
                .requiresSourceRoot().requiresTarget()
                .duration("Suite duration").resources("Headless browsers in separate processes")
                .prerequisite("Node.js + @playwright/test installed in the test directory (npx playwright install)")
                .prerequisite("'npx' listed in securetest.execution.allowed-commands")
                .field(FieldSpec.optional("directory", "Test directory", FieldType.PATH, "", "Folder with playwright.config.* relative to the workspace (empty = workspace root)."))
                .field(FieldSpec.required("baseUrl", "Base URL", FieldType.URL, "self", "Exported as PLAYWRIGHT_BASE_URL and BASE_URL. 'self' = this application."))
                .field(FieldSpec.optional("projects", "Browser matrix", FieldType.LIST, "chromium,firefox,webkit",
                        "Playwright project names to run. Empty = every project in the config."))
                .field(FieldSpec.optional("grep", "Only tests matching", FieldType.TEXT, "", "Optional title filter (--grep)."))
                .field(FieldSpec.number("workers", "Parallel workers", 2, 1, 16, ""))
                .field(FieldSpec.number("retries", "Retries", 1, 0, 5, "Tests that pass on retry are reported as flaky."))
                .field(FieldSpec.number("timeoutMinutes", "Timeout (minutes)", 30, 1, 240, ""))
                .build();
    }

    private static Path dir(ScanContext ctx) {
        Path root = ScanSupport.requireSource(ctx);
        String d = ctx.option("directory", "");
        return d.isBlank() ? root : SourceFiles.resolveInside(root, d);
    }

    @Override
    public List<PreflightCheck> preflight(ScanContext ctx) {
        List<PreflightCheck> out = ExternalTools.toolChecks(ctx, "npx", "Install Node.js and run 'npm i -D @playwright/test && npx playwright install'.");
        try {
            Path d = dir(ctx);
            boolean config = List.of("playwright.config.ts", "playwright.config.js", "playwright.config.mjs", "playwright.config.cjs").stream().anyMatch(n -> Files.exists(d.resolve(n)));
            out.add(config ? PreflightCheck.ok("Playwright config", d.toString()) : PreflightCheck.error("Playwright config", "No playwright.config.* in " + d));
            out.add(PreflightCheck.ok("Target allowlist", ctx.targets().requireAllowedUrl(baseUrl(ctx)).toString()));
        } catch (RuntimeException e) {
            out.add(PreflightCheck.error("Configuration", e.getMessage()));
        }
        return out;
    }

    private static String baseUrl(ScanContext ctx) {
        String b = ctx.option("baseUrl", "self");
        return b.equalsIgnoreCase("self") ? ctx.targets().selfBaseUrl() : b;
    }

    @Override
    public void scan(ScanContext ctx) throws Exception {
        Path d = dir(ctx);
        String base = ctx.targets().requireAllowedUrl(baseUrl(ctx)).toString();
        List<String> cmd = new ArrayList<>(List.of("npx", "playwright", "test", "--reporter=json",
                "--workers=" + ctx.intOption("workers", 2, 1, 16), "--retries=" + ctx.intOption("retries", 1, 0, 5)));
        for (String p : ctx.option("projects", "").split(",")) {
            String t = p.trim();
            if (!t.isEmpty()) {
                if (!t.matches("[\\w .-]{1,60}")) throw new IllegalArgumentException("Invalid project name: " + t);
                cmd.add("--project=" + t);
            }
        }
        String grep = ctx.option("grep", "");
        if (!grep.isBlank()) {
            if (!grep.matches("[\\w .@:/-]{1,100}")) throw new IllegalArgumentException("Invalid grep filter");
            cmd.add("--grep=" + grep);
        }
        ctx.progress(5, "Running " + String.join(" ", cmd));
        CommandRunner.CommandResult r = ctx.commands().run(cmd, d, Duration.ofMinutes(ctx.intOption("timeoutMinutes", 30, 1, 240)),
                Map.of("PLAYWRIGHT_BASE_URL", base, "BASE_URL", base, "CI", "1"));
        ctx.log("Playwright exit code " + r.exitCode() + (r.timedOut() ? " (timed out)" : ""));
        String out = r.stdout();
        int brace = out.indexOf('{');
        if (brace < 0) throw new IllegalStateException("Playwright produced no JSON report: " + ScanSupport.truncate(Redactor.redact(r.stderr()), 600));
        JsonNode report = ScanSupport.JSON.readTree(out.substring(brace));
        ctx.attachArtifact("playwright-report.json", "application/json", out.substring(brace).getBytes(java.nio.charset.StandardCharsets.UTF_8));
        importReport(ctx, report, d, ScanSupport.requireSource(ctx));
        if (r.timedOut()) throw new IllegalStateException("Playwright run timed out");
    }

    static void importReport(ScanContext ctx, JsonNode report, Path testDir, Path root) throws Exception {
        Map<String, int[]> matrix = new LinkedHashMap<>(); // project -> passed, failed, flaky, skipped
        List<Map<String, Object>> rows = new ArrayList<>();
        int[] attachments = {0};
        for (JsonNode suite : report.path("suites")) walk(ctx, suite, testDir, root, matrix, rows, attachments);
        List<Map<String, Object>> m = new ArrayList<>();
        matrix.forEach((p, c) -> m.add(Map.of("project", p, "passed", c[0], "failed", c[1], "flaky", c[2], "skipped", c[3])));
        ctx.putResult("browserMatrix", m);
        ctx.putResult("browserTests", rows.size() > 2000 ? rows.subList(0, 2000) : rows);
        JsonNode stats = report.path("stats");
        ctx.putResult("browserSummary", Map.of("expected", stats.path("expected").asInt(), "unexpected", stats.path("unexpected").asInt(),
                "flaky", stats.path("flaky").asInt(), "skipped", stats.path("skipped").asInt(), "durationSeconds", Math.round(stats.path("duration").asDouble() / 100) / 10.0));
    }

    private static void walk(ScanContext ctx, JsonNode suite, Path testDir, Path root, Map<String, int[]> matrix,
                             List<Map<String, Object>> rows, int[] attachments) throws Exception {
        for (JsonNode child : suite.path("suites")) walk(ctx, child, testDir, root, matrix, rows, attachments);
        for (JsonNode spec : suite.path("specs")) {
            for (JsonNode test : spec.path("tests")) {
                String project = test.path("projectName").asText("default");
                String status = test.path("status").asText(); // expected | unexpected | flaky | skipped
                int[] c = matrix.computeIfAbsent(project, k -> new int[4]);
                switch (status) {
                    case "expected" -> c[0]++;
                    case "unexpected" -> c[1]++;
                    case "flaky" -> c[2]++;
                    default -> c[3]++;
                }
                JsonNode results = test.path("results");
                JsonNode last = results.size() > 0 ? results.get(results.size() - 1) : null;
                Map<String, Object> row = new LinkedHashMap<>();
                row.put("test", spec.path("title").asText());
                row.put("file", spec.path("file").asText());
                row.put("project", project);
                row.put("status", status);
                row.put("ms", last == null ? 0 : last.path("duration").asLong());
                rows.add(row);
                if (!status.equals("unexpected") && !status.equals("flaky")) continue;
                JsonNode failed = null;
                for (JsonNode res : results) if (!"passed".equals(res.path("status").asText()) && !"skipped".equals(res.path("status").asText())) { failed = res; break; }
                String message = failed == null ? "" : failed.path("error").path("message").asText(failed.path("errors").path(0).path("message").asText(""));
                boolean flaky = status.equals("flaky");
                Finding f = Finding.of(ModuleCatalog.TESTING, ID, flaky ? "PW-FLAKY" : "PW-FAILED",
                                (flaky ? "Flaky browser test: " : "Browser test failed: ") + spec.path("title").asText() + " [" + project + "]",
                                flaky ? Severity.MEDIUM : Severity.HIGH)
                        .description(Redactor.redact(ScanSupport.truncate(stripAnsi(message), 1500)))
                        .evidence(failed == null ? null : Redactor.redact(ScanSupport.truncate(stripAnsi(failed.path("error").path("stack").asText("")), 3000)))
                        .remediation(flaky ? "The journey passed only on retry. Replace fixed waits with web-first assertions and isolate test data."
                                : "Open the screenshot/trace for this run, reproduce locally with 'npx playwright test --debug', and fix the UI or the test.")
                        .asset(project).category("Browser test").confidence(Confidence.HIGH).tags("ISO27001-A.8.29", "SOC2-CC8.1")
                        .attr("browser", project);
                Path file = testDir.resolve(spec.path("file").asText(""));
                int line = spec.path("line").asInt(0);
                if (line > 0 && Files.isRegularFile(file) && file.normalize().startsWith(root.normalize())) {
                    SourceFiles.locate(f, root, file, UnifiedDiff.lines(SourceFiles.read(file)), line, line, null);
                }
                if (failed != null) {
                    for (JsonNode a : failed.path("attachments")) {
                        if (attachments[0] >= MAX_ATTACHMENTS || !a.path("contentType").asText().startsWith("image/")) continue;
                        Path img = Path.of(a.path("path").asText(""));
                        if (!img.isAbsolute()) img = testDir.resolve(img);
                        if (Files.isRegularFile(img) && Files.size(img) < 5_000_000) {
                            String name = "screenshot-" + (++attachments[0]) + "-" + project + ".png";
                            ctx.attachArtifact(name, a.path("contentType").asText(), Files.readAllBytes(img));
                            f.attr("screenshot", name);
                        }
                    }
                }
                ctx.report(f);
            }
        }
    }

    private static String stripAnsi(String s) { return s == null ? "" : s.replaceAll("\u001B\\[[;\\d]*m", ""); }
}
