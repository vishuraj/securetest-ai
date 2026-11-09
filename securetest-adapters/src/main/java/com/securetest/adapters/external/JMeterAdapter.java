package com.securetest.adapters.external;

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
import com.securetest.core.util.SourceFiles;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Apache JMeter adapter: runs a JMX plan in non-GUI mode in a separate process (SRS 5.8). Every host referenced by
 * the plan is checked against the target allowlist before execution.
 */
public class JMeterAdapter implements Scanner {

    public static final String ID = "jmeter";
    private static final Pattern DOMAIN = Pattern.compile("<stringProp name=\"HTTPSampler\\.domain\">([^<]+)</stringProp>");

    @Override
    public ScannerDescriptor descriptor() {
        return ScannerDescriptor.builder(ID, ModuleCatalog.PERFORMANCE, "JMeter test plan")
                .purpose("Executes a JMeter .jmx test plan in non-GUI mode, then reports throughput, percentiles and error rate per sampler "
                        + "against your thresholds. Load is generated outside the application JVM.")
                .access("Executes 'jmeter' in a temporary directory. All HTTP sampler hosts in the plan must be allowlisted.")
                .mode(ScanMode.RESOURCE_INTENSIVE).location(ExecutionLocation.EXTERNAL_TOOL).tool("Apache JMeter", "installed").requiresTarget()
                .duration("Plan duration").resources("Separate JVM; size per plan")
                .prerequisite("JMeter installed; 'jmeter' in securetest.execution.allowed-commands")
                .field(FieldSpec.required("plan", "Test plan (.jmx)", FieldType.PATH, "", "Path relative to the workspace or absolute."))
                .field(FieldSpec.optional("properties", "JMeter properties", FieldType.TEXT, "threads=10,duration=60",
                        "Passed as -Jkey=value (e.g. threads, rampup, duration, host)."))
                .field(FieldSpec.number("p95ThresholdMs", "p95 threshold (ms)", 1000, 1, 600000, ""))
                .field(FieldSpec.number("maxErrorRatePct", "Max error rate (%)", 1, 0, 100, ""))
                .field(FieldSpec.number("timeoutMinutes", "Timeout (minutes)", 30, 1, 480, ""))
                .build();
    }

    @Override
    public List<PreflightCheck> preflight(ScanContext ctx) {
        List<PreflightCheck> out = ExternalTools.toolChecks(ctx, "jmeter", "Install Apache JMeter and add its bin directory to PATH.");
        try {
            Path plan = plan(ctx);
            out.add(Files.isRegularFile(plan) ? PreflightCheck.ok("Test plan", plan.toString()) : PreflightCheck.error("Test plan", "Not found: " + plan));
            if (Files.isRegularFile(plan)) {
                for (String host : hosts(plan, ctx)) {
                    out.add(ctx.targets().isAllowedHost(host) ? PreflightCheck.ok("Allowlist " + host, "authorized")
                            : PreflightCheck.error("Allowlist " + host, "Plan targets a host that is not on the allowlist"));
                }
            }
        } catch (Exception e) {
            out.add(PreflightCheck.error("Test plan", e.getMessage()));
        }
        return out;
    }

    private static Path plan(ScanContext ctx) {
        String p = ctx.option("plan", "");
        Path path = Path.of(p);
        if (!path.isAbsolute() && ctx.sourceRoot().isPresent()) path = SourceFiles.resolveInside(ctx.sourceRoot().get(), p);
        return path;
    }

    private static List<String> hosts(Path plan, ScanContext ctx) throws Exception {
        Map<String, String> props = props(ctx);
        List<String> out = new ArrayList<>();
        Matcher m = DOMAIN.matcher(Files.readString(plan));
        while (m.find()) {
            String h = m.group(1).trim();
            Matcher pm = Pattern.compile("\\$\\{__P\\((\\w+)(,([^)]*))?\\)}").matcher(h);
            if (pm.matches()) h = props.getOrDefault(pm.group(1), pm.group(3) == null ? "" : pm.group(3));
            if (!h.isBlank() && !out.contains(h)) out.add(h);
        }
        return out;
    }

    private static Map<String, String> props(ScanContext ctx) {
        Map<String, String> m = new LinkedHashMap<>();
        for (String kv : ctx.option("properties", "").split(",")) {
            String[] p = kv.split("=", 2);
            if (p.length == 2 && p[0].trim().matches("[\\w.]+")) m.put(p[0].trim(), p[1].trim());
        }
        return m;
    }

    @Override
    public void scan(ScanContext ctx) throws Exception {
        Path plan = plan(ctx);
        for (String h : hosts(plan, ctx)) ctx.targets().requireAllowedHost(h);
        Path dir = Files.createTempDirectory("securetest-jmeter");
        Path jtl = dir.resolve("results.jtl");
        List<String> cmd = new ArrayList<>(List.of("jmeter", "-n", "-t", plan.toString(), "-l", jtl.toString(),
                "-Jjmeter.save.saveservice.output_format=csv", "-j", dir.resolve("jmeter.log").toString()));
        props(ctx).forEach((k, v) -> cmd.add("-J" + k + "=" + v.replaceAll("[\\r\\n&|<>^%\"]", "")));
        ctx.progress(5, "Running JMeter");
        CommandRunner.CommandResult r = ctx.commands().run(cmd, dir, Duration.ofMinutes(ctx.intOption("timeoutMinutes", 30, 1, 480)));
        if (!Files.exists(jtl)) throw new IllegalStateException("JMeter produced no results (exit " + r.exitCode() + ")");
        List<String> lines = Files.readAllLines(jtl);
        ctx.attachArtifact("results.jtl", "text/csv", Files.readAllBytes(jtl));
        if (lines.size() < 2) throw new IllegalStateException("Empty JTL file");
        List<String> header = Arrays.asList(lines.get(0).split(","));
        int iElapsed = header.indexOf("elapsed");
        int iLabel = header.indexOf("label");
        int iSuccess = header.indexOf("success");
        int iTs = header.indexOf("timeStamp");
        Map<String, List<long[]>> byLabel = new LinkedHashMap<>();
        long minTs = Long.MAX_VALUE;
        long maxTs = 0;
        for (String line : lines.subList(1, lines.size())) {
            String[] c = line.split(",", -1);
            if (c.length <= Math.max(iElapsed, Math.max(iLabel, iSuccess))) continue;
            long ts = Long.parseLong(c[iTs]);
            minTs = Math.min(minTs, ts);
            maxTs = Math.max(maxTs, ts);
            byLabel.computeIfAbsent(c[iLabel], k -> new ArrayList<>()).add(new long[] {Long.parseLong(c[iElapsed]), "true".equals(c[iSuccess]) ? 1 : 0});
        }
        double seconds = Math.max(1, (maxTs - minTs) / 1000.0);
        int p95t = ctx.intOption("p95ThresholdMs", 1000, 1, 600000);
        int maxErr = ctx.intOption("maxErrorRatePct", 1, 0, 100);
        List<Map<String, Object>> rows = new ArrayList<>();
        long total = 0;
        long totalErr = 0;
        for (Map.Entry<String, List<long[]>> e : byLabel.entrySet()) {
            long[] lat = e.getValue().stream().mapToLong(x -> x[0]).sorted().toArray();
            long err = e.getValue().stream().filter(x -> x[1] == 0).count();
            total += lat.length;
            totalErr += err;
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("label", e.getKey());
            row.put("samples", lat.length);
            row.put("errorRatePct", Math.round(10000.0 * err / lat.length) / 100.0);
            row.put("throughputRps", Math.round(10 * lat.length / seconds) / 10.0);
            row.put("p50Ms", pct(lat, 50));
            row.put("p95Ms", pct(lat, 95));
            row.put("p99Ms", pct(lat, 99));
            rows.add(row);
            if (pct(lat, 95) > p95t || 100.0 * err / lat.length > maxErr) {
                ctx.report(Finding.of(ModuleCatalog.PERFORMANCE, ID, "JMETER-GATE", "Sampler '" + e.getKey() + "' failed performance gate",
                                100.0 * err / lat.length > maxErr ? Severity.HIGH : Severity.MEDIUM)
                        .description("p95 " + pct(lat, 95) + " ms (threshold " + p95t + "), error rate " + row.get("errorRatePct") + "% (max " + maxErr + "%).")
                        .evidence(row.toString()).asset(e.getKey()).category("Performance").confidence(Confidence.HIGH)
                        .remediation("Investigate the slow/failed sampler; compare with the previous baseline run."));
            }
        }
        Map<String, Object> summary = new LinkedHashMap<>();
        summary.put("requests", total);
        summary.put("errorRatePct", total == 0 ? 0 : Math.round(10000.0 * totalErr / total) / 100.0);
        summary.put("throughputRps", Math.round(10 * total / seconds) / 10.0);
        summary.put("durationSeconds", seconds);
        summary.put("samplers", rows);
        ctx.putResult("jmeterSummary", summary);
    }

    private static long pct(long[] sorted, int p) {
        if (sorted.length == 0) return 0;
        return sorted[Math.max(0, Math.min(sorted.length - 1, (int) Math.ceil(p / 100.0 * sorted.length) - 1))];
    }
}
