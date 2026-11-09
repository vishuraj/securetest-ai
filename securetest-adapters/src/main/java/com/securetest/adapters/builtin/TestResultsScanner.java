package com.securetest.adapters.builtin;

import com.securetest.adapters.support.ScanSupport;
import com.securetest.core.model.Enums.Confidence;
import com.securetest.core.model.Enums.FieldType;
import com.securetest.core.model.Finding;
import com.securetest.core.model.ModuleCatalog;
import com.securetest.core.model.Severity;
import com.securetest.core.spi.FieldSpec;
import com.securetest.core.spi.PreflightCheck;
import com.securetest.core.spi.ScanContext;
import com.securetest.core.spi.Scanner;
import com.securetest.core.spi.ScannerDescriptor;
import com.securetest.core.util.SourceFiles;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Imports JUnit/TestNG XML results (Surefire, Failsafe, Gradle) and JaCoCo coverage from the workspace
 * (SRS 5.4). It never runs tests itself; see {@link TestRunnerScanner}.
 */
public class TestResultsScanner implements Scanner {

    public static final String ID = "builtin-test-results";

    @Override
    public ScannerDescriptor descriptor() {
        return ScannerDescriptor.builder(ID, ModuleCatalog.TESTING, "Import test results and coverage")
                .purpose("Reads existing JUnit/TestNG XML reports and JaCoCo coverage produced by your build (target/surefire-reports, "
                        + "target/failsafe-reports, build/test-results, jacoco.xml). Failures, flaky tests and low coverage become findings.")
                .access("Read access to build output inside the source workspace.")
                .requiresSourceRoot()
                .field(FieldSpec.number("minLineCoverage", "Minimum line coverage %", 60, 0, 100, "Coverage below this creates a finding."))
                .field(FieldSpec.optional("reportDir", "Additional report directory", FieldType.PATH, "", "Optional directory with *.xml test reports."))
                .build();
    }

    @Override
    public List<PreflightCheck> preflight(ScanContext ctx) {
        List<PreflightCheck> out = new ArrayList<>();
        if (ctx.sourceRoot().isEmpty()) {
            out.add(PreflightCheck.error("Source workspace", "No source workspace configured."));
            return out;
        }
        try {
            int n = reportFiles(ctx.sourceRoot().get(), ctx.option("reportDir", "")).size();
            out.add(n > 0 ? PreflightCheck.ok("Test reports", n + " report file(s) found")
                    : PreflightCheck.warn("Test reports", "No test reports found yet. Run your build (e.g. mvn test) or use the test runner."));
        } catch (Exception e) {
            out.add(PreflightCheck.warn("Test reports", e.getMessage()));
        }
        return out;
    }

    static List<Path> reportFiles(Path root, String extra) throws Exception {
        List<Path> all = new ArrayList<>();
        // build output directories are excluded from the normal walk, so look for them explicitly
        for (Path dir : buildDirs(root)) {
            for (String sub : List.of("surefire-reports", "failsafe-reports", "test-results")) {
                Path d = dir.resolve(sub);
                if (Files.isDirectory(d)) {
                    try (var s = Files.walk(d, 3)) {
                        s.filter(p -> p.getFileName().toString().matches("TEST-.*\\.xml|.*\\.xml") && !p.getFileName().toString().startsWith("testng-"))
                         .forEach(all::add);
                    }
                }
            }
        }
        if (extra != null && !extra.isBlank() && Files.isDirectory(Path.of(extra))) {
            try (var s = Files.walk(Path.of(extra), 3)) {
                s.filter(p -> p.toString().endsWith(".xml")).forEach(all::add);
            }
        }
        return all;
    }

    static List<Path> buildDirs(Path root) throws Exception {
        List<Path> dirs = new ArrayList<>();
        for (Path buildFile : SourceFiles.walk(root, p -> {
            String n = p.getFileName().toString();
            return n.equals("pom.xml") || n.startsWith("build.gradle");
        }, 500)) {
            Path parent = buildFile.getParent();
            if (Files.isDirectory(parent.resolve("target"))) dirs.add(parent.resolve("target"));
            if (Files.isDirectory(parent.resolve("build"))) dirs.add(parent.resolve("build"));
        }
        return dirs;
    }

    private static DocumentBuilder parser() throws Exception {
        DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
        f.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        f.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
        f.setFeature("http://xml.org/sax/features/external-general-entities", false);
        f.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        f.setExpandEntityReferences(false);
        f.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        f.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
        DocumentBuilder b = f.newDocumentBuilder();
        b.setEntityResolver((publicId, systemId) -> new org.xml.sax.InputSource(new java.io.StringReader("")));
        return b;
    }

    private static final Pattern FRAME = Pattern.compile("at ([\\w.$]+)\\.([\\w$<>]+)\\(([\\w$]+\\.java):(\\d+)\\)");

    @Override
    public void scan(ScanContext ctx) throws Exception {
        Path root = ScanSupport.requireSource(ctx);
        importResults(ctx, root, ctx.option("reportDir", ""), ctx.intOption("minLineCoverage", 60, 0, 100), ID);
    }

    static void importResults(ScanContext ctx, Path root, String extraDir, int minCoverage, String source) throws Exception {
        List<Path> files = reportFiles(root, extraDir);
        ctx.progress(10, "Parsing " + files.size() + " report files");
        DocumentBuilder parser = parser();
        int tests = 0, failures = 0, errors = 0, skipped = 0, flaky = 0;
        double time = 0;
        List<Map<String, Object>> cases = new ArrayList<>();
        for (Path file : files) {
            ctx.checkCancelled();
            Document doc;
            try {
                doc = parser.parse(file.toFile());
            } catch (Exception e) {
                continue;
            }
            NodeList tcs = doc.getElementsByTagName("testcase");
            if (tcs.getLength() == 0) continue;
            for (int i = 0; i < tcs.getLength(); i++) {
                Element tc = (Element) tcs.item(i);
                tests++;
                String cls = tc.getAttribute("classname");
                String name = tc.getAttribute("name");
                double t = parse(tc.getAttribute("time"));
                time += t;
                String status = "PASSED";
                Element problem = null;
                if (child(tc, "failure") != null) { status = "FAILED"; failures++; problem = child(tc, "failure"); }
                else if (child(tc, "error") != null) { status = "ERROR"; errors++; problem = child(tc, "error"); }
                else if (child(tc, "skipped") != null) { status = "SKIPPED"; skipped++; }
                boolean isFlaky = child(tc, "flakyFailure") != null || child(tc, "flakyError") != null;
                if (isFlaky) { flaky++; status = "FLAKY"; }
                Map<String, Object> row = new LinkedHashMap<>();
                row.put("class", cls);
                row.put("name", name);
                row.put("status", status);
                row.put("time", t);
                cases.add(row);
                if (problem != null || isFlaky) {
                    Element p = problem != null ? problem : (child(tc, "flakyFailure") != null ? child(tc, "flakyFailure") : child(tc, "flakyError"));
                    String message = p.getAttribute("message");
                    String trace = p.getTextContent();
                    Finding f = Finding.of(ModuleCatalog.TESTING, source, isFlaky ? "TEST-FLAKY" : "TEST-" + status,
                                    (isFlaky ? "Flaky test: " : "Test " + status.toLowerCase() + ": ") + simple(cls) + "." + name,
                                    isFlaky ? Severity.MEDIUM : Severity.HIGH)
                            .description((message == null || message.isBlank() ? p.getAttribute("type") : message))
                            .evidence(ScanSupport.truncate(trace, 4000))
                            .remediation(isFlaky ? "The test failed and then passed on rerun. Look for timing, ordering or shared-state dependencies."
                                    : "Fix the code or the test. Review the stack trace in the evidence section.")
                            .category("Test result").confidence(Confidence.HIGH).asset(cls).tags("ISO27001-A.8.29", "SOC2-CC8.1");
                    locateTest(f, root, cls, trace);
                    ctx.report(f);
                }
            }
        }
        Map<String, Object> summary = new LinkedHashMap<>();
        summary.put("reportFiles", files.size());
        summary.put("tests", tests);
        summary.put("passed", tests - failures - errors - skipped);
        summary.put("failures", failures);
        summary.put("errors", errors);
        summary.put("skipped", skipped);
        summary.put("flaky", flaky);
        summary.put("durationSeconds", Math.round(time * 10) / 10.0);
        summary.put("passRate", tests == 0 ? null : Math.round(1000.0 * (tests - failures - errors - skipped) / Math.max(1, tests - skipped)) / 10.0);
        ctx.putResult("testSummary", summary);
        cases.sort(Comparator.comparingDouble(m -> -((Double) m.get("time"))));
        ctx.putResult("slowestTests", cases.subList(0, Math.min(10, cases.size())));
        ctx.putResult("testCases", cases.size() > 2000 ? cases.subList(0, 2000) : cases);
        ctx.progress(70, "Reading coverage");
        coverage(ctx, root, parser, minCoverage, source);
    }

    private static void coverage(ScanContext ctx, Path root, DocumentBuilder parser, int min, String source) throws Exception {
        List<Path> reports = new ArrayList<>();
        for (Path dir : buildDirs(root)) {
            for (String rel : List.of("site/jacoco/jacoco.xml", "site/jacoco-aggregate/jacoco.xml", "reports/jacoco/test/jacocoTestReport.xml")) {
                if (Files.isRegularFile(dir.resolve(rel))) reports.add(dir.resolve(rel));
            }
        }
        if (reports.isEmpty()) {
            ctx.log("No JaCoCo report found (add jacoco-maven-plugin to collect coverage)");
            return;
        }
        long covered = 0, missed = 0, bCovered = 0, bMissed = 0;
        List<Map<String, Object>> packages = new ArrayList<>();
        for (Path r : reports) {
            Document doc = parser.parse(r.toFile());
            Element report = doc.getDocumentElement();
            for (Element c : children(report, "counter")) {
                if (c.getAttribute("type").equals("LINE")) { covered += (long) parse(c.getAttribute("covered")); missed += (long) parse(c.getAttribute("missed")); }
                if (c.getAttribute("type").equals("BRANCH")) { bCovered += (long) parse(c.getAttribute("covered")); bMissed += (long) parse(c.getAttribute("missed")); }
            }
            for (Element pkg : children(report, "package")) {
                for (Element c : children(pkg, "counter")) {
                    if (!c.getAttribute("type").equals("LINE")) continue;
                    double cv = parse(c.getAttribute("covered"));
                    double ms = parse(c.getAttribute("missed"));
                    packages.add(Map.of("package", pkg.getAttribute("name").replace('/', '.'), "lineCoverage", cv + ms == 0 ? 0 : Math.round(1000 * cv / (cv + ms)) / 10.0));
                }
            }
        }
        double line = covered + missed == 0 ? 0 : 100.0 * covered / (covered + missed);
        double branch = bCovered + bMissed == 0 ? 0 : 100.0 * bCovered / (bCovered + bMissed);
        Map<String, Object> cov = new LinkedHashMap<>();
        cov.put("lineCoverage", Math.round(line * 10) / 10.0);
        cov.put("branchCoverage", Math.round(branch * 10) / 10.0);
        cov.put("packages", packages);
        ctx.putResult("coverage", cov);
        if (line < min) {
            ctx.report(Finding.of(ModuleCatalog.TESTING, source, "COVERAGE-LOW", String.format("Line coverage %.1f%% is below the %d%% threshold", line, min), Severity.MEDIUM)
                    .description("Low coverage means changes (including security fixes and migrations) cannot be validated automatically.")
                    .remediation("Add tests for the least covered packages listed on the Testing page.")
                    .category("Coverage").confidence(Confidence.HIGH).asset(root.getFileName() == null ? "workspace" : root.getFileName().toString())
                    .tags("ISO27001-A.8.29", "SOC2-CC8.1"));
        }
    }

    private static void locateTest(Finding f, Path root, String cls, String trace) {
        if (trace == null) return;
        Matcher m = FRAME.matcher(trace);
        String simple = simple(cls);
        while (m.find()) {
            String frameClass = m.group(1);
            if (!frameClass.equals(cls) && !frameClass.startsWith(cls + "$")) continue;
            String rel = cls.replace('.', '/').replaceAll("\\$.*$", "") + ".java";
            for (String base : List.of("src/test/java/", "")) {
                try {
                    List<Path> hits = SourceFiles.walk(root, p -> p.toString().replace('\\', '/').endsWith(base + rel), 1);
                    if (!hits.isEmpty()) {
                        Path file = hits.get(0);
                        int line = Integer.parseInt(m.group(4));
                        SourceFiles.locate(f, root, file, com.securetest.core.util.UnifiedDiff.lines(SourceFiles.read(file)), line, line, null);
                        return;
                    }
                } catch (Exception ignored) {
                    // best effort
                }
            }
        }
        f.asset = simple;
    }

    private static String simple(String cls) { return cls.substring(cls.lastIndexOf('.') + 1); }

    private static Element child(Element e, String name) {
        for (Node n = e.getFirstChild(); n != null; n = n.getNextSibling()) {
            if (n instanceof Element el && el.getTagName().equals(name)) return el;
        }
        return null;
    }

    private static List<Element> children(Element e, String name) {
        List<Element> out = new ArrayList<>();
        for (Node n = e.getFirstChild(); n != null; n = n.getNextSibling()) {
            if (n instanceof Element el && el.getTagName().equals(name)) out.add(el);
        }
        return out;
    }

    private static double parse(String s) {
        try { return s == null || s.isBlank() ? 0 : Double.parseDouble(s.replace(",", "")); } catch (NumberFormatException e) { return 0; }
    }
}
