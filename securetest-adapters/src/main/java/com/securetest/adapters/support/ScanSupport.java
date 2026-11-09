package com.securetest.adapters.support;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.securetest.core.model.Finding;
import com.securetest.core.spi.ScanContext;
import com.securetest.core.spi.ScanRejectedException;
import com.securetest.core.util.Hashing;
import com.securetest.core.util.SourceFiles;
import com.securetest.core.util.UnifiedDiff;

import java.io.IOException;
import java.nio.file.Path;
import java.util.List;
import java.util.Locale;
import java.util.function.Predicate;
import java.util.regex.Matcher;

/** Shared helpers for scanners. */
public final class ScanSupport {

    public static final ObjectMapper JSON = new ObjectMapper().configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

    private ScanSupport() { }

    public static Path requireSource(ScanContext ctx) {
        return ctx.sourceRoot().orElseThrow(() -> new ScanRejectedException(
                "No source workspace configured. Set securetest.workspace.source-root (or run the app from its project directory)."));
    }

    public static Predicate<Path> extensions(String... exts) {
        List<String> list = List.of(exts);
        return p -> list.contains(SourceFiles.extension(p));
    }

    /**
     * Runs pattern rules over files and reports findings with redacted, highlighted snippets.
     * @return number of findings
     */
    public static int runRules(ScanContext ctx, Path root, List<Path> files, List<PatternRule> rules, String moduleId, String source)
            throws IOException, InterruptedException {
        int count = 0;
        int i = 0;
        for (Path file : files) {
            ctx.checkCancelled();
            if (++i % 25 == 0) ctx.progress(10 + (int) (80.0 * i / files.size()), "Analyzed " + i + "/" + files.size() + " files");
            List<PatternRule> applicable = rules.stream().filter(r -> r.files().test(file)).toList();
            if (applicable.isEmpty()) continue;
            String content;
            try {
                content = SourceFiles.read(file);
            } catch (IOException e) {
                continue;
            }
            List<String> lines = UnifiedDiff.lines(content);
            String hash = Hashing.sha256(file);
            for (PatternRule rule : applicable) {
                if (rule.multiline()) {
                    Matcher m = rule.pattern().matcher(content);
                    while (m.find()) {
                        int start = lineOf(content, m.start());
                        int end = lineOf(content, m.end());
                        ctx.report(toFinding(rule, moduleId, source, root, file, lines, start, end, hash));
                        count++;
                    }
                } else {
                    for (int ln = 0; ln < lines.size(); ln++) {
                        if (rule.pattern().matcher(lines.get(ln)).find()) {
                            ctx.report(toFinding(rule, moduleId, source, root, file, lines, ln + 1, ln + 1, hash));
                            count++;
                        }
                    }
                }
            }
        }
        return count;
    }

    public static Finding toFinding(PatternRule rule, String moduleId, String source, Path root, Path file, List<String> lines,
                                    int start, int end, String hash) {
        Finding f = Finding.of(moduleId, source, rule.id(), rule.title(), rule.severity())
                .description(rule.description()).remediation(rule.remediation()).confidence(rule.confidence())
                .category(rule.category());
        f.complianceTags.addAll(rule.tags());
        SourceFiles.locate(f, root, file, lines, start, end, hash);
        f.asset = f.filePath;
        if (rule.fixFrom() != null) {
            f.fix("line-replace").attr("fix.from", rule.fixFrom()).attr("fix.to", rule.fixTo());
        }
        return f;
    }

    public static int lineOf(String content, int offset) {
        int line = 1;
        for (int i = 0; i < offset && i < content.length(); i++) if (content.charAt(i) == '\n') line++;
        return line;
    }

    public static String text(JsonNode n, String field) {
        JsonNode v = n == null ? null : n.get(field);
        return v == null || v.isNull() ? null : v.asText();
    }

    public static String lower(String s) { return s == null ? "" : s.toLowerCase(Locale.ROOT); }

    public static String truncate(String s, int max) {
        if (s == null) return null;
        return s.length() <= max ? s : s.substring(0, max) + " …";
    }
}
