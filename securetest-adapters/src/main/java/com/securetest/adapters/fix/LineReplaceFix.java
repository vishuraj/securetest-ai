package com.securetest.adapters.fix;

import com.securetest.core.model.Finding;
import com.securetest.core.spi.FixProvider;
import com.securetest.core.util.SourceFiles;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Generic deterministic fix: applies a regex replacement on the exact flagged line(s).
 * Scanners opt in by setting {@code fixId=line-replace} with {@code fix.from}/{@code fix.to} attributes.
 * The line content is re-verified so a stale finding never patches the wrong code.
 */
public class LineReplaceFix implements FixProvider {

    @Override
    public boolean supports(Finding f) {
        return "line-replace".equals(f.fixId) && f.filePath != null && f.lineStart != null && f.attributes.containsKey("fix.from");
    }

    @Override
    public Optional<ProposedFix> propose(Finding f, Path root) throws IOException {
        Path file = SourceFiles.resolveInside(root, f.filePath);
        if (!Files.isRegularFile(file)) return Optional.empty();
        String content = SourceFiles.read(file);
        String nl = content.contains("\r\n") ? "\r\n" : "\n";
        String[] lines = content.split("\r?\n", -1);
        Pattern from = Pattern.compile(f.attributes.get("fix.from"));
        String to = f.attributes.getOrDefault("fix.to", "");
        int start = Math.max(1, f.lineStart);
        int end = Math.min(lines.length, f.lineEnd == null ? start : f.lineEnd);
        boolean changed = false;
        for (int i = start - 1; i < end; i++) {
            Matcher m = from.matcher(lines[i]);
            if (m.find()) {
                lines[i] = m.replaceAll(Matcher.quoteReplacement(to));
                changed = true;
            }
        }
        if (!changed) return Optional.empty(); // code moved or already fixed: refuse to guess
        boolean sensitive = f.category != null && List.of("Cryptography", "Access control", "Secrets", "Configuration").contains(f.category)
                || f.complianceTags.stream().anyMatch(t -> t.startsWith("OWASP-A02") || t.startsWith("OWASP-A01") || t.startsWith("OWASP-A07"));
        return Optional.of(new ProposedFix("Fix " + f.ruleId + " in " + f.filePath + ":" + f.lineStart,
                "Rewrites only the flagged line(s) to use '" + to.trim() + "'. " + (f.remediation == null ? "" : f.remediation),
                List.of(new FileEdit(f.filePath, String.join(nl, lines))), sensitive, "rule-based: line-replace (" + f.ruleId + ")"));
    }
}
