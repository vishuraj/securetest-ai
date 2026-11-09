package com.securetest.core.util;

import com.securetest.core.model.Finding;

import java.util.Locale;

/**
 * Stable fingerprints used for deduplication across scans and scanners (SRS 5.6, 8.4).
 * Line numbers are deliberately excluded for code findings so that inserting a line above
 * an issue does not create a "new" finding; the normalized content of the flagged line is used instead.
 */
public final class Fingerprints {
    private Fingerprints() { }

    public static String of(Finding f) {
        StringBuilder key = new StringBuilder();
        if (f.dependency != null && f.dependency.packageName != null) {
            // Same advisory on the same package is one issue, whichever scanner found it.
            String advisory = !f.dependency.aliases.isEmpty() ? f.dependency.aliases.get(0) : f.dependency.advisoryId;
            key.append("dep|").append(f.dependency.packageName).append('|')
               .append(nz(f.dependency.installedVersion)).append('|').append(nz(advisory != null ? advisory : f.ruleId));
        } else {
            key.append(nz(f.moduleId)).append('|').append(nz(f.ruleId)).append('|').append(nz(f.asset)).append('|')
               .append(nz(f.filePath)).append('|');
            String line = highlightedLine(f);
            key.append(line != null ? normalize(line) : (f.lineStart != null ? f.lineStart : nz(f.title)));
        }
        return Hashing.sha256(key.toString()).substring(0, 32);
    }

    private static String highlightedLine(Finding f) {
        return f.snippet.stream().filter(l -> l.highlighted).map(l -> l.text).findFirst().orElse(null);
    }

    private static String normalize(String s) {
        return s.replaceAll("\\s+", " ").trim().toLowerCase(Locale.ROOT);
    }

    private static String nz(Object o) { return o == null ? "" : o.toString(); }
}
