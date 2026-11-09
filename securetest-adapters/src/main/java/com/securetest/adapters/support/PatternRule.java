package com.securetest.adapters.support;

import com.securetest.core.model.Enums.Confidence;
import com.securetest.core.model.Severity;

import java.nio.file.Path;
import java.util.List;
import java.util.function.Predicate;
import java.util.regex.Pattern;

/**
 * Declarative regex rule used by the built-in static, secrets and IaC scanners.
 *
 * @param multiline match against the whole file instead of line by line
 * @param fixFrom   when set (with fixTo), the finding gets the generic "line-replace" automated fix
 */
public record PatternRule(
        String id,
        String title,
        Severity severity,
        Confidence confidence,
        Predicate<Path> files,
        Pattern pattern,
        boolean multiline,
        String description,
        String remediation,
        List<String> tags,
        String category,
        String fixFrom,
        String fixTo) {

    public static Builder rule(String id, String title, Severity severity) { return new Builder(id, title, severity); }

    public static final class Builder {
        private final String id;
        private final String title;
        private final Severity severity;
        private Confidence confidence = Confidence.MEDIUM;
        private Predicate<Path> files = p -> true;
        private Pattern pattern;
        private boolean multiline;
        private String description = "";
        private String remediation = "";
        private List<String> tags = List.of();
        private String category = "";
        private String fixFrom;
        private String fixTo;

        private Builder(String id, String title, Severity severity) {
            this.id = id;
            this.title = title;
            this.severity = severity;
        }

        public Builder confidence(Confidence c) { confidence = c; return this; }
        public Builder files(Predicate<Path> p) { files = p; return this; }
        public Builder regex(String r) { pattern = Pattern.compile(r); return this; }
        public Builder regexIgnoreCase(String r) { pattern = Pattern.compile(r, Pattern.CASE_INSENSITIVE); return this; }
        public Builder multiline(String r) { pattern = Pattern.compile(r, Pattern.DOTALL); multiline = true; return this; }
        public Builder description(String d) { description = d; return this; }
        public Builder remediation(String r) { remediation = r; return this; }
        public Builder tags(String... t) { tags = List.of(t); return this; }
        public Builder category(String c) { category = c; return this; }
        public Builder fix(String from, String to) { fixFrom = from; fixTo = to; return this; }

        public PatternRule build() {
            return new PatternRule(id, title, severity, confidence, files, pattern, multiline, description, remediation, tags, category, fixFrom, fixTo);
        }
    }
}
