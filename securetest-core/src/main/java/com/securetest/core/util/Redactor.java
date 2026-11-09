package com.securetest.core.util;

import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Removes secrets and sensitive literals from snippets, evidence and reports (SEC-006, SEC-011, SRS 7.6).
 */
public final class Redactor {

    public static final String MASK = "****REDACTED****";

    private static final List<Pattern> VALUE_PATTERNS = List.of(
            Pattern.compile("AKIA[0-9A-Z]{16}"),
            Pattern.compile("gh[pousr]_[A-Za-z0-9]{30,}"),
            Pattern.compile("xox[baprs]-[A-Za-z0-9-]{10,}"),
            Pattern.compile("eyJ[A-Za-z0-9_-]{8,}\\.eyJ[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}"),
            Pattern.compile("sk-[A-Za-z0-9_-]{20,}"),
            Pattern.compile("AIza[0-9A-Za-z_-]{35}"),
            Pattern.compile("-----BEGIN [A-Z ]*PRIVATE KEY-----[\\s\\S]*?(-----END [A-Z ]*PRIVATE KEY-----|$)")
    );

    /** key = value / key: value / "key": "value" assignments whose key looks sensitive. */
    private static final Pattern ASSIGNMENT = Pattern.compile(
            "(?i)((?:password|passwd|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|private[_-]?key|client[_-]?secret|credential|auth)[\\w.-]*\"?\\s*[:=]\\s*\"?)([^\"'\\s,;}{)]{3,})");

    private static final Pattern AUTH_HEADER = Pattern.compile("(?i)(authorization|cookie|set-cookie|x-api-key)(\\s*:\\s*)([^\\r\\n]+)");

    private static final Pattern URL_CREDENTIALS = Pattern.compile("(?i)([a-z][a-z0-9+.-]*://)([^/\\s:@]+):([^/\\s@]+)@");

    private Redactor() { }

    public static String redact(String text) {
        if (text == null || text.isEmpty()) return text;
        String out = text;
        for (Pattern p : VALUE_PATTERNS) {
            out = p.matcher(out).replaceAll(MASK);
        }
        out = URL_CREDENTIALS.matcher(out).replaceAll("$1$2:" + Matcher.quoteReplacement(MASK) + "@");
        out = AUTH_HEADER.matcher(out).replaceAll("$1$2" + Matcher.quoteReplacement(MASK));
        Matcher m = ASSIGNMENT.matcher(out);
        StringBuilder sb = new StringBuilder();
        while (m.find()) {
            String value = m.group(2);
            String replacement = looksLikePlaceholder(value) ? m.group(0) : m.group(1) + MASK;
            m.appendReplacement(sb, Matcher.quoteReplacement(replacement));
        }
        m.appendTail(sb);
        return sb.toString();
    }

    /** Values like ${DB_PASSWORD}, env://x or "changeme" placeholders are not secrets themselves. */
    private static boolean looksLikePlaceholder(String value) {
        return value.startsWith("${") || value.contains("://") || value.equals(MASK)
                || value.equalsIgnoreCase("null") || value.equalsIgnoreCase("true") || value.equalsIgnoreCase("false");
    }

    /** Masks a credential for display: never echo values back (SRS 6.2). */
    public static String mask(String value) {
        if (value == null || value.isEmpty()) return value;
        if (isReference(value)) return value;
        return "••••••••";
    }

    public static boolean isReference(String value) {
        return value != null && value.matches("^(env|prop|file|secret|vault)://.+");
    }
}
