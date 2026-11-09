package com.securetest.core.model;

import java.util.Locale;

/**
 * SecureTest severity / priority scale (SRS 7.1). The same scale is used for the
 * preserved source-tool severity and for the normalized SecureTest priority, but the
 * two values are always stored in separate fields.
 */
public enum Severity {
    CRITICAL(5, "Critical", "Immediate triage; block release where policy requires."),
    HIGH(4, "High", "Urgent remediation; assign owner and due date."),
    MEDIUM(3, "Major / Medium", "Plan remediation in a normal sprint."),
    LOW(2, "Minor / Low", "Backlog and periodic cleanup."),
    INFO(1, "Info", "Review as appropriate.");

    private final int rank;
    private final String label;
    private final String responseTarget;

    Severity(int rank, String label, String responseTarget) {
        this.rank = rank;
        this.label = label;
        this.responseTarget = responseTarget;
    }

    public int rank() { return rank; }
    public String label() { return label; }
    public String responseTarget() { return responseTarget; }

    public boolean atLeast(Severity other) { return rank >= other.rank; }

    public Severity raise() { return this == CRITICAL ? CRITICAL : values()[ordinal() - 1]; }
    public Severity lower() { return this == INFO ? INFO : values()[ordinal() + 1]; }

    /** Lenient parsing of tool severities (e.g. "Major", "BLOCKER", "moderate", "error"). */
    public static Severity parse(String raw) {
        if (raw == null || raw.isBlank()) return INFO;
        String s = raw.trim().toUpperCase(Locale.ROOT);
        return switch (s) {
            case "CRITICAL", "BLOCKER", "EMERGENCY", "ALERT", "SEVERE", "FATAL" -> CRITICAL;
            case "HIGH", "ERROR", "IMPORTANT" -> HIGH;
            case "MEDIUM", "MAJOR", "MODERATE", "WARNING", "WARN" -> MEDIUM;
            case "LOW", "MINOR", "NOTICE", "NEGLIGIBLE" -> LOW;
            default -> INFO;
        };
    }

    public static Severity fromCvss(double score) {
        if (score >= 9.0) return CRITICAL;
        if (score >= 7.0) return HIGH;
        if (score >= 4.0) return MEDIUM;
        if (score > 0.0) return LOW;
        return INFO;
    }
}
