package com.securetest.core.util;

import com.securetest.core.model.Enums.Confidence;
import com.securetest.core.model.Finding;
import com.securetest.core.model.Severity;

import java.util.ArrayList;
import java.util.List;

/**
 * Computes the normalized SecureTest priority from source severity and context (SRS 7.1).
 * <ul>
 *   <li>Source severity is never modified.</li>
 *   <li>A source Critical is never downgraded.</li>
 *   <li>Every adjustment is recorded in {@link Finding#priorityRationale} so users can see why.</li>
 * </ul>
 */
public final class PriorityCalculator {

    /** @param productionEnvironment true when the host runs with a production-like profile */
    public record Context(boolean productionEnvironment, String assetCriticality) { }

    private PriorityCalculator() { }

    public static void apply(Finding f, Context ctx) {
        List<String> why = new ArrayList<>();
        Severity p = f.sourceSeverity == null ? Severity.INFO : f.sourceSeverity;
        why.add("Start from source severity " + p.label() + (f.sourceSeverityRaw != null && !f.sourceSeverityRaw.equalsIgnoreCase(p.name())
                ? " (tool reported \"" + f.sourceSeverityRaw + "\")" : "") + ".");

        if (Boolean.TRUE.equals(f.reachable) && p != Severity.CRITICAL) {
            p = p.raise();
            why.add("Raised one level: vulnerable code is reachable.");
        }
        if ("internet".equalsIgnoreCase(f.exposure) && p.atLeast(Severity.MEDIUM) && p != Severity.CRITICAL) {
            p = p.raise();
            why.add("Raised one level: asset is internet-exposed.");
        }
        if (ctx != null && ctx.productionEnvironment() && p.atLeast(Severity.HIGH) && p != Severity.CRITICAL) {
            why.add("Production environment: kept at " + p.label() + " and flagged for release gate.");
        }
        if ("high".equalsIgnoreCase(ctx == null ? null : ctx.assetCriticality()) && p == Severity.MEDIUM) {
            p = p.raise();
            why.add("Raised one level: application marked as high business criticality.");
        }
        if (f.confidence == Confidence.LOW && p != Severity.CRITICAL && p.atLeast(Severity.LOW)) {
            p = p.lower();
            why.add("Lowered one level: low detection confidence (possible false positive).");
        }
        if (Boolean.FALSE.equals(f.reachable) && p != Severity.CRITICAL && p.atLeast(Severity.LOW)) {
            p = p.lower();
            why.add("Lowered one level: vulnerable code shown to be unreachable.");
        }
        if (f.sourceSeverity == Severity.CRITICAL) {
            p = Severity.CRITICAL; // invariant: never silently downgrade a source Critical
            why.add("Kept Critical: source Critical findings are never downgraded, regardless of confidence or reachability.");
        }
        why.add("Resulting priority: " + p.label() + ". Response target: " + p.responseTarget());
        f.priority = p;
        f.priorityRationale = why;
    }
}
