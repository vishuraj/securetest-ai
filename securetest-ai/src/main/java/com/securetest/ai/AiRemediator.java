package com.securetest.ai;

import com.securetest.core.model.Finding;
import com.securetest.core.spi.FixProvider;
import com.securetest.core.util.Redactor;
import com.securetest.core.util.SourceFiles;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * AI-assisted remediation with the SRS 9.2 safeguards:
 * <ul>
 *   <li>off unless enabled AND data processing approved by configuration;</li>
 *   <li>only a bounded, redacted code window is sent (never whole repositories, never secrets);</li>
 *   <li>model output is untrusted: the patch is range-checked, secret-checked and bracket-balance-checked;</li>
 *   <li>provenance (provider, model, prompt template, request id, tokens) is attached to every proposal;</li>
 *   <li>every AI patch is security-sensitive, so applying it needs an approver, and it goes through the normal
 *       diff → backup → validate → commit/undo change-set flow.</li>
 * </ul>
 */
public class AiRemediator {

    public static final String TEMPLATE_VERSION = "securetest-fix-v1";

    public record Settings(boolean enabled, boolean dataProcessingApproved, int contextLines, int dailyRequestLimit) { }

    public record Outcome(String status, FixProvider.ProposedFix fix, String message, Map<String, Object> provenance) { }

    static final String SYSTEM = """
            You are a senior application-security engineer proposing a minimal, reviewable patch for one finding \
            reported by a static or dynamic scanner. You see only a window of the file, with line numbers.

            Rules:
            - Change as few lines as possible, and only lines inside the shown window. Keep the original indentation and style.
            - Fix the root cause described by the finding; do not refactor unrelated code or rename public APIs.
            - Prefer the platform's standard secure API (for Java: java.security, Spring Security, parameterized JDBC/JPA).
            - If the fix needs a new import or dependency, use fully-qualified names inside the window when possible and \
            say so in reviewNotes.
            - Never invent credentials or secrets. Text shown as ****REDACTED**** is a removed secret; never reproduce it.
            - If the finding looks like a false positive, or no safe fix fits inside the window, return startLine 0 and \
            endLine 0 with an empty replacement, and explain why.
            """;

    private final ModelClient model;
    private final Settings settings;
    private final AtomicInteger usedToday = new AtomicInteger();
    private volatile LocalDate day = LocalDate.now();

    public AiRemediator(ModelClient model, Settings settings) {
        this.model = model;
        this.settings = settings;
    }

    public Map<String, Object> status() {
        rollDay();
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("enabled", settings.enabled() && settings.dataProcessingApproved());
        m.put("provider", model == null ? null : model.provider());
        m.put("model", model == null ? null : model.model());
        m.put("templateVersion", TEMPLATE_VERSION);
        m.put("contextLines", settings.contextLines());
        m.put("dailyRequestLimit", settings.dailyRequestLimit());
        m.put("usedToday", usedToday.get());
        return m;
    }

    private void rollDay() {
        LocalDate now = LocalDate.now();
        if (!now.equals(day)) {
            day = now;
            usedToday.set(0);
        }
    }

    /** Outcome of an assistant question: status OK, DISABLED, BUDGET, REFUSED, TRUNCATED or ERROR. */
    public record ChatOutcome(String status, String answer, String message, Map<String, Object> provenance) { }

    /**
     * The security assistant: a conversation about findings. Uses the same switch, data-processing approval and daily
     * budget as AI fixes. The caller is responsible for redacting what goes into the system prompt and turns.
     */
    public ChatOutcome chat(String system, List<ModelClient.Turn> turns) {
        if (!settings.enabled() || model == null) return new ChatOutcome("DISABLED", null, "The AI assistant is off (securetest.ai.enabled=false).", Map.of());
        if (!settings.dataProcessingApproved()) {
            return new ChatOutcome("DISABLED", null, "Sending findings to an external AI provider needs approval: set securetest.ai.data-processing-approved=true.", Map.of());
        }
        rollDay();
        if (usedToday.get() >= settings.dailyRequestLimit()) {
            return new ChatOutcome("BUDGET", null, "Daily AI request budget reached (" + settings.dailyRequestLimit() + ").", Map.of());
        }
        usedToday.incrementAndGet();
        ModelClient.ChatReply r = model.chat(system, turns);
        Map<String, Object> prov = new LinkedHashMap<>();
        prov.put("provider", model.provider());
        prov.put("model", r.model());
        prov.put("requestId", r.requestId());
        prov.put("inputTokens", r.inputTokens());
        prov.put("outputTokens", r.outputTokens());
        return new ChatOutcome(r.status(), r.text(), r.detail(), prov);
    }

    public Outcome propose(Finding f, Path root) throws IOException {
        if (!settings.enabled() || model == null) return new Outcome("DISABLED", null, "AI-assisted remediation is disabled (securetest.ai.enabled=false).", Map.of());
        if (!settings.dataProcessingApproved()) {
            return new Outcome("DISABLED", null, "Sending code to an external AI provider needs explicit approval: set securetest.ai.data-processing-approved=true.", Map.of());
        }
        if (f.filePath == null || f.lineStart == null || root == null) {
            return new Outcome("UNSUPPORTED", null, "AI fixes need a finding with a source location inside the workspace.", Map.of());
        }
        Path file = SourceFiles.resolveInside(root, f.filePath);
        if (!Files.isRegularFile(file) || SourceFiles.isSensitive(file)) {
            return new Outcome("UNSUPPORTED", null, "The file is missing or is a sensitive file type; it is never sent to an AI provider.", Map.of());
        }
        rollDay();
        if (usedToday.get() >= settings.dailyRequestLimit()) {
            return new Outcome("BUDGET", null, "Daily AI request budget reached (" + settings.dailyRequestLimit() + "). Raise securetest.ai.daily-request-limit or try tomorrow.", Map.of());
        }

        String content = SourceFiles.read(file);
        String nl = content.contains("\r\n") ? "\r\n" : "\n";
        boolean trailingNl = content.endsWith("\n");
        List<String> lines = new ArrayList<>(List.of(content.split("\r?\n", -1)));
        if (trailingNl) lines.remove(lines.size() - 1);
        int start = Math.max(1, f.lineStart);
        int end = Math.min(lines.size(), f.lineEnd == null ? start : f.lineEnd);
        int from = Math.max(1, start - settings.contextLines());
        int to = Math.min(lines.size(), end + settings.contextLines());

        StringBuilder window = new StringBuilder();
        boolean[] redacted = new boolean[lines.size() + 1];
        for (int i = from; i <= to; i++) {
            String original = lines.get(i - 1);
            String safe = Redactor.redact(original);
            redacted[i] = !safe.equals(original);
            window.append(String.format("%5d | %s%n", i, safe));
        }
        String user = "Finding: " + f.title + "\n"
                + "Rule: " + f.ruleId + " (" + f.source + "), severity " + f.sourceSeverity + "\n"
                + "Flagged lines: " + start + "-" + end + "\n"
                + "Description: " + nz(Redactor.redact(f.description)) + "\n"
                + "Scanner guidance: " + nz(Redactor.redact(f.remediation)) + "\n"
                + "File: " + f.filePath + " (" + SourceFiles.extension(file) + "), lines " + from + "-" + to + " of " + lines.size() + ":\n"
                + "```\n" + window + "```\n"
                + "Return the patch as the structured object.";

        usedToday.incrementAndGet();
        ModelClient.Reply reply = model.complete(SYSTEM, user);
        Map<String, Object> prov = new LinkedHashMap<>();
        prov.put("provider", model.provider());
        prov.put("model", reply.model());
        prov.put("templateVersion", TEMPLATE_VERSION);
        prov.put("requestId", reply.requestId());
        prov.put("inputTokens", reply.inputTokens());
        prov.put("outputTokens", reply.outputTokens());
        prov.put("linesSent", (to - from + 1));
        prov.put("redactedLinesSent", countTrue(redacted, from, to));

        switch (reply.status()) {
            case "REFUSED" -> { return new Outcome("REFUSED", null, "The model declined: " + reply.detail(), prov); }
            case "TRUNCATED", "ERROR" -> { return new Outcome("ERROR", null, reply.detail(), prov); }
            default -> { }
        }
        AiFixResponse r = reply.fix();
        prov.put("confidence", r.confidence);
        if (r.startLine == 0 || r.endLine == 0 || r.replacement == null) {
            return new Outcome("NO_CHANGE", null, "No safe automatic fix: " + nz(r.explanation), prov);
        }
        // ---- validation: model output is untrusted
        if (r.startLine < from || r.endLine > to || r.startLine > r.endLine) {
            return new Outcome("REJECTED", null, "The proposed range " + r.startLine + "-" + r.endLine + " is outside the window that was shown (" + from + "-" + to + ").", prov);
        }
        for (int i = r.startLine; i <= r.endLine; i++) {
            if (redacted[i]) return new Outcome("REJECTED", null, "The patch would touch a line containing a secret; fix it manually and rotate the secret.", prov);
        }
        if (r.replacement.contains(Redactor.MASK) || !Redactor.redact(r.replacement).equals(r.replacement)) {
            return new Outcome("REJECTED", null, "The patch contains a secret-like value; refusing to write it.", prov);
        }
        if (r.replacement.length() > 20_000) return new Outcome("REJECTED", null, "The patch is unexpectedly large.", prov);

        List<String> updated = new ArrayList<>(lines.subList(0, r.startLine - 1));
        String repl = r.replacement.endsWith("\n") ? r.replacement.substring(0, r.replacement.length() - 1) : r.replacement;
        if (!repl.isEmpty()) updated.addAll(List.of(repl.split("\r?\n", -1)));
        updated.addAll(lines.subList(r.endLine, lines.size()));
        String newContent = String.join(nl, updated) + (trailingNl ? nl : "");
        if (newContent.equals(content)) return new Outcome("NO_CHANGE", null, "The model returned the original code unchanged.", prov);
        String ext = SourceFiles.extension(file);
        if (List.of("java", "kt", "js", "ts", "cs", "go", "groovy", "scala").contains(ext) && !balanced(content, newContent)) {
            return new Outcome("REJECTED", null, "The patch changes the bracket balance of the file (likely a syntax error); refusing it.", prov);
        }
        String explanation = nz(r.explanation) + (r.reviewNotes == null || r.reviewNotes.isBlank() ? "" : "\nReview notes: " + r.reviewNotes)
                + "\nAI-generated (" + model.provider() + " / " + reply.model() + ", confidence " + nz(r.confidence)
                + "). Treat as a suggestion: review the diff and run the tests.";
        String provenance = "ai: " + model.provider() + "/" + reply.model() + " template=" + TEMPLATE_VERSION
                + " request=" + reply.requestId() + " tokens=" + reply.inputTokens() + "/" + reply.outputTokens();
        FixProvider.ProposedFix fix = new FixProvider.ProposedFix("AI fix for " + f.ruleId + " in " + f.filePath + ":" + start,
                explanation, List.of(new FixProvider.FileEdit(f.filePath, newContent)), true, provenance);
        return new Outcome("PROPOSED", fix, explanation, prov);
    }

    /** Same net balance of (), [], {} before and after (ignores string contents only roughly, by design). */
    static boolean balanced(String before, String after) {
        return Math.abs(delta(before, '(', ')')) == Math.abs(delta(after, '(', ')'))
                && delta(before, '{', '}') == delta(after, '{', '}')
                && delta(before, '[', ']') == delta(after, '[', ']');
    }

    private static int delta(String s, char open, char close) {
        int d = 0;
        for (char c : s.toCharArray()) {
            if (c == open) d++;
            else if (c == close) d--;
        }
        return d;
    }

    private static int countTrue(boolean[] a, int from, int to) {
        int n = 0;
        for (int i = from; i <= to; i++) if (a[i]) n++;
        return n;
    }

    private static String nz(String s) { return s == null ? "" : s; }
}
