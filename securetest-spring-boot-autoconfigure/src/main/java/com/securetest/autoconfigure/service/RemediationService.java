package com.securetest.autoconfigure.service;

import com.securetest.autoconfigure.security.ApiException;
import com.securetest.autoconfigure.security.SecureTestPrincipal;
import com.securetest.core.model.Enums.FindingStatus;
import com.securetest.core.model.Finding;
import com.securetest.core.spi.FixProvider;
import com.securetest.migration.ChangeSet;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Remediation plans (SRS 7.3): deterministic rule-based fixes produce a diff-first change set; findings without an
 * automated fix get a manual plan. Rules never send code anywhere (SRS 9.2 local/no-AI mode); the optional AI path
 * ({@link #previewAi}) is used only on an explicit per-finding request when securetest.ai is enabled and approved.
 */
public class RemediationService {

    private final FindingService findings;
    private final ChangeSetService changes;
    private final List<FixProvider> providers;
    private final com.securetest.ai.AiRemediator ai;
    private final AuditService audit;

    public RemediationService(FindingService findings, ChangeSetService changes, List<FixProvider> providers,
                              com.securetest.ai.AiRemediator ai, AuditService audit) {
        this.findings = findings;
        this.changes = changes;
        this.providers = providers;
        this.ai = ai;
        this.audit = audit;
        changes.addListener((cs, event) -> {
            if (!"REMEDIATION".equals(cs.kind) || cs.reference == null) return;
            try {
                Finding f = findings.get(cs.reference);
                switch (event) {
                    case "applied" -> findings.update(f.id, FindingStatus.IN_PROGRESS, null, null, "Fix applied via change set " + cs.id, cs.appliedBy);
                    case "undone" -> findings.update(f.id, FindingStatus.OPEN, null, null, "Fix undone (change set " + cs.id + ")", cs.undoneBy);
                    default -> { }
                }
            } catch (ApiException ignored) {
                // finding purged
            }
        });
    }

    public Map<String, Object> aiStatus() { return ai.status(); }

    /** AI-assisted proposal (opt-in). Always security-sensitive: an approver must apply it. */
    public Map<String, Object> previewAi(String findingId, SecureTestPrincipal p) {
        Finding f = findings.get(findingId);
        com.securetest.ai.AiRemediator.Outcome o;
        try {
            o = ai.propose(f, changes.root());
        } catch (java.io.IOException e) {
            throw new ApiException(500, "io_error", e.getMessage());
        }
        Map<String, String> details = new LinkedHashMap<>();
        o.provenance().forEach((k, v) -> details.put(k, String.valueOf(v)));
        details.put("finding", f.id);
        if (!"DISABLED".equals(o.status())) audit.record(p, "ai.remediation.requested", f.id, o.status(), details);
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("findingId", f.id);
        out.put("status", o.status());
        out.put("message", o.message());
        out.put("provenance", o.provenance());
        out.put("aiUsed", !o.provenance().isEmpty());
        if (o.fix() == null) {
            out.put("automated", false);
            return out;
        }
        Map<String, String> edits = new LinkedHashMap<>();
        Map<String, String> why = new LinkedHashMap<>();
        for (FixProvider.FileEdit e : o.fix().edits()) {
            edits.put(e.path(), e.newContent());
            why.put(e.path(), "AI-generated; review carefully");
        }
        ChangeSet cs = changes.create("REMEDIATION", o.fix().title(), f.id, edits, why, o.fix().explanation(), true, o.fix().provenance(), p);
        findings.update(f.id, null, null, null, "AI remediation change set " + cs.id + " proposed (" + o.provenance().get("model") + ")", p.name());
        out.put("automated", true);
        out.put("changeSet", cs);
        out.put("requiresApproval", true);
        out.put("disclaimer", "AI output is an untrusted suggestion. It was range-, secret- and syntax-checked, but you must review the diff and run the tests.");
        return out;
    }

    public Map<String, Object> preview(String findingId, SecureTestPrincipal p) {
        Finding f = findings.get(findingId);
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("findingId", f.id);
        out.put("manualSteps", f.remediation);
        out.put("references", f.references);
        out.put("aiUsed", false);
        out.put("provenance", "SecureTest deterministic rules (no AI, no data leaves this machine)");
        Optional<FixProvider> provider = providers.stream().filter(pr -> pr.supports(f)).findFirst();
        if (provider.isEmpty()) {
            out.put("automated", false);
            out.put("reason", "No automated patch is available for rule " + f.ruleId + ". Follow the manual steps.");
            return out;
        }
        Optional<FixProvider.ProposedFix> fix;
        try {
            fix = provider.get().propose(f, changes.root());
        } catch (java.io.IOException e) {
            throw new ApiException(500, "io_error", e.getMessage());
        }
        if (fix.isEmpty()) {
            out.put("automated", false);
            out.put("reason", "The flagged code has changed since the scan or the version is not declared in this workspace. Re-scan or fix manually.");
            return out;
        }
        Map<String, String> edits = new LinkedHashMap<>();
        Map<String, String> why = new LinkedHashMap<>();
        for (FixProvider.FileEdit e : fix.get().edits()) {
            edits.put(e.path(), e.newContent());
            why.put(e.path(), fix.get().explanation());
        }
        ChangeSet cs = changes.create("REMEDIATION", fix.get().title(), f.id, edits, why, fix.get().explanation(),
                fix.get().securitySensitive(), fix.get().provenance(), p);
        findings.update(f.id, null, null, null, "Remediation change set " + cs.id + " proposed", p.name());
        out.put("automated", true);
        out.put("changeSet", cs);
        out.put("requiresApproval", cs.securitySensitive);
        out.put("disclaimer", "Automated fixes are not guaranteed to be correct. Review the diff and run the tests before committing.");
        return out;
    }
}
