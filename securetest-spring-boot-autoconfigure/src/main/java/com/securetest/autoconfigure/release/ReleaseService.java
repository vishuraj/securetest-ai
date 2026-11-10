package com.securetest.autoconfigure.release;

import com.fasterxml.jackson.core.type.TypeReference;
import com.securetest.autoconfigure.pentest.EngagementService;
import com.securetest.autoconfigure.security.ApiException;
import com.securetest.autoconfigure.security.Rbac.Role;
import com.securetest.autoconfigure.security.SecureTestPrincipal;
import com.securetest.autoconfigure.service.ComplianceService;
import com.securetest.autoconfigure.service.FindingService;
import com.securetest.autoconfigure.service.ModuleService;
import com.securetest.autoconfigure.service.StatusService;
import com.securetest.autoconfigure.support.LocalStore;
import com.securetest.core.model.Enums.ControlStatus;
import com.securetest.core.model.Enums.ModuleState;
import com.securetest.core.model.ModuleCatalog;
import com.securetest.core.model.Severity;

import java.time.Instant;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Release readiness (quality + security sign-off): live checks over tests, code quality, vulnerabilities, the release gate,
 * performance, compliance and pentest results, a custom checklist, waivers with reasons, and role-based sign-offs. When a
 * release is approved its check results are frozen as the release record.
 */
public class ReleaseService {

    public static final List<String> CHECKS = List.of("GATE", "VULNERABILITIES", "CODE_QUALITY", "TESTS", "PERFORMANCE", "COMPLIANCE", "PENTEST");

    public static class Release {
        public String id;
        public String version;
        public String name;
        public LocalDate targetDate;
        /** DRAFT → APPROVED → RELEASED, or REJECTED. */
        public String status = "DRAFT";
        public List<String> requiredChecks = new ArrayList<>();
        public List<String> requiredSignoffs = new ArrayList<>(List.of("QA", "SECURITY", "OWNER"));
        public String engagementId;
        public Map<String, Waiver> waivers = new LinkedHashMap<>();
        public List<Item> items = new ArrayList<>();
        public List<Signoff> signoffs = new ArrayList<>();
        /** Check results frozen when the release was approved. */
        public List<Check> approvedChecks;
        public String createdBy;
        public Instant createdAt;
        public Instant approvedAt;
        public Instant releasedAt;
    }

    public record Check(String id, String title, String state, String detail, boolean required) { }

    public static class Waiver {
        public String reason;
        public String by;
        public Instant at;
    }

    public static class Item {
        public String id;
        public String title;
        public boolean done;
        public String by;
        public Instant at;
    }

    public static class Signoff {
        public String role;
        public String user;
        public String decision;
        public String comment;
        public Instant at;
    }

    public record ReleaseRequest(String version, String name, LocalDate targetDate, List<String> requiredChecks, List<String> requiredSignoffs,
                                 String engagementId, List<String> items) { }

    private final LocalStore store;
    private final StatusService status;
    private final FindingService findings;
    private final ModuleService modules;
    private final ComplianceService compliance;
    private final EngagementService engagements;
    private final Map<String, Release> releases;
    private final AtomicInteger counter = new AtomicInteger();

    public ReleaseService(LocalStore store, StatusService status, FindingService findings, ModuleService modules, ComplianceService compliance,
                          EngagementService engagements) {
        this.store = store;
        this.status = status;
        this.findings = findings;
        this.modules = modules;
        this.compliance = compliance;
        this.engagements = engagements;
        this.releases = new ConcurrentHashMap<>(store.load("releases", new TypeReference<Map<String, Release>>() { }, LinkedHashMap::new));
        releases.keySet().forEach(id -> {
            try {
                counter.set(Math.max(counter.get(), Integer.parseInt(id.substring(4))));
            } catch (RuntimeException ignored) {
                // other id format
            }
        });
        store.register("releases", () -> new LinkedHashMap<>(releases));
    }

    public List<Release> list() {
        return releases.values().stream().sorted(Comparator.comparing((Release r) -> r.createdAt).reversed()).toList();
    }

    public Release get(String id) {
        Release r = releases.get(id);
        if (r == null) throw ApiException.notFound("Release " + id);
        return r;
    }

    public synchronized Release create(ReleaseRequest q, String actor) {
        if (q.version() == null || q.version().isBlank()) throw ApiException.badRequest("version is required");
        Release r = new Release();
        r.id = String.format("REL-%04d", counter.incrementAndGet());
        r.version = clip(q.version(), 60);
        r.name = clip(q.name(), 200);
        r.targetDate = q.targetDate();
        r.engagementId = q.engagementId();
        if (r.engagementId != null) engagements.get(r.engagementId);
        if (q.requiredChecks() != null) {
            for (String c : q.requiredChecks()) if (!CHECKS.contains(c)) throw ApiException.badRequest("Unknown check " + c + "; use " + CHECKS);
            r.requiredChecks = new ArrayList<>(q.requiredChecks());
        } else {
            r.requiredChecks = new ArrayList<>(List.of("GATE", "VULNERABILITIES"));
            if (modules.isEnabled(ModuleCatalog.TESTING)) r.requiredChecks.add("TESTS");
            if (modules.isEnabled(ModuleCatalog.CODE_QUALITY)) r.requiredChecks.add("CODE_QUALITY");
            if (r.engagementId != null) r.requiredChecks.add("PENTEST");
        }
        if (q.requiredSignoffs() != null) {
            for (String s : q.requiredSignoffs()) Role.valueOf(s.toUpperCase(Locale.ROOT));
            r.requiredSignoffs = q.requiredSignoffs().stream().map(s -> s.toUpperCase(Locale.ROOT)).distinct().toList();
        }
        if (q.items() != null) {
            q.items().stream().filter(t -> t != null && !t.isBlank()).limit(50).forEach(t -> {
                Item i = new Item();
                i.id = "I-" + (r.items.size() + 1);
                i.title = clip(t, 300);
                r.items.add(i);
            });
        }
        r.createdBy = actor;
        r.createdAt = Instant.now();
        releases.put(r.id, r);
        store.markDirty("releases");
        return r;
    }

    /** Live evaluation of every check. A waived check counts as passed. */
    public List<Check> evaluate(Release r) {
        if (r.approvedChecks != null) return r.approvedChecks;
        List<Check> out = new ArrayList<>();
        Map<String, Object> gate = status.gate();
        out.add(check(r, "GATE", "Release gate", "PASS".equals(gate.get("status")) ? "PASS" : "FAIL",
                "PASS".equals(gate.get("status")) ? "Within the policy thresholds" : String.join("; ", castList(gate.get("reasons")))));
        Map<Severity, Integer> vuln = findings.openCounts(ModuleCatalog.VULNERABILITY);
        int critVuln = vuln.getOrDefault(Severity.CRITICAL, 0);
        out.add(check(r, "VULNERABILITIES", "No open critical vulnerabilities", !modules.isEnabled(ModuleCatalog.VULNERABILITY) && critVuln == 0 ? "NOT_RUN"
                : critVuln == 0 ? "PASS" : "FAIL", critVuln + " critical, " + vuln.getOrDefault(Severity.HIGH, 0) + " high open"));
        out.add(moduleCheck(r, "CODE_QUALITY", "Code quality: no open high or critical issues", ModuleCatalog.CODE_QUALITY));
        out.add(moduleCheck(r, "TESTS", "Tests pass", ModuleCatalog.TESTING));
        out.add(moduleCheck(r, "PERFORMANCE", "Performance test run without high or critical issues", ModuleCatalog.PERFORMANCE));
        long failed = compliance.evaluate().stream().filter(c -> c.status() == ControlStatus.FAIL).count();
        out.add(check(r, "COMPLIANCE", "No failing compliance controls", !modules.isEnabled(ModuleCatalog.COMPLIANCE) ? "NOT_RUN" : failed == 0 ? "PASS" : "FAIL",
                failed + " control(s) failing"));
        if (r.engagementId == null) {
            out.add(check(r, "PENTEST", "Pentest completed", "NOT_RUN", "No engagement linked"));
        } else {
            var e = engagements.get(r.engagementId);
            long open = engagements.findingsOf(e.id).stream().filter(f -> f.isOpen() && (f.priority == null ? f.sourceSeverity : f.priority).atLeast(Severity.HIGH)).count();
            out.add(check(r, "PENTEST", "Pentest " + e.id + " completed with no open high/critical findings",
                    "COMPLETED".equals(e.status) && open == 0 ? "PASS" : "FAIL", "Engagement " + e.status.toLowerCase(Locale.ROOT) + ", " + open + " open high/critical"));
        }
        return out;
    }

    private Check moduleCheck(Release r, String id, String title, String module) {
        if (!modules.isEnabled(module)) return check(r, id, title, "NOT_RUN", "Module is off");
        ModuleState s = status.state(module);
        Map<Severity, Integer> open = findings.openCounts(module);
        int bad = open.getOrDefault(Severity.CRITICAL, 0) + open.getOrDefault(Severity.HIGH, 0);
        String state = s == ModuleState.READY || s == ModuleState.DISABLED ? "NOT_RUN" : s == ModuleState.FAILED || bad > 0 ? "FAIL"
                : s == ModuleState.COMPLETED ? "PASS" : "NOT_RUN";
        return check(r, id, title, state, s.name().toLowerCase(Locale.ROOT).replace('_', ' ') + ", " + bad + " high/critical open");
    }

    private Check check(Release r, String id, String title, String state, String detail) {
        Waiver w = r.waivers.get(id);
        boolean required = r.requiredChecks.contains(id);
        if (w != null && !"PASS".equals(state)) return new Check(id, title, "WAIVED", detail + " — waived by " + w.by + ": " + w.reason, required);
        return new Check(id, title, state, detail, required);
    }

    /** Ready when every required check passed (or was waived) and every checklist item is done. */
    public Map<String, Object> readiness(Release r) {
        List<Check> checks = evaluate(r);
        List<String> blockers = new ArrayList<>();
        checks.stream().filter(Check::required).filter(c -> !c.state().equals("PASS") && !c.state().equals("WAIVED"))
                .forEach(c -> blockers.add(c.title() + " (" + c.state().toLowerCase(Locale.ROOT).replace('_', ' ') + ")"));
        r.items.stream().filter(i -> !i.done).forEach(i -> blockers.add("Checklist: " + i.title));
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("ready", blockers.isEmpty());
        m.put("blockers", blockers);
        m.put("checks", checks);
        List<String> missing = r.requiredSignoffs.stream().filter(role -> r.signoffs.stream().noneMatch(s -> s.role.equals(role) && "APPROVE".equals(s.decision))).toList();
        m.put("missingSignoffs", missing);
        return m;
    }

    public synchronized Release waive(String id, String checkId, String reason, String actor) {
        Release r = open(id);
        if (!CHECKS.contains(checkId)) throw ApiException.badRequest("Unknown check " + checkId);
        if (reason == null || reason.isBlank()) throw ApiException.badRequest("A reason is required to waive a check");
        Waiver w = new Waiver();
        w.reason = clip(reason, 1000);
        w.by = actor;
        w.at = Instant.now();
        r.waivers.put(checkId, w);
        store.markDirty("releases");
        return r;
    }

    public synchronized Release tick(String id, String itemId, boolean done, String actor) {
        Release r = open(id);
        Item i = r.items.stream().filter(x -> x.id.equals(itemId)).findFirst().orElseThrow(() -> ApiException.notFound("Item " + itemId));
        i.done = done;
        i.by = actor;
        i.at = Instant.now();
        store.markDirty("releases");
        return r;
    }

    /** A sign-off by a holder of the role (admins may sign any role). Once every required role approved, the release is APPROVED. */
    public synchronized Release signoff(String id, String role, String decision, String comment, SecureTestPrincipal p) {
        Release r = open(id);
        String rl = role == null ? "" : role.toUpperCase(Locale.ROOT);
        if (!r.requiredSignoffs.contains(rl)) throw ApiException.badRequest("This release needs sign-off from " + r.requiredSignoffs);
        if (!p.roles().contains(Role.valueOf(rl)) && !p.roles().contains(Role.ADMIN)) throw ApiException.forbidden("Only a " + rl + " can sign off as " + rl);
        if (!"APPROVE".equals(decision) && !"REJECT".equals(decision)) throw ApiException.badRequest("decision must be APPROVE or REJECT");
        Map<String, Object> ready = readiness(r);
        if ("APPROVE".equals(decision) && !Boolean.TRUE.equals(ready.get("ready"))) {
            throw ApiException.conflict("Not ready to approve: " + String.join("; ", castList(ready.get("blockers"))));
        }
        r.signoffs.removeIf(s -> s.role.equals(rl));
        Signoff s = new Signoff();
        s.role = rl;
        s.user = p.name();
        s.decision = decision;
        s.comment = clip(comment, 2000);
        s.at = Instant.now();
        r.signoffs.add(s);
        if ("REJECT".equals(decision)) {
            r.status = "REJECTED";
        } else if (castList(readiness(r).get("missingSignoffs")).isEmpty()) {
            r.approvedChecks = evaluate(r); // freeze the evidence
            r.status = "APPROVED";
            r.approvedAt = Instant.now();
        }
        store.markDirty("releases");
        return r;
    }

    public synchronized Release markReleased(String id) {
        Release r = get(id);
        if (!"APPROVED".equals(r.status)) throw ApiException.conflict("Only an approved release can be marked released");
        r.status = "RELEASED";
        r.releasedAt = Instant.now();
        store.markDirty("releases");
        return r;
    }

    /** Reopens a rejected release for another round, keeping its history of sign-offs. */
    public synchronized Release reopen(String id) {
        Release r = get(id);
        if (!"REJECTED".equals(r.status)) throw ApiException.conflict("Only a rejected release can be reopened");
        r.status = "DRAFT";
        r.signoffs.removeIf(s -> "REJECT".equals(s.decision));
        store.markDirty("releases");
        return r;
    }

    private Release open(String id) {
        Release r = get(id);
        if (!"DRAFT".equals(r.status)) throw ApiException.conflict("The release is " + r.status.toLowerCase(Locale.ROOT));
        return r;
    }

    @SuppressWarnings("unchecked")
    private static List<String> castList(Object o) {
        return o instanceof List<?> l ? (List<String>) l : List.of();
    }

    private static String clip(String s, int max) {
        return s == null ? null : s.length() > max ? s.substring(0, max) : s;
    }
}
