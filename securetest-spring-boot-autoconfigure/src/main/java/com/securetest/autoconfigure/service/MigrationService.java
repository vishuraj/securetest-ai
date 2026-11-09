package com.securetest.autoconfigure.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.securetest.autoconfigure.security.ApiException;
import com.securetest.autoconfigure.security.SecureTestPrincipal;
import com.securetest.autoconfigure.support.LocalStore;
import com.securetest.migration.ChangeSet;
import com.securetest.migration.CompatibilityMatrix;
import com.securetest.migration.MigrationEngine;
import com.securetest.migration.MigrationModels.Assessment;
import com.securetest.migration.MigrationModels.Inventory;
import com.securetest.migration.MigrationModels.MigrationRun;
import com.securetest.migration.MigrationModels.Target;

import java.io.IOException;
import java.time.Instant;
import java.util.Comparator;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/** Migration workflow: Discover → Assess → Plan → Preview → Apply → Validate → Commit/Undo (SRS 7.4, 7.5). */
public class MigrationService {

    private final MigrationEngine engine;
    private final ChangeSetService changes;
    private final AuditService audit;
    private final LocalStore store;
    private final Map<String, MigrationRun> runs;

    public MigrationService(MigrationEngine engine, ChangeSetService changes, AuditService audit, LocalStore store) {
        this.engine = engine;
        this.changes = changes;
        this.audit = audit;
        this.store = store;
        this.runs = new ConcurrentHashMap<>(store.load("migrations", new TypeReference<Map<String, MigrationRun>>() { }, LinkedHashMap::new));
        store.register("migrations", () -> new LinkedHashMap<>(runs));
        changes.addListener((cs, event) -> {
            if (!"MIGRATION".equals(cs.kind) || cs.reference == null) return;
            MigrationRun run = runs.get(cs.reference);
            if (run == null) return;
            run.status = switch (cs.status) {
                case APPLIED -> "APPLIED";
                case VALIDATED -> "VALIDATED";
                case VALIDATION_FAILED -> "VALIDATION_FAILED";
                case COMMITTED -> "COMMITTED";
                case UNDONE -> "UNDONE";
                case CONFLICT -> "CONFLICT";
                default -> run.status;
            };
            run.history.add(Instant.now() + " " + event + " (change set " + cs.id + ")");
            store.markDirty("migrations");
        });
    }

    public Inventory discover() {
        try {
            return engine.discover(changes.root());
        } catch (IOException e) {
            throw new ApiException(500, "io_error", e.getMessage());
        }
    }

    public Map<String, Object> matrix() { return CompatibilityMatrix.asTable(); }

    public MigrationRun assess(int javaVersion, String bootVersion, SecureTestPrincipal p) {
        try {
            Inventory inv = engine.discover(changes.root());
            Target target = new Target(javaVersion, bootVersion);
            Assessment a = engine.assess(changes.root(), target, inv);
            MigrationRun run = new MigrationRun();
            run.id = "M-" + UUID.randomUUID().toString().substring(0, 8);
            a.migrationId = run.id;
            run.assessment = a;
            run.requestedBy = p.name();
            run.repoRef = inv.root + (inv.gitBranch != null ? " @ " + inv.gitBranch : "");
            run.baselineRef = inv.gitHead != null ? inv.gitHead : "workspace snapshot " + Instant.now();
            run.sourceVersions.put("java", String.valueOf(inv.detectedJava));
            run.sourceVersions.put("springBoot", String.valueOf(inv.detectedSpringBoot));
            run.sourceVersions.put("namespace", inv.servletNamespace);
            run.targetVersions.put("java", String.valueOf(javaVersion));
            run.targetVersions.put("springBoot", bootVersion);
            run.status = a.compatibilityErrors.isEmpty() ? "ASSESSED" : "UNSUPPORTED_TARGET";
            run.history.add(Instant.now() + " assessed by " + p.name() + ": " + a.items.size() + " items, risk " + a.riskLevel);
            runs.put(run.id, run);
            store.markDirty("migrations");
            audit.record(p, "migration.assessed", run.id, run.status,
                    Map.of("target", "Java " + javaVersion + " / Spring Boot " + bootVersion, "risk", a.riskLevel));
            return run;
        } catch (IOException e) {
            throw new ApiException(500, "io_error", e.getMessage());
        }
    }

    public MigrationRun get(String id) {
        MigrationRun r = runs.get(id);
        if (r == null) throw ApiException.notFound("Migration " + id);
        return r;
    }

    public List<MigrationRun> list() {
        return runs.values().stream().sorted(Comparator.comparing((MigrationRun r) -> r.createdAt).reversed()).toList();
    }

    public MigrationRun plan(String id, SecureTestPrincipal p) {
        MigrationRun run = get(id);
        if (!run.assessment.compatibilityErrors.isEmpty()) throw ApiException.conflict("Target is unsupported: " + run.assessment.compatibilityErrors);
        run.plan = engine.plan(run.assessment);
        run.status = "PLANNED";
        run.history.add(Instant.now() + " plan generated by " + p.name());
        store.markDirty("migrations");
        audit.record(p, "migration.planned", id, "OK", Map.of("steps", String.valueOf(run.plan.steps.size())));
        return run;
    }

    public ChangeSet preview(String id, List<String> categories, SecureTestPrincipal p) {
        MigrationRun run = get(id);
        if (run.plan == null) plan(id, p);
        Set<String> cats = new HashSet<>();
        for (String c : categories == null || categories.isEmpty() ? MigrationEngine.CATEGORIES : categories) cats.add(MigrationEngine.normalizeCategory(c));
        Map<String, String> explanations = new LinkedHashMap<>();
        Map<String, String> edits;
        try {
            Inventory inv = run.assessment.inventory;
            edits = engine.transform(changes.root(), run.assessment.target, inv, cats, explanations);
        } catch (IOException e) {
            throw new ApiException(500, "io_error", e.getMessage());
        }
        if (edits.isEmpty()) throw ApiException.conflict("No automated changes for the selected categories; remaining items are manual.");
        boolean sensitive = cats.contains(MigrationEngine.CAT_SECURITY);
        ChangeSet cs = changes.create("MIGRATION", "Migrate to Java " + run.assessment.target.javaVersion() + " / Spring Boot "
                        + run.assessment.target.springBootVersion() + " (" + String.join(", ", cats) + ")", run.id, edits, explanations,
                "Automated portion of migration plan " + run.id + ". Manual items remain listed in the assessment.", sensitive,
                "rule-based: securetest-migration-engine", p);
        run.changeSetId = cs.id;
        run.selectedCategories = List.copyOf(cats);
        run.status = "PREVIEWED";
        run.history.add(Instant.now() + " preview " + cs.id + " with " + cs.files.size() + " files by " + p.name());
        store.markDirty("migrations");
        return cs;
    }

    public ChangeSet apply(String id, boolean createBranch, boolean allowDirty, SecureTestPrincipal p) {
        MigrationRun run = get(id);
        if (run.changeSetId == null) throw ApiException.conflict("Generate a preview first.");
        return changes.apply(run.changeSetId, createBranch, allowDirty, p);
    }
}
