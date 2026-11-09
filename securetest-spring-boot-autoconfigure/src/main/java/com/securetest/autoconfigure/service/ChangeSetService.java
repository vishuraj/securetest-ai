package com.securetest.autoconfigure.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.securetest.autoconfigure.SecureTestProperties;
import com.securetest.autoconfigure.security.ApiException;
import com.securetest.autoconfigure.security.Rbac.Permission;
import com.securetest.autoconfigure.security.SecureTestPrincipal;
import com.securetest.autoconfigure.support.AppContext;
import com.securetest.autoconfigure.support.LocalStore;
import com.securetest.core.spi.ScanRejectedException;
import com.securetest.core.util.AllowlistCommandRunner;
import com.securetest.migration.ChangeSet;
import com.securetest.migration.ChangeSetEngine;

import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Governs every source change made by SecureTest (SRS 7.3, 7.5, 9.2): policy opt-in for apply,
 * approval for security-sensitive and migration changes, rollback point, validation, commit and undo,
 * all audited.
 */
public class ChangeSetService {

    public interface Listener {
        void onChange(ChangeSet cs, String event);
    }

    private final SecureTestProperties props;
    private final AppContext app;
    private final ChangeSetEngine engine;
    private final AuditService audit;
    private final LocalStore store;
    private final Map<String, ChangeSet> sets;
    private final List<Listener> listeners = new ArrayList<>();

    public ChangeSetService(SecureTestProperties props, AppContext app, ChangeSetEngine engine, AuditService audit, LocalStore store) {
        this.props = props;
        this.app = app;
        this.engine = engine;
        this.audit = audit;
        this.store = store;
        this.sets = new ConcurrentHashMap<>(store.load("changesets", new TypeReference<Map<String, ChangeSet>>() { }, LinkedHashMap::new));
        store.register("changesets", () -> new LinkedHashMap<>(sets));
    }

    public void addListener(Listener l) { listeners.add(l); }

    public Path root() {
        return app.sourceRoot().orElseThrow(() -> new ApiException(409, "no_workspace", "No source workspace configured (securetest.workspace.source-root)."));
    }

    public ChangeSet create(String kind, String title, String reference, Map<String, String> edits, Map<String, String> explanations,
                            String explanation, boolean sensitive, String provenance, SecureTestPrincipal p) {
        try {
            ChangeSet cs = engine.create(kind, title, reference, root(), edits, explanations, p.name());
            cs.explanation = explanation;
            cs.securitySensitive = sensitive;
            cs.provenance = provenance;
            sets.put(cs.id, cs);
            store.markDirty("changesets");
            audit.record(p.name(), p.remoteAddress(), kind.toLowerCase() + ".proposed", cs.id, "PREVIEW",
                    Map.of("reference", String.valueOf(reference), "files", String.valueOf(cs.files.size()), "provenance", String.valueOf(provenance)));
            return cs;
        } catch (java.io.IOException e) {
            throw new ApiException(500, "io_error", e.getMessage());
        }
    }

    public ChangeSet get(String id) {
        ChangeSet cs = sets.get(id);
        if (cs == null) throw ApiException.notFound("Change set " + id);
        return cs;
    }

    public List<ChangeSet> list(String kind) {
        return sets.values().stream().filter(c -> kind == null || kind.equals(c.kind))
                .sorted(Comparator.comparing((ChangeSet c) -> c.createdAt).reversed()).toList();
    }

    public String patch(String id, SecureTestPrincipal p) {
        ChangeSet cs = get(id);
        audit.record(p.name(), p.remoteAddress(), "changeset.exported", id, "OK", Map.of());
        return engine.exportPatch(cs);
    }

    public ChangeSet apply(String id, boolean createBranch, boolean allowDirty, SecureTestPrincipal p) {
        ChangeSet cs = get(id);
        if (!props.getSecurity().isAllowAutoRemediation()) {
            throw ApiException.forbidden("Applying changes is disabled by policy (securetest.security.allow-auto-remediation=false). "
                    + "Export the patch and apply it yourself (manual mode).");
        }
        if (!p.has(Permission.REMEDIATE)) throw ApiException.forbidden("REMEDIATE permission required");
        boolean needsApproval = cs.securitySensitive || "MIGRATION".equals(cs.kind);
        if (needsApproval && !p.has(Permission.APPROVE)) {
            throw ApiException.forbidden("This change is security-sensitive or a framework migration: a user with APPROVE permission must apply it.");
        }
        if (app.productionLike()) throw ApiException.forbidden("Source changes are never applied from a production-profile application.");
        cs.approvedBy = p.name();
        cs.approvedAt = Instant.now();
        try {
            engine.apply(cs, root(), new ChangeSetEngine.ApplyOptions(createBranch, allowDirty), p.name());
        } catch (ScanRejectedException e) {
            throw new ApiException(409, "apply_refused", e.getMessage());
        } catch (java.io.IOException e) {
            cs.status = ChangeSet.Status.FAILED;
            cs.log(p.name(), "Apply failed: " + e.getMessage());
            throw new ApiException(500, "io_error", e.getMessage());
        } finally {
            store.markDirty("changesets");
        }
        audit.record(p.name(), p.remoteAddress(), "changeset.applied", id, cs.status.name(),
                Map.of("branch", String.valueOf(cs.gitBranch), "files", String.valueOf(cs.files.size()), "snapshotOfDirty", String.valueOf(cs.snapshotOfDirtyWorkspace)));
        listeners.forEach(l -> l.onChange(cs, "applied"));
        return cs;
    }

    public ChangeSet validate(String id, SecureTestPrincipal p) {
        ChangeSet cs = get(id);
        List<String> cmd = props.getExecution().getValidationCommand();
        if (cmd == null || cmd.isEmpty()) throw ApiException.badRequest("No validation command configured (securetest.execution.validation-command).");
        List<String> command = new ArrayList<>(cmd);
        Path local = root().resolve(command.get(0));
        if (local.toFile().isFile()) command.set(0, local.toString());
        try {
            engine.validate(cs, root(), new AllowlistCommandRunner(new HashSet<>(props.getExecution().getAllowedCommands())), command,
                    Duration.ofMinutes(30), p.name());
        } catch (ScanRejectedException e) {
            throw new ApiException(409, "validation_refused", e.getMessage());
        } catch (Exception e) {
            throw new ApiException(500, "validation_error", e.getMessage());
        } finally {
            store.markDirty("changesets");
        }
        audit.record(p.name(), p.remoteAddress(), "changeset.validated", id, cs.status.name(), Map.of("command", String.join(" ", command)));
        listeners.forEach(l -> l.onChange(cs, "validated"));
        return cs;
    }

    public ChangeSet commit(String id, SecureTestPrincipal p) {
        if (!p.has(Permission.APPROVE)) throw ApiException.forbidden("APPROVE permission required to commit");
        ChangeSet cs = get(id);
        try {
            engine.commit(cs, root(), p.name());
        } catch (ScanRejectedException e) {
            throw new ApiException(409, "commit_refused", e.getMessage());
        } finally {
            store.markDirty("changesets");
        }
        audit.record(p.name(), p.remoteAddress(), "changeset.committed", id, "OK", Map.of("commit", String.valueOf(cs.gitCommit)));
        listeners.forEach(l -> l.onChange(cs, "committed"));
        return cs;
    }

    public ChangeSet undo(String id, SecureTestPrincipal p) {
        if (!p.has(Permission.REMEDIATE)) throw ApiException.forbidden("REMEDIATE permission required");
        ChangeSet cs = get(id);
        try {
            engine.undo(cs, root(), p.name());
        } catch (ScanRejectedException e) {
            throw new ApiException(409, "undo_refused", e.getMessage());
        } catch (java.io.IOException e) {
            throw new ApiException(500, "io_error", e.getMessage());
        } finally {
            store.markDirty("changesets");
        }
        audit.record(p.name(), p.remoteAddress(), "changeset.undone", id, cs.status.name(), Map.of("conflicts", String.valueOf(cs.conflicts.size())));
        listeners.forEach(l -> l.onChange(cs, "undone"));
        return cs;
    }
}
