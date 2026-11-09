package com.securetest.migration;

import com.securetest.core.spi.CommandRunner;
import com.securetest.core.spi.ScanRejectedException;
import com.securetest.core.util.Hashing;
import com.securetest.core.util.SourceFiles;
import com.securetest.core.util.UnifiedDiff;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/**
 * Diff-first change engine: preview, patch export, apply with rollback point, validate,
 * commit and undo with conflict detection (FR-MIG-003..009, SRS 7.3).
 * <p>Layout under {@code storageDir/<changeSetId>/}: {@code proposed/<path>} and {@code backup/<path>}.</p>
 */
public class ChangeSetEngine {

    private final Path storageDir;
    private final GitWorkspace git;

    public ChangeSetEngine(Path storageDir, GitWorkspace git) {
        this.storageDir = storageDir;
        this.git = git;
    }

    public record ApplyOptions(boolean createBranch, boolean allowDirtyWithSnapshot) { }

    /** Creates a PREVIEW change set. {@code edits} maps relative path to proposed full content. */
    public ChangeSet create(String kind, String title, String reference, Path root, Map<String, String> edits,
                            Map<String, String> explanations, String actor) throws IOException {
        ChangeSet cs = new ChangeSet();
        cs.id = kind.substring(0, 3).toLowerCase() + "-" + UUID.randomUUID().toString().substring(0, 8);
        cs.kind = kind;
        cs.title = title;
        cs.reference = reference;
        cs.createdBy = actor;
        cs.createdAt = Instant.now();
        cs.baselineRevision = git.head(root).orElse("workspace (not a git repository)");
        Path dir = storageDir.resolve(cs.id).resolve("proposed");
        for (Map.Entry<String, String> e : new LinkedHashMap<>(edits).entrySet()) {
            Path file = SourceFiles.resolveInside(root, e.getKey());
            String original = Files.exists(file) ? SourceFiles.read(file) : "";
            if (original.equals(e.getValue())) continue;
            ChangeSet.FileChange fc = new ChangeSet.FileChange();
            fc.path = SourceFiles.relative(root, file);
            fc.created = !Files.exists(file);
            fc.originalSha256 = fc.created ? null : Hashing.sha256(file);
            fc.proposedSha256 = Hashing.sha256(e.getValue().getBytes(StandardCharsets.UTF_8));
            fc.diff = UnifiedDiff.unified(fc.path, original, e.getValue(), 3);
            int[] st = UnifiedDiff.stats(original, e.getValue());
            fc.additions = st[0];
            fc.deletions = st[1];
            fc.explanation = explanations.getOrDefault(e.getKey(), "");
            Path target = SourceFiles.resolveInside(dir, fc.path);
            Files.createDirectories(target.getParent());
            Files.writeString(target, e.getValue(), StandardCharsets.UTF_8);
            cs.files.add(fc);
        }
        cs.log(actor, "Preview created with " + cs.files.size() + " file change(s) against " + cs.baselineRevision);
        return cs;
    }

    public String exportPatch(ChangeSet cs) {
        StringBuilder sb = new StringBuilder();
        sb.append("# SecureTest ").append(cs.kind.toLowerCase()).append(" patch ").append(cs.id).append('\n');
        sb.append("# ").append(cs.title).append('\n');
        sb.append("# Baseline: ").append(cs.baselineRevision).append("  |  apply with: git apply ").append(cs.id).append(".patch\n");
        for (ChangeSet.FileChange f : cs.files) sb.append(f.diff);
        return sb.toString();
    }

    public void apply(ChangeSet cs, Path root, ApplyOptions opts, String actor) throws IOException {
        if (cs.status != ChangeSet.Status.PREVIEW) throw new ScanRejectedException("Change set is " + cs.status + "; only PREVIEW change sets can be applied.");
        // 1. conflict detection: files must still match what was previewed
        List<String> conflicts = new ArrayList<>();
        for (ChangeSet.FileChange f : cs.files) {
            Path file = SourceFiles.resolveInside(root, f.path);
            String current = Files.exists(file) ? Hashing.sha256(file) : null;
            if (f.created ? current != null : !f.originalSha256.equals(current)) conflicts.add(f.path + " changed since the preview was generated");
        }
        if (!conflicts.isEmpty()) {
            cs.conflicts = conflicts;
            cs.status = ChangeSet.Status.CONFLICT;
            cs.log(actor, "Apply refused: " + conflicts);
            return;
        }
        // 2. never overwrite uncommitted user work
        boolean repo = git.isRepository(root);
        if (repo) {
            Set<String> dirty = git.dirtyFiles(root);
            List<String> touched = cs.files.stream().map(f -> f.path).filter(dirty::contains).toList();
            if (!touched.isEmpty() && !opts.allowDirtyWithSnapshot()) {
                throw new ScanRejectedException("Uncommitted changes in " + touched + ". Commit or stash them, or explicitly approve a safe snapshot.");
            }
            cs.snapshotOfDirtyWorkspace = !touched.isEmpty();
            cs.originalBranch = git.branch(root).orElse(null);
            if (opts.createBranch()) {
                String branch = "securetest/" + cs.id;
                GitWorkspace.Result r = git.createBranch(root, branch);
                if (!r.ok()) throw new ScanRejectedException("Could not create branch " + branch + ": " + r.out().trim());
                cs.gitBranch = branch;
                cs.log(actor, "Created branch " + branch + " from " + cs.originalBranch);
            }
        }
        // 3. rollback point
        Path backup = storageDir.resolve(cs.id).resolve("backup");
        for (ChangeSet.FileChange f : cs.files) {
            if (f.created) continue;
            Path src = SourceFiles.resolveInside(root, f.path);
            Path dst = SourceFiles.resolveInside(backup, f.path);
            Files.createDirectories(dst.getParent());
            Files.copy(src, dst, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
        }
        // 4. write
        Path proposed = storageDir.resolve(cs.id).resolve("proposed");
        for (ChangeSet.FileChange f : cs.files) {
            Path target = SourceFiles.resolveInside(root, f.path);
            if (target.getParent() != null) Files.createDirectories(target.getParent());
            Files.copy(SourceFiles.resolveInside(proposed, f.path), target, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
        }
        cs.status = ChangeSet.Status.APPLIED;
        cs.appliedBy = actor;
        cs.appliedAt = Instant.now();
        cs.log(actor, "Applied " + cs.files.size() + " file(s); backup stored as rollback point");
    }

    public void validate(ChangeSet cs, Path root, CommandRunner runner, List<String> command, Duration timeout, String actor)
            throws IOException, InterruptedException {
        if (cs.status != ChangeSet.Status.APPLIED && cs.status != ChangeSet.Status.VALIDATION_FAILED && cs.status != ChangeSet.Status.VALIDATED) {
            throw new ScanRejectedException("Validate after applying the change set.");
        }
        CommandRunner.CommandResult r = runner.run(command, root, timeout);
        String out = (r.stdout() + "\n" + r.stderr()).trim();
        String tail = out.length() > 6000 ? out.substring(out.length() - 6000) : out;
        cs.validation = new ChangeSet.Validation(String.join(" ", command), r.exitCode(), r.success(), tail, Instant.now(), r.durationMs());
        cs.status = r.success() ? ChangeSet.Status.VALIDATED : ChangeSet.Status.VALIDATION_FAILED;
        cs.log(actor, "Validation '" + String.join(" ", command) + "' " + (r.success() ? "passed" : "failed (exit " + r.exitCode() + ")"));
    }

    public void commit(ChangeSet cs, Path root, String actor) {
        if (cs.status != ChangeSet.Status.APPLIED && cs.status != ChangeSet.Status.VALIDATED) {
            throw new ScanRejectedException("Only applied or validated change sets can be committed (status " + cs.status + ").");
        }
        if (!git.isRepository(root)) throw new ScanRejectedException("The workspace is not a git repository; the backup remains the rollback point.");
        GitWorkspace.Result add = git.add(root, cs.files.stream().map(f -> f.path).toList());
        if (!add.ok()) throw new ScanRejectedException("git add failed: " + add.out());
        GitWorkspace.Result c = git.commit(root, "SecureTest " + cs.kind.toLowerCase() + ": " + cs.title + "\n\nChange set " + cs.id
                + "\nApproved-by: " + cs.approvedBy + "\nProvenance: " + cs.provenance);
        if (!c.ok()) throw new ScanRejectedException("git commit failed: " + c.out());
        cs.gitCommit = git.head(root).orElse(null);
        cs.status = ChangeSet.Status.COMMITTED;
        cs.committedBy = actor;
        cs.committedAt = Instant.now();
        cs.log(actor, "Committed " + cs.gitCommit);
    }

    public void undo(ChangeSet cs, Path root, String actor) throws IOException {
        if (cs.status == ChangeSet.Status.UNDONE || cs.status == ChangeSet.Status.PREVIEW) {
            throw new ScanRejectedException("Nothing to undo (status " + cs.status + ").");
        }
        if (cs.gitCommit != null) {
            GitWorkspace.Result r = git.revert(root, cs.gitCommit);
            if (!r.ok()) {
                git.revertAbort(root);
                cs.conflicts = List.of("git revert of " + cs.gitCommit + " conflicts with later changes: " + r.out().trim());
                cs.status = ChangeSet.Status.CONFLICT;
                cs.log(actor, "Undo stopped: revert conflict. Resolve manually with: git revert " + cs.gitCommit);
                return;
            }
            markUndone(cs, actor, "Reverted commit " + cs.gitCommit + " (new commit " + git.head(root).orElse("?") + ")");
            return;
        }
        List<String> conflicts = new ArrayList<>();
        for (ChangeSet.FileChange f : cs.files) {
            Path file = SourceFiles.resolveInside(root, f.path);
            String current = Files.exists(file) ? Hashing.sha256(file) : null;
            if (!f.proposedSha256.equals(current)) conflicts.add(f.path + " was modified after SecureTest applied the change");
        }
        if (!conflicts.isEmpty()) {
            cs.conflicts = conflicts;
            cs.status = ChangeSet.Status.CONFLICT;
            cs.log(actor, "Undo stopped to preserve later edits: " + conflicts + ". Backups are in " + storageDir.resolve(cs.id).resolve("backup"));
            return;
        }
        Path backup = storageDir.resolve(cs.id).resolve("backup");
        for (ChangeSet.FileChange f : cs.files) {
            Path target = SourceFiles.resolveInside(root, f.path);
            if (f.created) {
                Files.deleteIfExists(target);
            } else {
                Files.copy(SourceFiles.resolveInside(backup, f.path), target, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
            }
        }
        markUndone(cs, actor, "Restored " + cs.files.size() + " file(s) from the rollback point"
                + (cs.gitBranch != null ? "; branch " + cs.gitBranch + " left in place (switch back to " + cs.originalBranch + " when ready)" : ""));
    }

    private void markUndone(ChangeSet cs, String actor, String message) {
        cs.status = ChangeSet.Status.UNDONE;
        cs.undoneBy = actor;
        cs.undoneAt = Instant.now();
        cs.conflicts = new ArrayList<>();
        cs.log(actor, message);
    }

    public String proposedContent(ChangeSet cs, String path) throws IOException {
        return Files.readString(SourceFiles.resolveInside(storageDir.resolve(cs.id).resolve("proposed"), path), StandardCharsets.UTF_8);
    }
}
