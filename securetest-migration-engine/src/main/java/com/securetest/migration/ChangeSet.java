package com.securetest.migration;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * A reviewable, reversible set of file changes produced by remediation or migration (SRS 7.3, 7.5).
 * File contents live on disk next to the change-set; this object holds metadata only.
 */
public class ChangeSet {

    public enum Status { PREVIEW, APPLIED, VALIDATED, VALIDATION_FAILED, COMMITTED, UNDONE, CONFLICT, FAILED }

    public String id;
    public String kind;              // REMEDIATION | MIGRATION
    public String title;
    public String reference;         // finding id or migration id
    public String explanation;
    public String provenance;        // "rule-based: <provider>" (no AI used unless stated)
    public boolean securitySensitive;
    public Status status = Status.PREVIEW;
    public List<FileChange> files = new ArrayList<>();

    public String createdBy;
    public Instant createdAt;
    public String approvedBy;
    public Instant approvedAt;
    public String appliedBy;
    public Instant appliedAt;
    public String committedBy;
    public Instant committedAt;
    public String undoneBy;
    public Instant undoneAt;

    public String baselineRevision;
    public String originalBranch;
    public String gitBranch;
    public String gitCommit;
    public boolean snapshotOfDirtyWorkspace;
    public Validation validation;
    public List<String> conflicts = new ArrayList<>();
    public List<String> history = new ArrayList<>();

    public void log(String actor, String message) {
        history.add(Instant.now() + "  " + (actor == null ? "system" : actor) + ": " + message);
    }

    public static class FileChange {
        public String path;
        public boolean created;
        public String originalSha256;
        public String proposedSha256;
        public int additions;
        public int deletions;
        public String diff;
        public String explanation;
    }

    public record Validation(String command, int exitCode, boolean passed, String outputTail, Instant at, long durationMs) { }
}
