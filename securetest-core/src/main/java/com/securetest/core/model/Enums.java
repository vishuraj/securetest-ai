package com.securetest.core.model;

/** Small enumerations shared across the platform. */
public final class Enums {
    private Enums() { }

    public enum Confidence { HIGH, MEDIUM, LOW }

    public enum FindingStatus { OPEN, IN_PROGRESS, SUPPRESSED, ACCEPTED_RISK, FALSE_POSITIVE, FIXED }

    /** Module state as displayed in the dashboard (SRS 5.2). */
    public enum ModuleState { DISABLED, NOT_CONFIGURED, READY, QUEUED, RUNNING, COMPLETED, FAILED, NEEDS_ATTENTION, UNSUPPORTED }

    public enum JobStatus {
        AWAITING_APPROVAL, QUEUED, RUNNING, COMPLETED, FAILED, CANCELLED, REJECTED;

        public boolean terminal() {
            return this == COMPLETED || this == FAILED || this == CANCELLED || this == REJECTED;
        }
    }

    /** What a scan does to its target. */
    public enum ScanMode {
        /** Reads local data or observes normal responses only. */
        PASSIVE,
        /** Sends crafted / probing traffic to a target. Requires allowlist + confirmation + approval. */
        ACTIVE,
        /** Generates load or consumes significant CPU / memory. Requires confirmation and a resource budget. */
        RESOURCE_INTENSIVE
    }

    /** Where the work actually executes. */
    public enum ExecutionLocation { EMBEDDED, EXTERNAL_TOOL, REMOTE_SERVICE }

    public enum FieldType { TEXT, TEXTAREA, URL, NUMBER, BOOLEAN, SELECT, PATH, SECRET, LIST }

    public enum ControlStatus { PASS, FAIL, PARTIAL, NOT_ASSESSED, NOT_APPLICABLE }
}
