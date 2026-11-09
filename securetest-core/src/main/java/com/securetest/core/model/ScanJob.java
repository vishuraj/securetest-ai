package com.securetest.core.model;

import com.securetest.core.model.Enums.JobStatus;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** A scan request and its lifecycle (SRS 12 ScanJob). Secret values are never stored here. */
public class ScanJob {
    public String id;
    public String moduleId;
    public String scannerId;
    public String scannerName;
    public String toolVersion;
    public String profileName;
    public String requestedBy;
    public String approvedBy;
    public String idempotencyKey;
    public String correlationId;
    public JobStatus status = JobStatus.QUEUED;
    public Instant createdAt;
    public Instant startedAt;
    public Instant endedAt;
    public int progress;
    public String progressMessage;
    /** Non-secret options; secret fields are shown as "••••" or as their reference. */
    public Map<String, String> options = new LinkedHashMap<>();
    public List<String> log = new ArrayList<>();
    public int findingsCount;
    public Map<String, Integer> severityCounts = new LinkedHashMap<>();
    public String error;
    public String executionLocation;
    public String workerId = "embedded";
    /** Structured, scanner-specific results (performance stats, test summary, inventory...). */
    public Map<String, Object> results = new LinkedHashMap<>();
    public List<String> artifacts = new ArrayList<>();

    public Long getDurationMs() {
        if (startedAt == null) return null;
        Instant end = endedAt != null ? endedAt : Instant.now();
        return Duration.between(startedAt, end).toMillis();
    }

    public synchronized void appendLog(String line) {
        log.add(Instant.now() + "  " + line);
        if (log.size() > 500) log.remove(0);
    }
}
