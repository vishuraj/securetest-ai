package com.securetest.controlplane.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.securetest.controlplane.store.FindingStore;
import com.securetest.controlplane.store.FindingStore.Existing;
import com.securetest.controlplane.store.InventoryStore;
import com.securetest.controlplane.store.JobStore.Job;
import com.securetest.core.model.Enums.FindingStatus;
import com.securetest.core.model.Finding;
import com.securetest.core.model.Severity;
import com.securetest.core.util.Fingerprints;
import com.securetest.core.util.PriorityCalculator;
import com.securetest.core.util.Redactor;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.EnumMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Normalizes findings posted by workers and merges them into the tenant's central finding store
 * (de-duplication by fingerprint, occurrence counting, regression detection, auto-close of fixed issues).
 */
@Service
public class FindingIngestService {

    public record Result(int accepted, Map<Severity, Integer> byPriority, int autoClosed) { }

    private final FindingStore findings;
    private final InventoryStore inventory;
    private final ObjectMapper mapper;

    public FindingIngestService(FindingStore findings, InventoryStore inventory, ObjectMapper mapper) {
        this.findings = findings;
        this.inventory = inventory;
        this.mapper = mapper;
    }

    public Result ingest(Job job, List<Finding> reported, boolean completeScan) {
        boolean production = inventory.findEnvironmentById(job.tenantId(), job.environmentId())
                .map(InventoryStore.Environment::production).orElse(false);
        PriorityCalculator.Context ctx = new PriorityCalculator.Context(production, null);
        Map<Severity, Integer> counts = new EnumMap<>(Severity.class);
        Set<String> seen = new HashSet<>();
        Instant now = Instant.now();
        int accepted = 0;
        for (Finding f : reported) {
            if (f == null || f.title == null || f.title.isBlank()) continue;
            normalize(f, job);
            if (!seen.add(f.fingerprint)) continue; // duplicate within the same scan
            PriorityCalculator.apply(f, ctx);
            if (f.priority == null) f.priority = f.sourceSeverity;
            f.lastDetected = now;
            f.lastScanId = job.id();

            Existing existing = findings.find(job.tenantId(), job.applicationId(), job.environmentId(), f.fingerprint).orElse(null);
            if (existing == null) {
                f.id = com.securetest.controlplane.store.Rows.newId();
                f.firstDetected = now;
                f.occurrences = 1;
                f.status = FindingStatus.OPEN;
                findings.insert(job.tenantId(), job.applicationId(), job.environmentId(), f, json(f));
            } else {
                f.id = existing.id();
                f.firstDetected = existing.firstDetected();
                f.occurrences = existing.occurrences() + 1;
                FindingStatus previous = FindingStatus.valueOf(existing.status());
                // keep human triage decisions (suppressed, accepted risk, false positive); re-open fixed issues
                f.status = previous == FindingStatus.FIXED ? FindingStatus.OPEN : previous;
                f.regression = previous == FindingStatus.FIXED;
                if (f.regression) f.addHistory("worker", "REGRESSION", "Re-detected by scan " + job.id());
                findings.update(job.tenantId(), f, json(f));
            }
            counts.merge(f.priority, 1, Integer::sum);
            accepted++;
        }
        int closed = completeScan
                ? findings.autoClose(job.tenantId(), job.applicationId(), job.environmentId(), job.scannerId(), seen)
                : 0;
        return new Result(accepted, counts, closed);
    }

    /** Server-side normalization: never trust identity, workflow or tenant fields sent by a worker. */
    private static void normalize(Finding f, Job job) {
        f.source = job.scannerId();
        if (f.moduleId == null) f.moduleId = job.moduleId();
        if (f.sourceSeverity == null) f.sourceSeverity = Severity.parse(f.sourceSeverityRaw);
        f.priority = null;
        f.priorityRationale.clear();
        f.suppression = null;
        f.owner = null;
        f.dueDate = null;
        f.history.clear();
        f.relatedFindingIds.clear();
        f.evidence = Redactor.redact(truncate(f.evidence, 20_000));
        f.description = truncate(f.description, 20_000);
        if (f.asset == null) f.asset = job.targetUrl();
        f.fingerprint = Fingerprints.of(f);
    }

    private static String truncate(String s, int max) {
        return s == null || s.length() <= max ? s : s.substring(0, max);
    }

    private String json(Finding f) {
        try {
            return mapper.writeValueAsString(f);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Cannot serialize finding", e);
        }
    }
}
