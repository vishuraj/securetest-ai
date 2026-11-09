package com.securetest.autoconfigure.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.securetest.autoconfigure.SecureTestProperties;
import com.securetest.autoconfigure.security.ApiException;
import com.securetest.autoconfigure.support.AppContext;
import com.securetest.autoconfigure.support.LocalStore;
import com.securetest.core.model.Enums.FindingStatus;
import com.securetest.core.model.Finding;
import com.securetest.core.model.ScanJob;
import com.securetest.core.model.Severity;
import com.securetest.core.util.Fingerprints;
import com.securetest.core.util.PriorityCalculator;
import com.securetest.core.util.Redactor;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.EnumMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/** Finding store: normalization, deduplication, priority, lifecycle, suppressions and search (SRS 7.1, 7.2, 8.4). */
public class FindingService {

    public record Page<T>(List<T> items, long total, int page, int size) { }

    public record Filter(String q, Set<Severity> priorities, Set<FindingStatus> statuses, Set<String> modules, String source,
                         String sort, boolean includeClosed) { }

    private final SecureTestProperties props;
    private final AppContext app;
    private final LocalStore store;
    private final Map<String, Finding> byId = new ConcurrentHashMap<>();
    private final Map<String, String> byFingerprint = new ConcurrentHashMap<>();
    private final AtomicLong counter = new AtomicLong();
    private final AtomicLong revision = new AtomicLong();

    public FindingService(SecureTestProperties props, AppContext app, LocalStore store) {
        this.props = props;
        this.app = app;
        this.store = store;
        List<Finding> loaded = store.load("findings", new TypeReference<List<Finding>>() { }, ArrayList::new);
        for (Finding f : loaded) {
            byId.put(f.id, f);
            byFingerprint.put(f.fingerprint, f.id);
            try {
                counter.set(Math.max(counter.get(), Long.parseLong(f.id.substring(2))));
            } catch (RuntimeException ignored) {
                // foreign id format
            }
        }
        store.register("findings", () -> new ArrayList<>(byId.values()));
    }

    /** Monotonic data-snapshot version for reports. */
    public long revision() { return revision.get(); }

    /**
     * Merges scan output: dedupe by fingerprint, keep workflow state, detect regressions, compute priority,
     * and auto-close open findings from the same scanner that were not seen in a complete run.
     */
    public synchronized List<Finding> ingest(ScanJob job, List<Finding> reported, String sourceRevision, boolean completeRun) {
        Instant now = Instant.now();
        PriorityCalculator.Context pctx = new PriorityCalculator.Context(app.productionLike(), props.getApplication().getCriticality());
        Set<String> seen = new HashSet<>();
        List<Finding> result = new ArrayList<>();
        for (Finding f : reported) {
            if (props.getSecurity().isRedactSecrets()) {
                f.evidence = Redactor.redact(f.evidence);
                f.description = Redactor.redact(f.description);
                f.title = Redactor.redact(f.title);
            }
            if (f.revision == null) f.revision = sourceRevision;
            if (f.moduleId == null) f.moduleId = job.moduleId;
            f.fingerprint = Fingerprints.of(f);
            if (!seen.add(f.fingerprint)) continue; // duplicate inside the same scan
            String existingId = byFingerprint.get(f.fingerprint);
            Finding target;
            if (existingId != null && byId.containsKey(existingId)) {
                target = byId.get(existingId);
                if (!f.source.equals(target.source)) {
                    String also = target.attributes.getOrDefault("alsoReportedBy", "");
                    if (!also.contains(f.source)) target.attributes.put("alsoReportedBy", also.isEmpty() ? f.source : also + "," + f.source);
                } else {
                    refresh(target, f);
                }
                target.lastDetected = now;
                target.lastScanId = job.id;
                target.occurrences++;
                if (target.status == FindingStatus.FIXED) {
                    target.status = FindingStatus.OPEN;
                    target.regression = true;
                    target.addHistory(job.requestedBy, "REGRESSION", "Detected again by scan " + job.id + " after being fixed");
                }
            } else {
                target = f;
                target.id = String.format("F-%06d", counter.incrementAndGet());
                target.firstDetected = now;
                target.lastDetected = now;
                target.lastScanId = job.id;
                target.occurrences = 1;
                target.status = FindingStatus.OPEN;
                target.addHistory(job.requestedBy, "DETECTED", "Detected by " + job.scannerName + " (scan " + job.id + ")");
                byId.put(target.id, target);
                byFingerprint.put(target.fingerprint, target.id);
            }
            if (target.sourceToolVersion == null) target.sourceToolVersion = job.toolVersion;
            PriorityCalculator.apply(target, pctx);
            result.add(target);
        }
        if (completeRun) {
            for (Finding f : byId.values()) {
                if (f.source.equals(job.scannerId) && f.isOpen() && !seen.contains(f.fingerprint)) {
                    f.status = FindingStatus.FIXED;
                    f.addHistory("system", "RESOLVED", "Not detected by scan " + job.id);
                }
            }
        }
        revision.incrementAndGet();
        store.markDirty("findings");
        return result;
    }

    /** Copies scanner-owned fields from a fresh detection while keeping workflow state. */
    private static void refresh(Finding target, Finding fresh) {
        target.title = fresh.title;
        target.description = fresh.description;
        target.remediation = fresh.remediation;
        target.sourceSeverity = fresh.sourceSeverity;
        target.sourceSeverityRaw = fresh.sourceSeverityRaw;
        target.confidence = fresh.confidence;
        target.lineStart = fresh.lineStart;
        target.lineEnd = fresh.lineEnd;
        target.snippet = fresh.snippet;
        target.fileHash = fresh.fileHash;
        target.revision = fresh.revision;
        target.evidence = fresh.evidence;
        target.dependency = fresh.dependency;
        target.references = fresh.references;
        target.complianceTags = fresh.complianceTags;
        target.fixId = fresh.fixId;
        target.attributes.putAll(fresh.attributes);
    }

    public Finding get(String id) {
        Finding f = byId.get(id);
        if (f == null) throw ApiException.notFound("Finding " + id);
        return f;
    }

    public List<Finding> all() { return new ArrayList<>(byId.values()); }

    public Page<Finding> search(Filter filter, int page, int size) {
        String q = filter.q() == null ? "" : filter.q().toLowerCase(Locale.ROOT);
        List<Finding> list = byId.values().stream()
                .filter(f -> filter.includeClosed() || filter.statuses() != null && !filter.statuses().isEmpty() || f.isOpen())
                .filter(f -> filter.priorities() == null || filter.priorities().isEmpty() || filter.priorities().contains(f.priority))
                .filter(f -> filter.statuses() == null || filter.statuses().isEmpty() || filter.statuses().contains(f.status))
                .filter(f -> filter.modules() == null || filter.modules().isEmpty() || filter.modules().contains(f.moduleId))
                .filter(f -> filter.source() == null || filter.source().isBlank() || filter.source().equals(f.source))
                .filter(f -> q.isEmpty() || haystack(f).contains(q))
                .sorted(comparator(filter.sort()))
                .toList();
        int from = Math.min(list.size(), page * size);
        return new Page<>(list.subList(from, Math.min(list.size(), from + size)), list.size(), page, size);
    }

    private static String haystack(Finding f) {
        return (f.id + " " + f.title + " " + f.ruleId + " " + f.filePath + " " + f.asset + " " + f.source + " " + f.category + " "
                + (f.dependency != null ? f.dependency.packageName + " " + String.join(" ", f.dependency.aliases) : "")).toLowerCase(Locale.ROOT);
    }

    private static Comparator<Finding> comparator(String sort) {
        Comparator<Finding> byPriority = Comparator.comparingInt((Finding f) -> f.priority == null ? 0 : f.priority.rank()).reversed();
        if (sort == null) return byPriority.thenComparing(f -> f.lastDetected, Comparator.nullsLast(Comparator.reverseOrder()));
        return switch (sort) {
            case "newest" -> Comparator.comparing((Finding f) -> f.firstDetected, Comparator.nullsLast(Comparator.reverseOrder()));
            case "oldest" -> Comparator.comparing((Finding f) -> f.firstDetected, Comparator.nullsLast(Comparator.naturalOrder()));
            case "module" -> Comparator.comparing((Finding f) -> f.moduleId).thenComparing(byPriority);
            case "file" -> Comparator.comparing((Finding f) -> f.filePath == null ? "~" : f.filePath).thenComparing(f -> f.lineStart == null ? 0 : f.lineStart);
            case "sourceSeverity" -> Comparator.comparingInt((Finding f) -> f.sourceSeverity.rank()).reversed();
            default -> byPriority;
        };
    }

    public synchronized Finding update(String id, FindingStatus status, String owner, Instant due, String note, String actor) {
        Finding f = get(id);
        if (status != null && status != f.status) {
            if (status == FindingStatus.SUPPRESSED || status == FindingStatus.ACCEPTED_RISK || status == FindingStatus.FALSE_POSITIVE) {
                throw ApiException.badRequest("Use the suppression endpoint (reason, owner and expiry are required).");
            }
            f.addHistory(actor, "STATUS", f.status + " → " + status + (note == null ? "" : ": " + note));
            f.status = status;
            if (status == FindingStatus.OPEN) f.suppression = null;
        }
        if (owner != null && !owner.equals(f.owner)) {
            f.addHistory(actor, "OWNER", (f.owner == null ? "-" : f.owner) + " → " + owner);
            f.owner = owner.isBlank() ? null : owner;
        }
        if (due != null && !due.equals(f.dueDate)) {
            f.addHistory(actor, "DUE_DATE", String.valueOf(due));
            f.dueDate = due;
        }
        if (note != null && status == null) f.addHistory(actor, "NOTE", note);
        revision.incrementAndGet();
        store.markDirty("findings");
        return f;
    }

    public synchronized Finding suppress(String id, FindingStatus type, String reason, String owner, Instant expires, String actor, String approver) {
        Finding f = get(id);
        if (type != FindingStatus.SUPPRESSED && type != FindingStatus.ACCEPTED_RISK && type != FindingStatus.FALSE_POSITIVE) {
            throw ApiException.badRequest("type must be SUPPRESSED, ACCEPTED_RISK or FALSE_POSITIVE");
        }
        if (reason == null || reason.isBlank() || reason.length() < 10) throw ApiException.badRequest("A reason of at least 10 characters is required.");
        if (owner == null || owner.isBlank()) throw ApiException.badRequest("An owner is required.");
        if (expires == null) throw ApiException.badRequest("An expiry date is required.");
        int maxDays = props.getPolicy().getMaxSuppressionDays();
        if (expires.isAfter(Instant.now().plus(Duration.ofDays(maxDays)))) throw ApiException.badRequest("Expiry may be at most " + maxDays + " days ahead (policy).");
        if (expires.isBefore(Instant.now())) throw ApiException.badRequest("Expiry must be in the future.");
        Finding.Suppression s = new Finding.Suppression();
        s.reason = reason;
        s.owner = owner;
        s.expiresAt = expires;
        s.createdBy = actor;
        s.approvedBy = approver;
        s.createdAt = Instant.now();
        s.resultingStatus = type;
        f.suppression = s;
        f.addHistory(actor, type.name(), reason + " (owner " + owner + ", expires " + expires + (approver != null ? ", approved by " + approver : "") + ")");
        f.status = type;
        revision.incrementAndGet();
        store.markDirty("findings");
        return f;
    }

    public synchronized Finding revokeSuppression(String id, String actor) {
        Finding f = get(id);
        if (f.suppression == null) throw ApiException.badRequest("Finding is not suppressed");
        f.suppression = null;
        f.status = FindingStatus.OPEN;
        f.addHistory(actor, "SUPPRESSION_REVOKED", "Exception revoked");
        store.markDirty("findings");
        return f;
    }

    /** Housekeeping: expire exceptions and purge closed findings older than retention. */
    public synchronized int housekeeping(Duration retention) {
        Instant now = Instant.now();
        int changes = 0;
        for (Finding f : byId.values()) {
            if (f.suppression != null && f.suppression.expired(now)) {
                f.addHistory("system", "SUPPRESSION_EXPIRED", "Exception expired on " + f.suppression.expiresAt);
                f.suppression = null;
                f.status = FindingStatus.OPEN;
                changes++;
            }
        }
        Instant cutoff = now.minus(retention);
        List<String> purge = byId.values().stream().filter(f -> !f.isOpen() && f.lastDetected != null && f.lastDetected.isBefore(cutoff)).map(f -> f.id).toList();
        for (String id : purge) {
            Finding f = byId.remove(id);
            byFingerprint.remove(f.fingerprint);
            changes++;
        }
        if (changes > 0) store.markDirty("findings");
        return changes;
    }

    public Map<String, Object> summary() {
        Map<Severity, Integer> open = new EnumMap<>(Severity.class);
        Map<String, Map<String, Integer>> byModule = new LinkedHashMap<>();
        Map<String, Integer> byStatus = new LinkedHashMap<>();
        int regressions = 0;
        for (Finding f : byId.values()) {
            byStatus.merge(f.status.name(), 1, Integer::sum);
            if (!f.isOpen()) continue;
            Severity p = f.priority == null ? f.sourceSeverity : f.priority;
            open.merge(p, 1, Integer::sum);
            byModule.computeIfAbsent(f.moduleId, k -> new LinkedHashMap<>()).merge(p.name(), 1, Integer::sum);
            if (f.regression) regressions++;
        }
        for (Severity s : Severity.values()) open.putIfAbsent(s, 0);
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("open", open);
        m.put("byModule", byModule);
        m.put("byStatus", byStatus);
        m.put("regressions", regressions);
        m.put("total", byId.size());
        return m;
    }

    public Map<Severity, Integer> openCounts(String moduleId) {
        Map<Severity, Integer> m = new EnumMap<>(Severity.class);
        for (Finding f : byId.values()) {
            if (f.isOpen() && (moduleId == null || moduleId.equals(f.moduleId))) m.merge(f.priority == null ? f.sourceSeverity : f.priority, 1, Integer::sum);
        }
        return m;
    }

    /** Adds externally ingested events (webhook) as findings. */
    public List<Finding> ingestExternal(String source, List<Finding> findings) {
        ScanJob pseudo = new ScanJob();
        pseudo.id = "ingest-" + Instant.now().toEpochMilli();
        pseudo.scannerId = source;
        pseudo.scannerName = source + " webhook";
        pseudo.requestedBy = "webhook:" + source;
        pseudo.moduleId = findings.isEmpty() ? "advanced-security" : findings.get(0).moduleId;
        return ingest(pseudo, findings, null, false);
    }
}
