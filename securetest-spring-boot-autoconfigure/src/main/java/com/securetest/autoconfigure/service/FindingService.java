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
        for (Finding f : byId.values()) { // retests waiting for this scan
            Finding.Verification v = f.verification;
            if (!retestFor(v, job)) continue;
            v.jobId = job.id;
            v.completedAt = now;
            v.verifiedBy = job.scannerName;
            if (seen.contains(f.fingerprint)) {
                v.state = "STILL_PRESENT";
                if (!f.isOpen()) f.status = FindingStatus.OPEN;
                f.addHistory("system", "RETEST_FAILED", "Still present in retest scan " + job.id);
            } else if (completeRun) {
                v.state = "VERIFIED_FIXED";
                f.status = FindingStatus.FIXED;
                f.addHistory("system", "VERIFIED_FIXED", "Not detected by retest scan " + job.id);
            } else {
                v.state = "INCONCLUSIVE";
                f.addHistory("system", "RETEST_INCONCLUSIVE", "Retest scan " + job.id + " did not complete fully");
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

    // ------------------------------------------------------------------ retest

    /**
     * Marks a retest as pending before its scan is submitted (automated: the next complete run of {@code scannerId} settles
     * it, so a scan that finishes before the job id is attached is not missed) or as waiting for a tester (scannerId null).
     */
    public synchronized Finding requestRetest(String id, String scannerId, String actor) {
        Finding f = get(id);
        Finding.Verification v = new Finding.Verification();
        v.state = scannerId == null ? "AWAITING_TESTER" : "PENDING";
        v.scannerId = scannerId;
        v.requestedBy = actor;
        v.requestedAt = Instant.now();
        f.verification = v;
        f.addHistory(actor, "RETEST_REQUESTED", scannerId == null ? "Waiting for a tester to verify the fix" : "Retest with " + scannerId);
        touch();
        return f;
    }

    /** Records which scan runs the retest (for display), unless that scan already settled it. */
    public synchronized Finding attachRetestJob(String id, String jobId) {
        Finding f = get(id);
        if (f.verification != null && f.verification.jobId == null) f.verification.jobId = jobId;
        touch();
        return f;
    }

    /** The retest could not be started (e.g. the module is off): nothing will settle it. */
    public synchronized void retestNotStarted(String id, String reason) {
        Finding f = get(id);
        if (f.verification != null && "PENDING".equals(f.verification.state)) {
            f.verification.state = "INCONCLUSIVE";
            f.verification.completedAt = Instant.now();
            f.verification.note = reason;
            touch();
        }
    }

    private static boolean retestFor(Finding.Verification v, ScanJob job) {
        if (v == null || !"PENDING".equals(v.state)) return false;
        return job.id.equals(v.jobId) || (v.jobId == null && job.scannerId.equals(v.scannerId))
                || (job.scannerId.equals(v.scannerId) && v.requestedAt != null && job.createdAt != null && !job.createdAt.isBefore(v.requestedAt));
    }

    /** A tester's verdict on a retest (manual findings, or overriding an automated result). */
    public synchronized Finding recordVerification(String id, boolean fixed, String note, String actor) {
        Finding f = get(id);
        Finding.Verification v = f.verification == null ? new Finding.Verification() : f.verification;
        if (v.requestedAt == null) {
            v.requestedAt = Instant.now();
            v.requestedBy = actor;
        }
        v.state = fixed ? "VERIFIED_FIXED" : "STILL_PRESENT";
        v.verifiedBy = actor;
        v.completedAt = Instant.now();
        v.note = note;
        f.verification = v;
        if (fixed) f.status = FindingStatus.FIXED; else if (!f.isOpen()) f.status = FindingStatus.OPEN;
        f.addHistory(actor, fixed ? "VERIFIED_FIXED" : "RETEST_FAILED", note == null ? "" : note);
        touch();
        return f;
    }

    /** A retest scan that failed or was cancelled leaves its findings' retest inconclusive. */
    public synchronized void jobEnded(ScanJob job) {
        boolean changed = false;
        for (Finding f : byId.values()) {
            Finding.Verification v = f.verification;
            if (retestFor(v, job) && (job.id.equals(v.jobId) || v.jobId == null)) {
                v.state = "INCONCLUSIVE";
                v.completedAt = Instant.now();
                v.note = "Retest scan " + job.id + " ended with " + job.status;
                f.addHistory("system", "RETEST_INCONCLUSIVE", v.note);
                changed = true;
            }
        }
        if (changed) touch();
    }

    // ------------------------------------------------------------------ manual findings, comments, attachments, issues

    /** A finding reported by a person (pentest / VAPT / exploratory testing) rather than a scanner. */
    public record ManualFinding(String moduleId, String title, Severity severity, String category, String asset, String description,
                                String stepsToReproduce, String impact, String remediation, List<String> references, String evidence,
                                String cwe, String engagementId, String owner, Instant dueDate) { }

    public synchronized Finding createManual(ManualFinding m, String actor) {
        if (m.title() == null || m.title().isBlank()) throw ApiException.badRequest("title is required");
        if (m.title().length() > 300) throw ApiException.badRequest("title is too long (max 300)");
        Severity sev = m.severity() == null ? Severity.MEDIUM : m.severity();
        String module = m.moduleId() == null || m.moduleId().isBlank() ? com.securetest.core.model.ModuleCatalog.API_SECURITY : m.moduleId();
        if (com.securetest.core.model.ModuleCatalog.find(module).isEmpty()) throw ApiException.badRequest("Unknown module " + module);
        Finding f = Finding.of(module, "manual", m.cwe() == null || m.cwe().isBlank() ? "MANUAL" : clip(m.cwe(), 40), clip(m.title(), 300), sev);
        f.category = clip(m.category(), 120);
        f.asset = clip(m.asset(), 500);
        f.description = clip(m.description(), 20_000);
        f.stepsToReproduce = clip(m.stepsToReproduce(), 20_000);
        f.impact = clip(m.impact(), 5_000);
        f.remediation = clip(m.remediation(), 10_000);
        f.evidence = clip(m.evidence(), 50_000);
        if (props.getSecurity().isRedactSecrets()) f.evidence = Redactor.redact(f.evidence);
        if (m.references() != null) {
            m.references().stream().filter(r -> r != null && !r.isBlank()).limit(20).forEach(r -> f.references.add(clip(r, 500)));
        }
        f.engagementId = m.engagementId();
        f.owner = m.owner();
        f.dueDate = m.dueDate();
        f.confidence = com.securetest.core.model.Enums.Confidence.HIGH; // a person reproduced it
        f.id = String.format("F-%06d", counter.incrementAndGet());
        f.fingerprint = "manual:" + f.id;
        Instant now = Instant.now();
        f.firstDetected = now;
        f.lastDetected = now;
        f.occurrences = 1;
        f.status = FindingStatus.OPEN;
        PriorityCalculator.apply(f, new PriorityCalculator.Context(app.productionLike(), props.getApplication().getCriticality()));
        f.addHistory(actor, "REPORTED", "Reported manually" + (m.engagementId() == null ? "" : " in engagement " + m.engagementId()));
        byId.put(f.id, f);
        byFingerprint.put(f.fingerprint, f.id);
        touch();
        return f;
    }

    public synchronized Finding addComment(String id, String text, String actor) {
        if (text == null || text.isBlank()) throw ApiException.badRequest("Comment text is required");
        Finding f = get(id);
        if (f.comments.size() >= 500) throw ApiException.conflict("Too many comments on this finding");
        Finding.Comment c = new Finding.Comment();
        c.id = "C-" + java.util.UUID.randomUUID().toString().substring(0, 8);
        c.author = actor;
        c.at = Instant.now();
        c.text = clip(props.getSecurity().isRedactSecrets() ? Redactor.redact(text) : text, 10_000);
        f.comments.add(c);
        touch();
        return f;
    }

    public synchronized Finding addAttachment(String id, Finding.Attachment a) {
        Finding f = get(id);
        if (f.attachments.size() >= 50) throw ApiException.conflict("Too many attachments on this finding (max 50)");
        f.attachments.add(a);
        f.addHistory(a.uploadedBy, "ATTACHMENT", a.name);
        touch();
        return f;
    }

    public synchronized Finding linkIssue(String id, Finding.IssueLink link, String actor) {
        Finding f = get(id);
        f.issues.put(link.tracker, link);
        f.addHistory(actor, "ISSUE_LINKED", link.tracker + " " + link.key);
        touch();
        return f;
    }

    public synchronized void touch() {
        revision.incrementAndGet();
        store.markDirty("findings");
    }

    private static String clip(String s, int max) {
        if (s == null) return null;
        return s.length() > max ? s.substring(0, max) : s;
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
