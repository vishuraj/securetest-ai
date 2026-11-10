package com.securetest.autoconfigure.disclosure;

import com.fasterxml.jackson.core.type.TypeReference;
import com.securetest.autoconfigure.SecureTestProperties;
import com.securetest.autoconfigure.security.ApiException;
import com.securetest.autoconfigure.service.FindingService;
import com.securetest.autoconfigure.service.NotificationService;
import com.securetest.autoconfigure.support.LocalStore;
import com.securetest.core.model.Finding;
import com.securetest.core.model.Severity;
import com.securetest.core.util.Hashing;
import com.securetest.core.util.Redactor;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayDeque;
import java.util.Comparator;
import java.util.Deque;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Reports from external security researchers (a vulnerability disclosure program, HackerOne-style but without bounties):
 * received through the public form, triaged by the team, and turned into findings when valid.
 */
public class DisclosureService {

    public static final Set<String> DECISIONS = Set.of("ACCEPTED", "REJECTED", "DUPLICATE", "NEEDS_INFO", "OUT_OF_SCOPE");

    public static class Report {
        public String id;
        public String title;
        public String asset;
        public String description;
        public String stepsToReproduce;
        public String impact;
        public String reporterName;
        public String reporterEmail;
        public boolean publicCredit;
        public Instant receivedAt;
        /** Salted hash of the client address, for abuse handling only (the address itself is not stored). */
        public String clientHash;
        public String status = "NEW";
        public String triagedBy;
        public Instant triagedAt;
        public String note;
        public String findingId;
    }

    public record Submission(String title, String asset, String description, String stepsToReproduce, String impact,
                             String reporterName, String reporterEmail, boolean publicCredit) { }

    private final SecureTestProperties props;
    private final LocalStore store;
    private final FindingService findings;
    private final NotificationService notifications;
    private final Map<String, Report> reports;
    private final AtomicInteger counter = new AtomicInteger();
    private final Map<String, Deque<Instant>> recent = new ConcurrentHashMap<>();
    private final String salt = java.util.UUID.randomUUID().toString();

    public DisclosureService(SecureTestProperties props, LocalStore store, FindingService findings, NotificationService notifications) {
        this.props = props;
        this.store = store;
        this.findings = findings;
        this.notifications = notifications;
        this.reports = new ConcurrentHashMap<>(store.load("disclosures", new TypeReference<Map<String, Report>>() { }, LinkedHashMap::new));
        reports.keySet().forEach(id -> {
            try {
                counter.set(Math.max(counter.get(), Integer.parseInt(id.substring(4))));
            } catch (RuntimeException ignored) {
                // other id format
            }
        });
        store.register("disclosures", () -> new LinkedHashMap<>(reports));
    }

    public boolean enabled() {
        return props.getDisclosure().isEnabled();
    }

    /** Stores a public submission. Returns the report id, or throws when it is invalid or the client is over its limit. */
    public synchronized Report submit(Submission s, String clientAddress) {
        if (!enabled() || !props.getDisclosure().isForm()) throw ApiException.notFound("Not found");
        if (s.title() == null || s.title().isBlank() || s.description() == null || s.description().isBlank()) {
            throw ApiException.badRequest("A title and a description are required.");
        }
        if (s.reporterEmail() != null && !s.reporterEmail().isBlank() && !s.reporterEmail().matches("[^@\\s]{1,64}@[^@\\s]{1,255}")) {
            throw ApiException.badRequest("The e-mail address is not valid.");
        }
        String client = Hashing.sha256(salt + (clientAddress == null ? "?" : clientAddress)).substring(0, 16);
        Deque<Instant> times = recent.computeIfAbsent(client, k -> new ArrayDeque<>());
        Instant hourAgo = Instant.now().minus(1, ChronoUnit.HOURS);
        while (!times.isEmpty() && times.peekFirst().isBefore(hourAgo)) times.pollFirst();
        if (times.size() >= Math.max(1, props.getDisclosure().getReportsPerHour())) throw new ApiException(429, "too_many_requests", "Too many reports. Please try again later.");
        if (reports.size() >= 2000) throw new ApiException(503, "unavailable", "The report queue is full. Please use the e-mail contact.");
        times.addLast(Instant.now());
        Report r = new Report();
        r.id = String.format("VDP-%04d", counter.incrementAndGet());
        r.title = clip(s.title(), 200);
        r.asset = clip(s.asset(), 500);
        r.description = clip(Redactor.redact(s.description()), 20_000);
        r.stepsToReproduce = clip(Redactor.redact(s.stepsToReproduce()), 20_000);
        r.impact = clip(s.impact(), 5_000);
        r.reporterName = clip(s.reporterName(), 120);
        r.reporterEmail = clip(s.reporterEmail(), 320);
        r.publicCredit = s.publicCredit();
        r.receivedAt = Instant.now();
        r.clientHash = client;
        reports.put(r.id, r);
        store.markDirty("disclosures");
        notifications.publish("disclosure.received", "New vulnerability report " + r.id + ": " + r.title, Map.of("report", r.id));
        return r;
    }

    public List<Report> list() {
        return reports.values().stream().sorted(Comparator.comparing((Report r) -> r.receivedAt).reversed()).toList();
    }

    public Report get(String id) {
        Report r = reports.get(id);
        if (r == null) throw ApiException.notFound("Report " + id);
        return r;
    }

    /** Triage decision. ACCEPTED creates a finding from the report (once). */
    public synchronized Report triage(String id, String decision, String note, Severity severity, String moduleId, String actor) {
        Report r = get(id);
        if (!DECISIONS.contains(decision)) throw ApiException.badRequest("decision must be one of " + DECISIONS);
        r.status = decision;
        r.note = clip(note, 5_000);
        r.triagedBy = actor;
        r.triagedAt = Instant.now();
        if (decision.equals("ACCEPTED") && r.findingId == null) {
            Finding f = findings.createManual(new FindingService.ManualFinding(moduleId, r.title, severity == null ? Severity.MEDIUM : severity,
                    "Reported by an external researcher", r.asset, r.description, r.stepsToReproduce, r.impact, null, List.of(), null,
                    null, null, null, null), actor);
            f.attributes.put("disclosureId", r.id);
            if (r.reporterName != null && r.publicCredit) f.attributes.put("reportedBy", r.reporterName);
            findings.touch();
            r.findingId = f.id;
        }
        store.markDirty("disclosures");
        return r;
    }

    private static String clip(String s, int max) {
        return s == null || s.isBlank() ? null : s.length() > max ? s.substring(0, max) : s;
    }
}
