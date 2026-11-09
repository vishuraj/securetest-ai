package com.securetest.autoconfigure.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.securetest.autoconfigure.security.ApiException;
import com.securetest.autoconfigure.security.Rbac.Permission;
import com.securetest.autoconfigure.security.Rbac.Role;
import com.securetest.autoconfigure.security.SecureTestPrincipal;
import com.securetest.autoconfigure.support.LocalStore;
import com.securetest.core.model.Enums.FieldType;
import com.securetest.core.model.Enums.ScanMode;
import com.securetest.core.spi.FieldSpec;
import com.securetest.core.spi.ScannerDescriptor;
import com.securetest.core.util.Redactor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.support.CronExpression;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/** Saved scan profiles, scheduled scans and manual / exploratory test management. */
public final class WorkspaceServices {
    private WorkspaceServices() { }

    // =====================================================================================  profiles

    /** Named, reusable scan configuration. Raw secrets are never stored: only secret references (SRS 6.2). */
    public static class ProfileService {
        public static class Profile {
            public String name;
            public String scannerId;
            public Map<String, String> options = new LinkedHashMap<>();
            public String createdBy;
            public Instant updatedAt;
            public List<String> droppedSecrets = new ArrayList<>();
        }

        private final LocalStore store;
        private final ScannerRegistry registry;
        private final Map<String, Profile> profiles;

        public ProfileService(LocalStore store, ScannerRegistry registry) {
            this.store = store;
            this.registry = registry;
            this.profiles = new ConcurrentHashMap<>(store.load("profiles", new TypeReference<Map<String, Profile>>() { }, LinkedHashMap::new));
            store.register("profiles", () -> new LinkedHashMap<>(profiles));
        }

        public Profile save(String name, String scannerId, Map<String, String> options, String actor) {
            if (name == null || !name.matches("[\\w .-]{1,60}")) throw ApiException.badRequest("Profile name must be 1-60 letters, digits, space, dot, dash or underscore.");
            ScannerDescriptor d = registry.get(scannerId).descriptor();
            Profile p = new Profile();
            p.name = name;
            p.scannerId = scannerId;
            p.createdBy = actor;
            p.updatedAt = Instant.now();
            for (FieldSpec f : d.getFields()) {
                String v = options == null ? null : options.get(f.key());
                if (v == null || v.isBlank()) continue;
                if (f.type() == FieldType.SECRET && !Redactor.isReference(v)) {
                    p.droppedSecrets.add(f.key());
                    continue;
                }
                p.options.put(f.key(), v);
            }
            profiles.put(scannerId + "/" + name, p);
            store.markDirty("profiles");
            return p;
        }

        public List<Profile> list(String scannerId) {
            return profiles.values().stream().filter(p -> scannerId == null || p.scannerId.equals(scannerId))
                    .sorted(Comparator.comparing(p -> p.name)).toList();
        }

        public Profile get(String scannerId, String name) {
            Profile p = profiles.get(scannerId + "/" + name);
            if (p == null) throw ApiException.notFound("Profile " + name);
            return p;
        }

        public void delete(String scannerId, String name) {
            if (profiles.remove(scannerId + "/" + name) == null) throw ApiException.notFound("Profile " + name);
            store.markDirty("profiles");
        }
    }

    // =====================================================================================  schedules

    /** Cron-based scheduled scans. Run with the creator's permissions captured at creation time. */
    public static class ScheduleService {
        private static final Logger log = LoggerFactory.getLogger(ScheduleService.class);

        public static class Schedule {
            public String id;
            public String scannerId;
            public String profileName;
            public String cron;
            public boolean enabled = true;
            public String createdBy;
            public boolean creatorCanApprove;
            public Instant nextRun;
            public Instant lastRun;
            public String lastJobId;
            public String lastError;
        }

        private final LocalStore store;
        private final ScannerRegistry registry;
        private final ProfileService profiles;
        private final Map<String, Schedule> schedules;
        private JobService jobs;

        public ScheduleService(LocalStore store, ScannerRegistry registry, ProfileService profiles) {
            this.store = store;
            this.registry = registry;
            this.profiles = profiles;
            this.schedules = new ConcurrentHashMap<>(store.load("schedules", new TypeReference<Map<String, Schedule>>() { }, LinkedHashMap::new));
            store.register("schedules", () -> new LinkedHashMap<>(schedules));
        }

        public void bind(JobService jobs) { this.jobs = jobs; }

        public Schedule create(String scannerId, String profileName, String cron, SecureTestPrincipal p) {
            ScannerDescriptor d = registry.get(scannerId).descriptor();
            if (profileName != null && !profileName.isBlank()) profiles.get(scannerId, profileName);
            CronExpression expr;
            try {
                expr = CronExpression.parse(cron);
            } catch (IllegalArgumentException e) {
                throw ApiException.badRequest("Invalid cron expression (6 fields: sec min hour day month weekday): " + e.getMessage());
            }
            if (d.getMode() == ScanMode.ACTIVE && !p.has(Permission.APPROVE)) {
                throw ApiException.forbidden("Scheduling an active scan requires APPROVE permission (the schedule acts as standing approval).");
            }
            Schedule s = new Schedule();
            s.id = "SCH-" + UUID.randomUUID().toString().substring(0, 6);
            s.scannerId = scannerId;
            s.profileName = profileName;
            s.cron = cron;
            s.createdBy = p.name();
            s.creatorCanApprove = p.has(Permission.APPROVE);
            s.nextRun = next(expr);
            schedules.put(s.id, s);
            store.markDirty("schedules");
            return s;
        }

        private static Instant next(CronExpression expr) {
            LocalDateTime n = expr.next(LocalDateTime.now());
            return n == null ? null : n.atZone(ZoneId.systemDefault()).toInstant();
        }

        public List<Schedule> list() { return new ArrayList<>(schedules.values()); }

        public void delete(String id) {
            if (schedules.remove(id) == null) throw ApiException.notFound("Schedule " + id);
            store.markDirty("schedules");
        }

        public Schedule setEnabled(String id, boolean enabled) {
            Schedule s = schedules.get(id);
            if (s == null) throw ApiException.notFound("Schedule " + id);
            s.enabled = enabled;
            store.markDirty("schedules");
            return s;
        }

        /** Called periodically by the housekeeping ticker. */
        public void tick() {
            if (jobs == null) return;
            Instant now = Instant.now();
            for (Schedule s : schedules.values()) {
                if (!s.enabled || s.nextRun == null || s.nextRun.isAfter(now)) continue;
                try {
                    Map<String, String> opts = s.profileName == null || s.profileName.isBlank() ? Map.of() : profiles.get(s.scannerId, s.profileName).options;
                    SecureTestPrincipal runAs = new SecureTestPrincipal("scheduler(" + s.createdBy + ")",
                            s.creatorCanApprove ? EnumSet.of(Role.SECURITY) : EnumSet.of(Role.DEVELOPER), "schedule", null);
                    var job = jobs.submit(new JobService.SubmitRequest(s.scannerId, opts, true, s.profileName, s.id + "@" + s.nextRun), runAs);
                    s.lastJobId = job.id;
                    s.lastError = null;
                } catch (RuntimeException e) {
                    s.lastError = e.getMessage();
                    log.info("SecureTest schedule {} skipped: {}", s.id, e.getMessage());
                }
                s.lastRun = now;
                s.nextRun = next(CronExpression.parse(s.cron));
                store.markDirty("schedules");
            }
        }
    }

    // =====================================================================================  manual & exploratory testing

    public static class TestManagementService {
        public static class TestCase {
            public String id;
            public String title;
            public String requirement;     // traceability
            public String preconditions;
            public List<String> steps = new ArrayList<>();
            public String expected;
            public String status = "NOT_RUN";  // NOT_RUN | PASS | FAIL | BLOCKED
            public String lastRunBy;
            public Instant lastRunAt;
            public List<Execution> executions = new ArrayList<>();
            public String createdBy;
            public Instant createdAt;
        }

        public record Execution(Instant at, String by, String status, String notes, String evidence) { }

        public static class Session {
            public String id;
            public String charter;
            public String tester;
            public Instant startedAt;
            public Instant endedAt;
            public String notes;
            public List<String> issues = new ArrayList<>();
            public List<String> evidence = new ArrayList<>();
        }

        private final LocalStore store;
        private final Map<String, TestCase> cases;
        private final Map<String, Session> sessions;

        public TestManagementService(LocalStore store) {
            this.store = store;
            this.cases = new ConcurrentHashMap<>(store.load("testcases", new TypeReference<Map<String, TestCase>>() { }, LinkedHashMap::new));
            this.sessions = new ConcurrentHashMap<>(store.load("sessions", new TypeReference<Map<String, Session>>() { }, LinkedHashMap::new));
            store.register("testcases", () -> new LinkedHashMap<>(cases));
            store.register("sessions", () -> new LinkedHashMap<>(sessions));
        }

        public List<TestCase> cases() { return cases.values().stream().sorted(Comparator.comparing(c -> c.id)).toList(); }

        public TestCase saveCase(TestCase in, String actor) {
            if (in.title == null || in.title.isBlank()) throw ApiException.badRequest("Title is required");
            TestCase c = in.id != null && cases.containsKey(in.id) ? cases.get(in.id) : new TestCase();
            if (c.id == null) {
                c.id = String.format("TC-%04d", cases.size() + 1);
                while (cases.containsKey(c.id)) c.id = "TC-" + UUID.randomUUID().toString().substring(0, 4);
                c.createdBy = actor;
                c.createdAt = Instant.now();
            }
            c.title = Redactor.redact(in.title);
            c.requirement = in.requirement;
            c.preconditions = Redactor.redact(in.preconditions);
            c.steps = in.steps == null ? new ArrayList<>() : in.steps.stream().map(Redactor::redact).toList();
            c.expected = Redactor.redact(in.expected);
            cases.put(c.id, c);
            store.markDirty("testcases");
            return c;
        }

        public TestCase execute(String id, String status, String notes, String evidence, String actor) {
            TestCase c = cases.get(id);
            if (c == null) throw ApiException.notFound("Test case " + id);
            if (!List.of("PASS", "FAIL", "BLOCKED", "NOT_RUN").contains(status)) throw ApiException.badRequest("status must be PASS, FAIL, BLOCKED or NOT_RUN");
            c.status = status;
            c.lastRunBy = actor;
            c.lastRunAt = Instant.now();
            c.executions.add(new Execution(Instant.now(), actor, status, Redactor.redact(notes), Redactor.redact(evidence)));
            store.markDirty("testcases");
            return c;
        }

        public void deleteCase(String id) {
            if (cases.remove(id) == null) throw ApiException.notFound("Test case " + id);
            store.markDirty("testcases");
        }

        public List<Session> sessions() {
            return sessions.values().stream().sorted(Comparator.comparing((Session s) -> s.startedAt).reversed()).toList();
        }

        public Session saveSession(Session in, String actor) {
            Session s = in.id != null && sessions.containsKey(in.id) ? sessions.get(in.id) : new Session();
            if (s.id == null) {
                if (in.charter == null || in.charter.isBlank()) throw ApiException.badRequest("Charter is required");
                s.id = "EX-" + UUID.randomUUID().toString().substring(0, 6);
                s.tester = actor;
                s.startedAt = Instant.now();
            }
            if (in.charter != null) s.charter = Redactor.redact(in.charter);
            if (in.notes != null) s.notes = Redactor.redact(in.notes);
            if (in.issues != null) s.issues = in.issues.stream().map(Redactor::redact).toList();
            if (in.evidence != null) s.evidence = in.evidence.stream().map(Redactor::redact).toList();
            if (in.endedAt != null && s.endedAt == null) s.endedAt = Instant.now();
            sessions.put(s.id, s);
            store.markDirty("sessions");
            return s;
        }

        public Map<String, Object> summary() {
            Map<String, Integer> byStatus = new LinkedHashMap<>();
            cases.values().forEach(c -> byStatus.merge(c.status, 1, Integer::sum));
            return Map.of("cases", cases.size(), "byStatus", byStatus, "sessions", sessions.size());
        }
    }
}
