package com.securetest.autoconfigure.service;

import com.securetest.autoconfigure.security.Authz;
import com.securetest.autoconfigure.security.SecureTestPrincipal;
import com.securetest.autoconfigure.support.LocalStore;
import com.securetest.core.model.AuditEvent;
import com.securetest.core.util.Hashing;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.function.Predicate;

/**
 * Append-only, hash-chained audit log (SEC-008, SRS 8.3). Each event's hash covers its content and the
 * previous hash, so any edit or deletion in the middle of audit.jsonl breaks {@link #verify()}.
 */
public class AuditService {

    private static final Logger log = LoggerFactory.getLogger("securetest.audit");
    private static final int MEMORY = 5000;

    private final LocalStore store;
    private final Path file;
    private final Deque<AuditEvent> recent = new ArrayDeque<>();
    private long sequence;
    private String lastHash = "GENESIS";

    public AuditService(LocalStore store) {
        this.store = store;
        this.file = store.dir().resolve("audit.jsonl");
        load();
    }

    private void load() {
        if (!store.writable() || !Files.exists(file)) return;
        try {
            for (String line : Files.readAllLines(file, StandardCharsets.UTF_8)) {
                if (line.isBlank()) continue;
                AuditEvent e = store.mapper().readValue(line, AuditEvent.class);
                recent.addLast(e);
                if (recent.size() > MEMORY) recent.removeFirst();
                sequence = e.sequence();
                lastHash = e.hash();
            }
        } catch (IOException e) {
            log.warn("SecureTest: audit log could not be read: {}", e.getMessage());
        }
    }

    public AuditEvent record(String action, String target, String outcome, Map<String, String> details) {
        SecureTestPrincipal p;
        try {
            p = Authz.current();
        } catch (RuntimeException e) {
            p = SecureTestPrincipal.system();
        }
        return record(p.name(), p.remoteAddress(), action, target, outcome, details);
    }

    public synchronized AuditEvent record(String actor, String remote, String action, String target, String outcome, Map<String, String> details) {
        long seq = ++sequence;
        String id = UUID.randomUUID().toString();
        Instant now = Instant.now();
        Map<String, String> d = details == null ? Map.of() : new LinkedHashMap<>(details);
        String corr = Authz.correlationId();
        String payload = seq + "|" + id + "|" + now + "|" + actor + "|" + action + "|" + target + "|" + outcome + "|" + corr + "|" + d + "|" + lastHash;
        String hash = Hashing.sha256(payload);
        AuditEvent e = new AuditEvent(seq, id, now, actor, action, target, outcome, corr, remote, d, lastHash, hash);
        lastHash = hash;
        recent.addLast(e);
        if (recent.size() > MEMORY) recent.removeFirst();
        if (store.writable()) {
            try (BufferedWriter w = Files.newBufferedWriter(file, StandardCharsets.UTF_8, StandardOpenOption.CREATE, StandardOpenOption.APPEND)) {
                w.write(store.mapper().writeValueAsString(e));
                w.newLine();
            } catch (IOException ex) {
                log.warn("SecureTest: failed to append audit event: {}", ex.getMessage());
            }
        }
        log.info("audit action={} actor={} target={} outcome={} correlationId={}", action, actor, target, outcome, corr);
        return e;
    }

    public synchronized List<AuditEvent> query(Predicate<AuditEvent> filter, int offset, int limit) {
        List<AuditEvent> all = new ArrayList<>(recent);
        java.util.Collections.reverse(all);
        return all.stream().filter(filter).skip(offset).limit(limit).toList();
    }

    public synchronized long count(Predicate<AuditEvent> filter) {
        return recent.stream().filter(filter).count();
    }

    /** Recomputes the full chain from disk (or memory when persistence is off). */
    public synchronized Map<String, Object> verify() {
        List<AuditEvent> events = new ArrayList<>();
        if (store.writable() && Files.exists(file)) {
            try {
                for (String line : Files.readAllLines(file, StandardCharsets.UTF_8)) {
                    if (!line.isBlank()) events.add(store.mapper().readValue(line, AuditEvent.class));
                }
            } catch (IOException e) {
                return Map.of("valid", false, "error", e.getMessage());
            }
        } else {
            events.addAll(recent);
        }
        String prev = events.isEmpty() ? "GENESIS" : events.get(0).previousHash();
        long checked = 0;
        for (AuditEvent e : events) {
            String payload = e.sequence() + "|" + e.id() + "|" + e.timestamp() + "|" + e.actor() + "|" + e.action() + "|" + e.target() + "|"
                    + e.outcome() + "|" + e.correlationId() + "|" + e.details() + "|" + prev;
            if (!e.previousHash().equals(prev) || !Hashing.sha256(payload).equals(e.hash())) {
                return Map.of("valid", false, "brokenAtSequence", e.sequence(), "checked", checked);
            }
            prev = e.hash();
            checked++;
        }
        return Map.of("valid", true, "checked", checked, "head", prev);
    }

    /** Retention: rewrites the log keeping events newer than the retention window (chain restarts from the kept head). */
    public synchronized int purgeOlderThan(Duration retention) {
        Instant cutoff = Instant.now().minus(retention);
        int before = recent.size();
        recent.removeIf(e -> e.timestamp().isBefore(cutoff));
        return before - recent.size();
    }
}
