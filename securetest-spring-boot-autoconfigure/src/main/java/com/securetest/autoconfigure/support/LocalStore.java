package com.securetest.autoconfigure.support;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;

/**
 * File-based persistence for the embedded profile (local-first, no database needed).
 * Each data class is a JSON document written atomically and debounced; the enterprise control plane
 * uses PostgreSQL + object storage instead (SRS 12.1).
 */
public class LocalStore {

    private static final Logger log = LoggerFactory.getLogger(LocalStore.class);

    private final Path dir;
    private final boolean persist;
    private final ObjectMapper mapper;
    private final Map<String, Supplier<Object>> sources = new ConcurrentHashMap<>();
    private final Map<String, Boolean> dirty = new ConcurrentHashMap<>();
    private final ScheduledExecutorService writer;

    public LocalStore(Path dir, boolean persist, ObjectMapper mapper) {
        this.dir = dir;
        this.persist = persist;
        this.mapper = mapper;
        this.writer = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "securetest-store");
            t.setDaemon(true);
            return t;
        });
        if (persist) {
            try {
                Files.createDirectories(dir);
            } catch (IOException e) {
                log.warn("SecureTest: cannot create storage directory {}: {}", dir, e.getMessage());
            }
            writer.scheduleWithFixedDelay(this::flush, 2, 2, TimeUnit.SECONDS);
        }
    }

    public Path dir() { return dir; }

    public Path subdir(String name) {
        Path p = dir.resolve(name);
        try {
            Files.createDirectories(p);
        } catch (IOException e) {
            log.debug("cannot create {}", p, e);
        }
        return p;
    }

    public ObjectMapper mapper() { return mapper; }

    public boolean writable() {
        return persist && Files.isDirectory(dir) && Files.isWritable(dir);
    }

    public <T> T load(String name, TypeReference<T> type, Supplier<T> fallback) {
        if (!persist) return fallback.get();
        Path f = dir.resolve(name + ".json");
        if (!Files.exists(f)) return fallback.get();
        try {
            T v = mapper.readValue(f.toFile(), type);
            return v == null ? fallback.get() : v;
        } catch (IOException e) {
            log.warn("SecureTest: could not read {} ({}); starting empty. The file is kept as {}.bak", f, e.getMessage(), name);
            try {
                Files.copy(f, dir.resolve(name + ".json.bak"), StandardCopyOption.REPLACE_EXISTING);
            } catch (IOException ignored) {
                // best effort
            }
            return fallback.get();
        }
    }

    /** Registers the snapshot supplier for a document; call {@link #markDirty} after changes. */
    public void register(String name, Supplier<Object> snapshot) {
        sources.put(name, snapshot);
    }

    public void markDirty(String name) {
        if (persist) dirty.put(name, Boolean.TRUE);
    }

    public synchronized void flush() {
        for (String name : dirty.keySet()) {
            dirty.remove(name);
            Supplier<Object> s = sources.get(name);
            if (s == null) continue;
            try {
                Path tmp = dir.resolve(name + ".json.tmp");
                mapper.writeValue(tmp.toFile(), s.get());
                try {
                    Files.move(tmp, dir.resolve(name + ".json"), StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
                } catch (AtomicMoveNotSupportedException e) {
                    Files.move(tmp, dir.resolve(name + ".json"), StandardCopyOption.REPLACE_EXISTING);
                }
            } catch (Exception e) {
                log.warn("SecureTest: failed to persist {}: {}", name, e.getMessage());
            }
        }
    }

    public void shutdown() {
        flush();
        writer.shutdownNow();
    }
}
