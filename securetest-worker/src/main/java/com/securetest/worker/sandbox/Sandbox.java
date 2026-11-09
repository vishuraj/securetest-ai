package com.securetest.worker.sandbox;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.securetest.worker.WorkerProperties;
import com.securetest.worker.sandbox.SandboxProtocol.Request;
import com.securetest.worker.sandbox.SandboxProtocol.Result;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.function.BiConsumer;
import java.util.function.BooleanSupplier;
import java.util.stream.Stream;

/**
 * Runs one scan in isolation. The job directory is the only thing shared with the sandbox.
 * Subclasses decide how the isolated process is started ({@link ContainerSandbox}, {@link ProcessSandbox}).
 */
public abstract class Sandbox {

    private static final Logger log = LoggerFactory.getLogger(Sandbox.class);

    protected final WorkerProperties.Sandbox cfg;
    private final ObjectMapper mapper = SandboxProtocol.mapper();

    protected Sandbox(WorkerProperties.Sandbox cfg) { this.cfg = cfg; }

    public static Sandbox create(WorkerProperties.Sandbox cfg) {
        return switch (cfg.getMode().toLowerCase(java.util.Locale.ROOT)) {
            case "process" -> new ProcessSandbox(cfg);
            case "container" -> new ContainerSandbox(cfg);
            default -> throw new IllegalArgumentException("Unknown sandbox mode '" + cfg.getMode() + "' (container | process)");
        };
    }

    public abstract String mode();

    /** Builds the command that runs {@code sandbox /job/request.json /job/result.json} for the given job dir. */
    protected abstract List<String> command(Path jobDir, String jobId);

    /** Called when the scan must be stopped early (timeout or cancellation). */
    protected void kill(Process p, String jobId) {
        p.descendants().forEach(ProcessHandle::destroyForcibly);
        p.destroyForcibly();
    }

    /**
     * @param progress   receives (percent, message) whenever the sandbox reports progress
     * @param cancelled  polled once a second; true stops the sandbox
     */
    public Result run(Request request, BiConsumer<Integer, String> progress, BooleanSupplier cancelled) {
        Path jobDir = null;
        try {
            Path base = cfg.getWorkDir() == null ? Path.of(System.getProperty("java.io.tmpdir")) : Path.of(cfg.getWorkDir());
            Files.createDirectories(base);
            jobDir = Files.createTempDirectory(base, "securetest-job-");
            mapper.writeValue(jobDir.resolve(SandboxProtocol.REQUEST).toFile(), request);
            Path output = jobDir.resolve("sandbox.log");
            ProcessBuilder pb = new ProcessBuilder(command(jobDir, request.jobId()))
                    .redirectErrorStream(true)
                    .redirectOutput(output.toFile());
            sanitizeEnvironment(pb);
            Process p = pb.start();
            long deadline = System.nanoTime() + cfg.getTimeout().toNanos();
            String lastProgress = null;
            while (!p.waitFor(1, TimeUnit.SECONDS)) {
                String current = readQuietly(jobDir.resolve(SandboxProtocol.PROGRESS));
                if (current != null && !current.equals(lastProgress)) {
                    lastProgress = current;
                    String[] parts = current.split("\t", 2);
                    try {
                        progress.accept(Integer.parseInt(parts[0].trim()), parts.length > 1 ? parts[1] : "");
                    } catch (NumberFormatException ignored) {
                        // malformed progress line
                    }
                }
                if (cancelled.getAsBoolean()) {
                    kill(p, request.jobId());
                    return Result.failed("Cancelled");
                }
                if (System.nanoTime() > deadline) {
                    kill(p, request.jobId());
                    return Result.failed("Sandbox timed out after " + cfg.getTimeout());
                }
            }
            Path resultFile = jobDir.resolve(SandboxProtocol.RESULT);
            if (!Files.exists(resultFile)) {
                String tail = tail(output, 2000);
                return Result.failed("Sandbox exited with code " + p.exitValue() + " and no result" + (tail.isBlank() ? "" : ": " + tail));
            }
            return mapper.readValue(resultFile.toFile(), Result.class);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return Result.failed("Worker interrupted");
        } catch (Exception e) {
            log.warn("Sandbox failure for job {}: {}", request.jobId(), e.toString());
            return Result.failed("Sandbox failure: " + e.getMessage());
        } finally {
            deleteQuietly(jobDir);
        }
    }

    /** The sandbox inherits no secrets: only what a JVM / container CLI needs to start. */
    protected void sanitizeEnvironment(ProcessBuilder pb) {
        var env = pb.environment();
        var keep = new java.util.HashMap<String, String>();
        for (String k : List.of("PATH", "Path", "SystemRoot", "SYSTEMROOT", "WINDIR", "TEMP", "TMP", "TMPDIR", "HOME", "USERPROFILE",
                "DOCKER_HOST", "DOCKER_CONFIG", "DOCKER_CONTEXT", "XDG_RUNTIME_DIR", "JAVA_HOME", "LANG")) {
            String v = env.get(k);
            if (v != null) keep.put(k, v);
        }
        env.clear();
        env.putAll(keep);
    }

    private static String readQuietly(Path p) {
        try {
            return Files.exists(p) ? Files.readString(p, StandardCharsets.UTF_8) : null;
        } catch (IOException e) {
            return null;
        }
    }

    private static String tail(Path p, int max) {
        String s = readQuietly(p);
        if (s == null) return "";
        s = s.strip();
        return s.length() <= max ? s : s.substring(s.length() - max);
    }

    private static void deleteQuietly(Path dir) {
        if (dir == null) return;
        try (Stream<Path> walk = Files.walk(dir)) {
            walk.sorted(Comparator.reverseOrder()).forEach(p -> {
                try {
                    Files.deleteIfExists(p);
                } catch (IOException ignored) {
                    // best effort
                }
            });
        } catch (IOException ignored) {
            // best effort
        }
    }
}
