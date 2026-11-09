package com.securetest.worker.sandbox;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.securetest.core.model.Finding;
import com.securetest.core.model.ScanJob;
import com.securetest.core.spi.ApplicationInfo;
import com.securetest.core.spi.PreflightCheck;
import com.securetest.core.spi.ScanContext;
import com.securetest.core.spi.Scanner;
import com.securetest.core.util.AllowlistCommandRunner;
import com.securetest.core.util.AllowlistTargetGuard;
import com.securetest.core.util.Fingerprints;
import com.securetest.core.util.GuardedHttpProbe;
import com.securetest.core.util.Redactor;
import com.securetest.worker.sandbox.SandboxProtocol.Request;
import com.securetest.worker.sandbox.SandboxProtocol.Result;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Entry point inside the sandbox: runs one scanner against one target and writes normalized findings.
 * Runs without Spring and without any credentials. Every outbound request goes through the allowlist guard.
 */
public final class SandboxMain {

    private static final int MAX_FINDINGS = 20_000;

    private SandboxMain() { }

    public static void main(String[] args) {
        if (args.length != 2) {
            System.err.println("usage: sandbox <request.json> <result.json>");
            System.exit(2);
        }
        ObjectMapper mapper = SandboxProtocol.mapper();
        Path resultFile = Path.of(args[1]);
        Result result;
        try {
            Request req = mapper.readValue(Path.of(args[0]).toFile(), Request.class);
            result = run(req, resultFile.resolveSibling(SandboxProtocol.PROGRESS));
        } catch (Throwable t) {
            result = Result.failed("Sandbox could not start: " + t.getClass().getSimpleName() + ": " + Redactor.redact(t.getMessage()));
        }
        try {
            Path tmp = resultFile.resolveSibling(SandboxProtocol.RESULT + ".tmp");
            mapper.writeValue(tmp.toFile(), result);
            Files.move(tmp, resultFile, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        } catch (Exception e) {
            System.err.println("Cannot write result: " + e);
            System.exit(1);
        }
        System.exit(0);
    }

    static Result run(Request req, Path progressFile) {
        long start = System.nanoTime();
        Result result = new Result();
        Context ctx = new Context(req, result, progressFile);
        try {
            Scanner scanner = instantiate(req.scannerClass());
            if (!scanner.descriptor().getId().equals(req.scannerId())) {
                throw new IllegalArgumentException("Scanner class does not implement " + req.scannerId());
            }
            ctx.moduleId = scanner.descriptor().getModuleId();
            ctx.log("Sandbox started for job " + req.jobId() + " (" + req.scannerId() + " -> " + req.targetUrl() + ")");
            ctx.targets().requireAllowedUrl(req.targetUrl());
            for (PreflightCheck check : scanner.preflight(ctx)) {
                ctx.log("Preflight " + check.name() + ": " + check.level() + " " + check.message());
                if (check.blocking()) throw new IllegalStateException("Preflight failed: " + check.name() + ": " + check.message());
            }
            scanner.scan(ctx);
            result.status = "COMPLETED";
        } catch (Throwable t) {
            result.status = "FAILED";
            result.error = t.getClass().getSimpleName() + ": " + Redactor.redact(String.valueOf(t.getMessage()));
            ctx.log("Scan failed: " + result.error);
        }
        // normalize
        Instant now = Instant.now();
        HashSet<String> seen = new HashSet<>();
        List<Finding> out = new ArrayList<>();
        for (Finding f : ctx.findings) {
            if (f.moduleId == null) f.moduleId = ctx.moduleId;
            f.source = req.scannerId();
            f.lastScanId = req.jobId();
            f.firstDetected = now;
            f.lastDetected = now;
            f.evidence = Redactor.redact(f.evidence);
            if (f.asset == null) f.asset = req.targetUrl();
            f.fingerprint = Fingerprints.of(f);
            if (seen.add(f.fingerprint)) out.add(f);
        }
        result.findings = out;
        result.log = ctx.job.log;
        result.durationMs = Duration.ofNanos(System.nanoTime() - start).toMillis();
        return result;
    }

    static Scanner instantiate(String className) throws ReflectiveOperationException {
        Class<?> c = Class.forName(className);
        if (!Scanner.class.isAssignableFrom(c)) throw new IllegalArgumentException(className + " is not a Scanner");
        return (Scanner) c.getDeclaredConstructor().newInstance();
    }

    /** ScanContext implementation used inside the sandbox. */
    static final class Context implements ScanContext {
        private final Request req;
        private final Result result;
        private final Path progressFile;
        private final AllowlistTargetGuard guard;
        private final GuardedHttpProbe http;
        private final AllowlistCommandRunner commands;
        private final ApplicationInfo app;
        final ScanJob job = new ScanJob();
        final List<Finding> findings = Collections.synchronizedList(new ArrayList<>());
        String moduleId;

        Context(Request req, Result result, Path progressFile) {
            this.req = req;
            this.result = result;
            this.progressFile = progressFile;
            this.job.id = req.jobId();
            // selfBaseUrl = the job's target, so scanners' "self" default means "the target of this job"
            this.guard = new AllowlistTargetGuard(req.allowedTargets() == null ? List.of() : req.allowedTargets(), req.targetUrl(), true);
            this.http = new GuardedHttpProbe(guard, Duration.ofSeconds(5), Duration.ofSeconds(30),
                    Math.max(1, Math.min(100, req.maxRequestsPerSecond())));
            this.commands = new AllowlistCommandRunner(new HashSet<>(req.allowedCommands() == null ? List.of() : req.allowedCommands()));
            SandboxProtocol.App a = req.application();
            this.app = new ApplicationInfo(a == null ? "remote" : a.name(), a == null ? "remote" : a.serviceId(), null,
                    a == null ? null : a.environment(), List.of(), System.getProperty("java.version"), System.getProperty("java.vendor"),
                    null, null, null, guard.selfBaseUrl() == null ? null : java.net.URI.create(guard.selfBaseUrl()).getHost(),
                    null, null, Instant.now());
        }

        @Override public String jobId() { return req.jobId(); }
        @Override public Map<String, String> options() { return req.options() == null ? Map.of() : req.options(); }
        /** Remote jobs never carry secrets. */
        @Override public String secret(String key) { return null; }
        @Override public Optional<Path> sourceRoot() { return Optional.empty(); }
        @Override public AllowlistTargetGuard targets() { return guard; }
        @Override public GuardedHttpProbe http() { return http; }
        @Override public AllowlistCommandRunner commands() { return commands; }
        @Override public ApplicationInfo application() { return app; }

        @Override
        public void report(Finding finding) {
            if (finding != null && findings.size() < MAX_FINDINGS) findings.add(finding);
        }

        @Override
        public void progress(int percent, String message) {
            try {
                Path tmp = progressFile.resolveSibling(SandboxProtocol.PROGRESS + ".tmp");
                Files.writeString(tmp, Math.max(0, Math.min(100, percent)) + "\t" + (message == null ? "" : Redactor.redact(message)),
                        StandardCharsets.UTF_8);
                Files.move(tmp, progressFile, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
            } catch (Exception ignored) {
                // progress is best effort
            }
        }

        @Override public void log(String message) { job.appendLog(Redactor.redact(message)); }
        @Override public boolean cancelled() { return false; } // the worker cancels by killing the sandbox

        @Override
        public void putResult(String key, Object value) {
            try {
                SandboxProtocol.mapper().writeValueAsString(value);
                result.results.put(key, value);
            } catch (Exception e) {
                result.results.put(key, String.valueOf(value));
            }
        }

        @Override
        public void attachArtifact(String name, String contentType, byte[] data) {
            log("Artifact '" + name + "' (" + (data == null ? 0 : data.length) + " bytes) not uploaded: remote artifacts are not supported yet");
        }
    }
}
