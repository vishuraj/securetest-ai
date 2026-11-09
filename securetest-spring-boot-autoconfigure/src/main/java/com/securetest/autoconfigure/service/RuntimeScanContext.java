package com.securetest.autoconfigure.service;

import com.securetest.autoconfigure.support.SecretResolver;
import com.securetest.core.model.Finding;
import com.securetest.core.model.ScanJob;
import com.securetest.core.spi.ApplicationInfo;
import com.securetest.core.spi.CommandRunner;
import com.securetest.core.spi.HttpProbe;
import com.securetest.core.spi.ScanContext;
import com.securetest.core.spi.TargetGuard;
import com.securetest.core.util.Redactor;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;

/** ScanContext implementation handed to scanners by the job service. Secret values live only in memory. */
class RuntimeScanContext implements ScanContext {

    private final ScanJob job;
    private final Map<String, String> options;
    private final Map<String, String> secrets;
    private final SecretResolver resolver;
    private final Optional<Path> sourceRoot;
    private final TargetGuard guard;
    private final HttpProbe http;
    private final CommandRunner commands;
    private final ApplicationInfo app;
    private final Path artifactDir;
    private final List<Finding> findings = Collections.synchronizedList(new ArrayList<>());
    final AtomicBoolean cancelled = new AtomicBoolean();
    private static final int MAX_FINDINGS = 20_000;

    RuntimeScanContext(ScanJob job, Map<String, String> options, Map<String, String> secrets, SecretResolver resolver,
                       Optional<Path> sourceRoot, TargetGuard guard, HttpProbe http, CommandRunner commands,
                       ApplicationInfo app, Path artifactDir) {
        this.job = job;
        this.options = options;
        this.secrets = secrets;
        this.resolver = resolver;
        this.sourceRoot = sourceRoot;
        this.guard = guard;
        this.http = http;
        this.commands = commands;
        this.app = app;
        this.artifactDir = artifactDir;
    }

    @Override public String jobId() { return job.id; }
    @Override public Map<String, String> options() { return options; }

    @Override
    public String secret(String key) {
        String v = secrets.get(key);
        if (v == null) return null;
        return Redactor.isReference(v) ? resolver.resolve(v) : v;
    }

    @Override public Optional<Path> sourceRoot() { return sourceRoot; }
    @Override public TargetGuard targets() { return guard; }
    @Override public HttpProbe http() { return http; }
    @Override public CommandRunner commands() { return commands; }
    @Override public ApplicationInfo application() { return app; }

    @Override
    public void report(Finding finding) {
        if (findings.size() < MAX_FINDINGS) findings.add(finding);
    }

    @Override
    public void progress(int percent, String message) {
        job.progress = Math.max(job.progress, Math.min(100, Math.max(0, percent)));
        job.progressMessage = message;
    }

    @Override
    public void log(String message) {
        job.appendLog(Redactor.redact(message));
    }

    @Override public boolean cancelled() { return cancelled.get(); }

    @Override
    public void putResult(String key, Object value) {
        job.results.put(key, value);
    }

    @Override
    public void attachArtifact(String name, String contentType, byte[] data) {
        String safe = name.replaceAll("[^\\w.-]", "_");
        try {
            Files.createDirectories(artifactDir);
            Files.write(artifactDir.resolve(safe), data);
            if (!job.artifacts.contains(safe)) job.artifacts.add(safe);
        } catch (IOException e) {
            log("Could not store artifact " + safe + ": " + e.getMessage());
        }
    }

    List<Finding> findings() { return findings; }
}
