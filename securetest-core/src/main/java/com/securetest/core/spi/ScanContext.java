package com.securetest.core.spi;

import com.securetest.core.model.Finding;

import java.nio.file.Path;
import java.util.Map;
import java.util.Optional;

/** Everything a scanner is allowed to use. Implemented by the runtime. */
public interface ScanContext {

    String jobId();

    /** Validated, non-secret options for this run. */
    Map<String, String> options();

    default String option(String key, String def) {
        String v = options().get(key);
        return v == null || v.isBlank() ? def : v.trim();
    }

    default int intOption(String key, int def, int min, int max) {
        try {
            int v = Integer.parseInt(option(key, String.valueOf(def)));
            return Math.max(min, Math.min(max, v));
        } catch (NumberFormatException e) {
            return def;
        }
    }

    default boolean boolOption(String key, boolean def) {
        return Boolean.parseBoolean(option(key, String.valueOf(def)));
    }

    /** Resolves a credential field (secret reference or in-memory value). Never log the result. */
    String secret(String key);

    /** Authorized source workspace, if configured. */
    Optional<Path> sourceRoot();

    TargetGuard targets();

    HttpProbe http();

    CommandRunner commands();

    ApplicationInfo application();

    void report(Finding finding);

    void progress(int percent, String message);

    void log(String message);

    boolean cancelled();

    /** Structured result shown in the module page (e.g. load-test statistics). */
    void putResult(String key, Object value);

    /** Stores an evidence artifact (SBOM, raw tool output...). */
    void attachArtifact(String name, String contentType, byte[] data);

    default void checkCancelled() throws InterruptedException {
        if (cancelled() || Thread.currentThread().isInterrupted()) {
            throw new InterruptedException("Scan cancelled");
        }
    }
}
