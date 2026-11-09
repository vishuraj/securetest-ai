package com.securetest.core.spi;

import java.io.IOException;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Optional;

/**
 * Runs external tools (Trivy, Checkov, JMeter, test commands...). Only executables on the
 * configured allowlist ({@code securetest.execution.allowed-commands}) can be started.
 */
public interface CommandRunner {

    boolean isAllowed(String executable);

    /** Locates an executable on the PATH. */
    Optional<Path> locate(String executable);

    CommandResult run(List<String> command, Path workingDirectory, Duration timeout)
            throws IOException, InterruptedException;

    /** Same as {@link #run(List, Path, Duration)} with extra environment variables (names: A-Z, 0-9, _). */
    default CommandResult run(List<String> command, Path workingDirectory, Duration timeout, java.util.Map<String, String> env)
            throws IOException, InterruptedException {
        return run(command, workingDirectory, timeout);
    }

    record CommandResult(int exitCode, String stdout, String stderr, long durationMs, boolean timedOut) {
        public boolean success() { return !timedOut && exitCode == 0; }
    }
}
