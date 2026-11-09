package com.securetest.core.util;

import com.securetest.core.spi.CommandRunner;
import com.securetest.core.spi.ScanRejectedException;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

/**
 * Starts external processes only when the executable is allowlisted. Output is bounded,
 * the process is killed on timeout and arguments are checked for shell metacharacters
 * when a Windows batch wrapper must be used.
 */
public class AllowlistCommandRunner implements CommandRunner {

    private static final boolean WINDOWS = System.getProperty("os.name", "").toLowerCase(Locale.ROOT).contains("win");
    private static final int MAX_OUTPUT = 8 * 1024 * 1024;
    private static final Pattern CMD_META = Pattern.compile("[&|<>^%\"\\r\\n]");

    private final Set<String> allowed;

    public AllowlistCommandRunner(Set<String> allowed) {
        this.allowed = allowed;
    }

    private static String baseName(String executable) {
        String name = Path.of(executable).getFileName().toString().toLowerCase(Locale.ROOT);
        return name.replaceAll("\\.(exe|cmd|bat|sh)$", "");
    }

    @Override
    public boolean isAllowed(String executable) {
        String base = baseName(executable);
        return allowed.stream().anyMatch(a -> baseName(a).equals(base));
    }

    @Override
    public Optional<Path> locate(String executable) {
        Path direct = Path.of(executable);
        if (direct.isAbsolute()) return Files.isRegularFile(direct) ? Optional.of(direct) : Optional.empty();
        String path = System.getenv("PATH");
        if (path == null) return Optional.empty();
        List<String> exts = WINDOWS ? List.of(".exe", ".cmd", ".bat", "") : List.of("");
        for (String dir : path.split(File.pathSeparator)) {
            if (dir.isBlank()) continue;
            for (String ext : exts) {
                try {
                    Path p = Path.of(dir.trim(), executable + ext);
                    if (Files.isRegularFile(p) && (WINDOWS || Files.isExecutable(p))) return Optional.of(p);
                } catch (RuntimeException ignored) {
                    // invalid PATH entry
                }
            }
        }
        return Optional.empty();
    }

    @Override
    public CommandResult run(List<String> command, Path workingDirectory, Duration timeout)
            throws IOException, InterruptedException {
        return run(command, workingDirectory, timeout, java.util.Map.of());
    }

    @Override
    public CommandResult run(List<String> command, Path workingDirectory, Duration timeout, java.util.Map<String, String> env)
            throws IOException, InterruptedException {
        if (command.isEmpty()) throw new ScanRejectedException("Empty command.");
        String exe = command.get(0);
        if (!isAllowed(exe)) {
            throw new ScanRejectedException("Command '" + baseName(exe) + "' is not allowlisted. Add it to "
                    + "securetest.execution.allowed-commands to permit execution.");
        }
        Path resolved = locate(exe).orElseThrow(() -> new ScanRejectedException("Executable '" + exe + "' was not found on the PATH."));
        List<String> full = new ArrayList<>();
        String lower = resolved.toString().toLowerCase(Locale.ROOT);
        if (WINDOWS && (lower.endsWith(".cmd") || lower.endsWith(".bat"))) {
            for (String arg : command.subList(1, command.size())) {
                if (CMD_META.matcher(arg).find()) throw new ScanRejectedException("Argument contains shell metacharacters: " + arg);
            }
            full.add("cmd.exe");
            full.add("/c");
        }
        full.add(resolved.toString());
        full.addAll(command.subList(1, command.size()));

        ProcessBuilder pb = new ProcessBuilder(full);
        env.forEach((k, v) -> {
            if (!k.matches("[A-Z][A-Z0-9_]{0,63}") || k.equals("PATH") || k.startsWith("JAVA_TOOL") || k.equals("LD_PRELOAD")) {
                throw new ScanRejectedException("Environment variable not allowed: " + k);
            }
            pb.environment().put(k, v);
        });
        if (workingDirectory != null) pb.directory(workingDirectory.toFile());
        long start = System.nanoTime();
        Process p = pb.start();
        p.getOutputStream().close();
        StreamCollector out = new StreamCollector(p.getInputStream());
        StreamCollector err = new StreamCollector(p.getErrorStream());
        out.start();
        err.start();
        boolean finished;
        try {
            finished = p.waitFor(timeout.toMillis(), TimeUnit.MILLISECONDS);
        } catch (InterruptedException e) {
            p.descendants().forEach(ProcessHandle::destroyForcibly);
            p.destroyForcibly();
            throw e;
        }
        if (!finished) {
            p.descendants().forEach(ProcessHandle::destroyForcibly);
            p.destroyForcibly();
        }
        out.join(2000);
        err.join(2000);
        long ms = (System.nanoTime() - start) / 1_000_000;
        return new CommandResult(finished ? p.exitValue() : -1, out.text(), err.text(), ms, !finished);
    }

    private static final class StreamCollector extends Thread {
        private final InputStream in;
        private final ByteArrayOutputStream buf = new ByteArrayOutputStream();

        StreamCollector(InputStream in) {
            this.in = in;
            setDaemon(true);
            setName("securetest-proc-io");
        }

        @Override
        public void run() {
            byte[] b = new byte[8192];
            int n;
            try {
                while ((n = in.read(b)) > 0) {
                    if (buf.size() < MAX_OUTPUT) buf.write(b, 0, Math.min(n, MAX_OUTPUT - buf.size()));
                }
            } catch (IOException ignored) {
                // process ended
            }
        }

        String text() { return buf.toString(StandardCharsets.UTF_8); }
    }
}
