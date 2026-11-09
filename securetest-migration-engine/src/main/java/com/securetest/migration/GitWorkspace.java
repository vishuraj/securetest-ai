package com.securetest.migration;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.TimeUnit;

/** Thin wrapper over the git CLI for baseline capture, branches, commits and reverts. */
public class GitWorkspace {

    public record Result(int exit, String out) {
        public boolean ok() { return exit == 0; }
    }

    private final boolean enabled;

    public GitWorkspace(boolean enabled) {
        this.enabled = enabled;
    }

    public boolean isRepository(Path root) {
        if (!enabled || root == null) return false;
        return run(root, "rev-parse", "--is-inside-work-tree").out().trim().equals("true");
    }

    public Optional<String> head(Path root) {
        if (!isRepository(root)) return Optional.empty();
        Result r = run(root, "rev-parse", "HEAD");
        return r.ok() ? Optional.of(r.out().trim()) : Optional.empty();
    }

    public Optional<String> branch(Path root) {
        if (!isRepository(root)) return Optional.empty();
        Result r = run(root, "rev-parse", "--abbrev-ref", "HEAD");
        return r.ok() ? Optional.of(r.out().trim()) : Optional.empty();
    }

    /** Dirty paths, relative to {@code root}. */
    public Set<String> dirtyFiles(Path root) {
        Set<String> out = new LinkedHashSet<>();
        if (!isRepository(root)) return out;
        String prefix = run(root, "rev-parse", "--show-prefix").out().trim();
        Result r = run(root, "status", "--porcelain", "--untracked-files=normal");
        for (String line : r.out().split("\\r?\\n")) {
            if (line.length() < 4) continue;
            String p = line.substring(3).trim();
            if (p.contains(" -> ")) p = p.substring(p.indexOf(" -> ") + 4);
            if (p.startsWith("\"") && p.endsWith("\"")) p = p.substring(1, p.length() - 1);
            if (!prefix.isEmpty()) {
                if (!p.startsWith(prefix)) continue;
                p = p.substring(prefix.length());
            }
            out.add(p);
        }
        return out;
    }

    public Result createBranch(Path root, String name) { return run(root, "checkout", "-b", name); }

    public Result add(Path root, List<String> paths) {
        List<String> args = new ArrayList<>(List.of("add", "--"));
        args.addAll(paths);
        return run(root, args.toArray(String[]::new));
    }

    public Result commit(Path root, String message) {
        return run(root, "-c", "user.name=SecureTest", "-c", "user.email=securetest@localhost", "commit", "-m", message);
    }

    public Result revert(Path root, String commit) {
        return run(root, "-c", "user.name=SecureTest", "-c", "user.email=securetest@localhost", "revert", "--no-edit", commit);
    }

    public Result revertAbort(Path root) { return run(root, "revert", "--abort"); }

    public Result run(Path root, String... args) {
        if (!enabled) return new Result(-1, "git integration disabled");
        List<String> cmd = new ArrayList<>();
        cmd.add("git");
        cmd.addAll(List.of(args));
        try {
            ProcessBuilder pb = new ProcessBuilder(cmd).directory(root.toFile()).redirectErrorStream(true);
            pb.environment().put("GIT_TERMINAL_PROMPT", "0");
            Process p = pb.start();
            p.getOutputStream().close();
            ByteArrayOutputStream buf = new ByteArrayOutputStream();
            try (InputStream in = p.getInputStream()) {
                in.transferTo(buf);
            }
            if (!p.waitFor(60, TimeUnit.SECONDS)) {
                p.destroyForcibly();
                return new Result(-1, "git timed out");
            }
            return new Result(p.exitValue(), buf.toString(StandardCharsets.UTF_8));
        } catch (IOException e) {
            return new Result(-1, "git not available: " + e.getMessage());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return new Result(-1, "interrupted");
        }
    }

    public static boolean exists(Path root) {
        return root != null && Files.isDirectory(root.resolve(".git"));
    }
}
