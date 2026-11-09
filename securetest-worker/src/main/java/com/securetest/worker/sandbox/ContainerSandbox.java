package com.securetest.worker.sandbox;

import com.securetest.worker.WorkerProperties;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * Runs each scan in a throw-away, locked-down container of the worker image:
 * read-only root file system, all capabilities dropped, no privilege escalation, non-root user,
 * memory / CPU / PID limits, and a dedicated network. Only the job directory is mounted.
 */
public class ContainerSandbox extends Sandbox {

    public ContainerSandbox(WorkerProperties.Sandbox cfg) { super(cfg); }

    @Override public String mode() { return "container"; }

    static String containerName(String jobId) {
        return "securetest-job-" + jobId.replaceAll("[^a-zA-Z0-9_.-]", "");
    }

    static final String FALLBACK_USER = "65532:65532";

    /**
     * Container user. Default: the worker's own non-root uid:gid, so the sandbox can write {@code result.json}
     * into the (mode 700) job directory without widening its permissions. Never root.
     */
    String containerUser() {
        if (cfg.getUser() != null && !cfg.getUser().isBlank()) return cfg.getUser().trim();
        try {
            Class<?> unix = Class.forName("com.sun.security.auth.module.UnixSystem");
            Object sys = unix.getDeclaredConstructor().newInstance();
            long uid = (long) unix.getMethod("getUid").invoke(sys);
            long gid = (long) unix.getMethod("getGid").invoke(sys);
            if (uid != 0) return uid + ":" + gid;
        } catch (Throwable ignored) {
            // not a Unix host (e.g. Docker Desktop on Windows): file ownership is not enforced on the mount
        }
        return FALLBACK_USER;
    }

    @Override
    protected List<String> command(Path jobDir, String jobId) {
        List<String> c = new ArrayList<>(List.of(
                cfg.getEngine(), "run", "--rm",
                "--name", containerName(jobId),
                "--network", cfg.getNetwork(),
                "--read-only",
                "--tmpfs", "/tmp:rw,noexec,nosuid,size=256m",
                "--cap-drop", "ALL",
                "--security-opt", "no-new-privileges",
                "--user", containerUser(),
                "--pids-limit", String.valueOf(cfg.getPidsLimit()),
                "--memory", cfg.getMemory(),
                "--cpus", cfg.getCpus(),
                "--env", "JAVA_TOOL_OPTIONS=-XX:MaxRAMPercentage=75",
                "--volume", jobDir.toAbsolutePath() + ":/job:rw",
                cfg.getImage(),
                "sandbox", "/job/" + SandboxProtocol.REQUEST, "/job/" + SandboxProtocol.RESULT));
        return c;
    }

    @Override
    protected void kill(Process p, String jobId) {
        try {
            new ProcessBuilder(cfg.getEngine(), "kill", containerName(jobId)).redirectErrorStream(true)
                    .redirectOutput(ProcessBuilder.Redirect.DISCARD).start().waitFor(20, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } catch (Exception ignored) {
            // fall through to killing the CLI process
        }
        super.kill(p, jobId);
    }
}
