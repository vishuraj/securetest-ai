package com.securetest.worker.sandbox;

import com.securetest.worker.WorkerApplication;
import com.securetest.worker.WorkerProperties;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * Runs each scan in a separate, short-lived JVM with a clean environment and its own heap limit.
 * Weaker isolation than {@link ContainerSandbox} (same user, same network, same file system), so it is meant
 * for development, CI and hosts without a container engine.
 */
public class ProcessSandbox extends Sandbox {

    public ProcessSandbox(WorkerProperties.Sandbox cfg) { super(cfg); }

    @Override public String mode() { return "process"; }

    @Override
    protected List<String> command(Path jobDir, String jobId) {
        String java = Path.of(System.getProperty("java.home"), "bin", "java").toString();
        List<String> c = new ArrayList<>();
        c.add(java);
        c.addAll(cfg.getJvmOptions());
        String self = selfJar();
        if (self != null) {
            // running from the executable (Spring Boot) jar
            c.add("-jar");
            c.add(self);
            c.add("sandbox");
        } else {
            c.add("-cp");
            c.add(System.getProperty("java.class.path"));
            c.add(SandboxMain.class.getName());
        }
        c.add(jobDir.resolve(SandboxProtocol.REQUEST).toAbsolutePath().toString());
        c.add(jobDir.resolve(SandboxProtocol.RESULT).toAbsolutePath().toString());
        return c;
    }

    /** Path of the executable jar when the worker runs as {@code java -jar}, else null. */
    static String selfJar() {
        try {
            var src = WorkerApplication.class.getProtectionDomain().getCodeSource();
            String loc = src == null ? "" : src.getLocation().toString();
            if (!loc.startsWith("nested:") && !loc.startsWith("jar:")) return null;
            String cp = System.getProperty("java.class.path");
            return cp != null && cp.endsWith(".jar") && !cp.contains(java.io.File.pathSeparator) ? cp : null;
        } catch (SecurityException e) {
            return null;
        }
    }
}
