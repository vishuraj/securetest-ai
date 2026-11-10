package com.securetest.worker;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

/** {@code securetest.worker.*} settings. */
@ConfigurationProperties(prefix = "securetest.worker")
public class WorkerProperties {

    /** Base URL of the control plane, e.g. https://securetest.example.com. */
    private String controlPlaneUrl;
    /** Fleet token (must match one of the control plane's securetest.control-plane.workers.tokens). */
    private String token;
    /** Stable worker id; defaults to the host name plus a random suffix. */
    private String id;
    private String name;
    private Duration pollInterval = Duration.ofSeconds(5);
    private Duration heartbeatInterval = Duration.ofSeconds(15);
    /** Parallel scans per worker. */
    private int concurrency = 2;
    /**
     * Hosts this worker is authorized to test (host names, *.domain wildcards or CIDR ranges). Enforced inside the
     * sandbox for every request a scanner makes, independently of what the control plane asks for.
     */
    private List<String> allowedTargets = new ArrayList<>();
    /** Optional subset of scanner ids to serve; empty = every remote-capable scanner. */
    private List<String> scanners = new ArrayList<>();
    /** External tools the sandbox may start (Trivy, ZAP, JMeter...); empty = none. */
    private List<String> allowedCommands = new ArrayList<>();
    private int maxRequestsPerSecond = 10;
    private final Sandbox sandbox = new Sandbox();

    public static class Sandbox {
        /** {@code container} (default; docker/podman) or {@code process} (child JVM; for development and tests). */
        private String mode = "container";
        /** Container engine CLI. */
        private String engine = "docker";
        /** Image that contains this worker jar; it is started with the {@code sandbox} argument. */
        private String image = "securetest/worker:1.0.2";
        /** Container network; must reach the targets and nothing else (use a dedicated egress-filtered network). */
        private String network = "bridge";
        private String memory = "1g";
        private String cpus = "1.0";
        private int pidsLimit = 256;
        /**
         * uid:gid inside the container. Default: the worker's own uid:gid (never root). If the worker runs as root,
         * set a non-root user here and make {@code work-dir} writable for it.
         */
        private String user;
        private Duration timeout = Duration.ofMinutes(30);
        /** Directory for per-job request/result files. Defaults to the system temp directory. */
        private String workDir;
        /** JVM options for the child process in {@code process} mode. */
        private List<String> jvmOptions = new ArrayList<>(List.of("-Xmx512m"));

        public String getMode() { return mode; }
        public void setMode(String mode) { this.mode = mode; }
        public String getEngine() { return engine; }
        public void setEngine(String engine) { this.engine = engine; }
        public String getImage() { return image; }
        public void setImage(String image) { this.image = image; }
        public String getNetwork() { return network; }
        public void setNetwork(String network) { this.network = network; }
        public String getMemory() { return memory; }
        public void setMemory(String memory) { this.memory = memory; }
        public String getCpus() { return cpus; }
        public void setCpus(String cpus) { this.cpus = cpus; }
        public String getUser() { return user; }
        public void setUser(String user) { this.user = user; }
        public int getPidsLimit() { return pidsLimit; }
        public void setPidsLimit(int pidsLimit) { this.pidsLimit = pidsLimit; }
        public Duration getTimeout() { return timeout; }
        public void setTimeout(Duration timeout) { this.timeout = timeout; }
        public String getWorkDir() { return workDir; }
        public void setWorkDir(String workDir) { this.workDir = workDir; }
        public List<String> getJvmOptions() { return jvmOptions; }
        public void setJvmOptions(List<String> jvmOptions) { this.jvmOptions = jvmOptions; }
    }

    public String getControlPlaneUrl() { return controlPlaneUrl; }
    public void setControlPlaneUrl(String v) { this.controlPlaneUrl = v; }
    public String getToken() { return token; }
    public void setToken(String v) { this.token = v; }
    public String getId() { return id; }
    public void setId(String v) { this.id = v; }
    public String getName() { return name; }
    public void setName(String v) { this.name = v; }
    public Duration getPollInterval() { return pollInterval; }
    public void setPollInterval(Duration v) { this.pollInterval = v; }
    public Duration getHeartbeatInterval() { return heartbeatInterval; }
    public void setHeartbeatInterval(Duration v) { this.heartbeatInterval = v; }
    public int getConcurrency() { return concurrency; }
    public void setConcurrency(int v) { this.concurrency = v; }
    public List<String> getAllowedTargets() { return allowedTargets; }
    public void setAllowedTargets(List<String> v) { this.allowedTargets = v; }
    public List<String> getScanners() { return scanners; }
    public void setScanners(List<String> v) { this.scanners = v; }
    public List<String> getAllowedCommands() { return allowedCommands; }
    public void setAllowedCommands(List<String> v) { this.allowedCommands = v; }
    public int getMaxRequestsPerSecond() { return maxRequestsPerSecond; }
    public void setMaxRequestsPerSecond(int v) { this.maxRequestsPerSecond = v; }
    public Sandbox getSandbox() { return sandbox; }
}
