package com.securetest.autoconfigure.support;

import com.securetest.autoconfigure.SecureTestProperties;
import com.securetest.core.spi.ApplicationInfo;
import org.springframework.boot.SpringBootVersion;
import org.springframework.boot.web.context.WebServerInitializedEvent;
import org.springframework.context.ApplicationListener;
import org.springframework.core.SpringVersion;
import org.springframework.core.env.Environment;

import java.lang.management.ManagementFactory;
import java.net.InetAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

/** Identity of the host application, its port and its source workspace. */
public class AppContext implements ApplicationListener<WebServerInitializedEvent> {

    private final Environment env;
    private final SecureTestProperties props;
    private final String version;
    private volatile Integer port;

    public AppContext(Environment env, SecureTestProperties props, String buildVersion) {
        this.env = env;
        this.props = props;
        this.version = buildVersion;
    }

    @Override
    public void onApplicationEvent(WebServerInitializedEvent event) {
        String ns = event.getApplicationContext().getServerNamespace();
        if (ns == null || ns.isEmpty()) port = event.getWebServer().getPort();
    }

    public List<String> profiles() {
        return Arrays.asList(env.getActiveProfiles());
    }

    public String environmentName() {
        if (props.getApplication().getEnvironment() != null) return props.getApplication().getEnvironment();
        return profiles().isEmpty() ? "local" : profiles().get(0);
    }

    public boolean productionLike() {
        return profiles().stream().map(p -> p.toLowerCase(Locale.ROOT)).anyMatch(p -> p.equals("prod") || p.equals("production") || p.equals("live"))
                || environmentName().toLowerCase(Locale.ROOT).startsWith("prod");
    }

    public String name() {
        return env.getProperty("spring.application.name", "application");
    }

    public String contextPath() {
        return env.getProperty("server.servlet.context-path", "");
    }

    public String selfBaseUrl() {
        int p = port != null ? port : env.getProperty("server.port", Integer.class, 8080);
        boolean ssl = env.getProperty("server.ssl.enabled", Boolean.class, false);
        return (ssl ? "https" : "http") + "://localhost:" + p + contextPath();
    }

    public Optional<Path> sourceRoot() {
        String configured = props.getWorkspace().getSourceRoot();
        if (configured != null && !configured.isBlank()) {
            Path p = Path.of(configured).toAbsolutePath().normalize();
            return Files.isDirectory(p) ? Optional.of(p) : Optional.empty();
        }
        Path cwd = Path.of(System.getProperty("user.dir")).toAbsolutePath().normalize();
        for (String marker : List.of("pom.xml", "build.gradle", "build.gradle.kts", ".git")) {
            if (Files.exists(cwd.resolve(marker))) return Optional.of(cwd);
        }
        return Optional.empty();
    }

    public String buildTool() {
        Optional<Path> root = sourceRoot();
        if (root.isEmpty()) return "unknown";
        if (Files.exists(root.get().resolve("pom.xml"))) return "Maven";
        if (Files.exists(root.get().resolve("build.gradle")) || Files.exists(root.get().resolve("build.gradle.kts"))) return "Gradle";
        return "unknown";
    }

    public ApplicationInfo info() {
        String host;
        try {
            host = InetAddress.getLocalHost().getHostName();
        } catch (Exception e) {
            host = "unknown";
        }
        return new ApplicationInfo(
                name(),
                props.getApplication().getServiceId() != null ? props.getApplication().getServiceId() : name() + "@" + environmentName(),
                version,
                environmentName(),
                profiles(),
                System.getProperty("java.version"),
                System.getProperty("java.vendor"),
                SpringBootVersion.getVersion(),
                SpringVersion.getVersion(),
                buildTool(),
                host,
                port,
                contextPath(),
                Instant.ofEpochMilli(ManagementFactory.getRuntimeMXBean().getStartTime()));
    }
}
