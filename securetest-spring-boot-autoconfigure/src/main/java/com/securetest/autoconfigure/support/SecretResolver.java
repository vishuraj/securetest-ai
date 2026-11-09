package com.securetest.autoconfigure.support;

import org.springframework.core.env.Environment;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.function.Function;

/**
 * Resolves secret references (SEC-006) without ever persisting the value:
 * <ul>
 *   <li>{@code env://NAME} – environment variable</li>
 *   <li>{@code prop://some.property} – Spring property (e.g. from Spring Cloud Vault / Config)</li>
 *   <li>{@code file:///run/secrets/x} – mounted secret file (Docker/Kubernetes)</li>
 *   <li>{@code secret://path} / {@code vault://path} – delegated to a pluggable {@link SecretManagerBridge}, else to property "path"</li>
 * </ul>
 */
public class SecretResolver {

    /** Extension point for an external secret manager (AWS Secrets Manager, Azure Key Vault, HashiCorp Vault...). */
    @FunctionalInterface
    public interface SecretManagerBridge extends Function<String, String> { }

    private final Environment env;
    private final SecretManagerBridge bridge;

    public SecretResolver(Environment env, SecretManagerBridge bridge) {
        this.env = env;
        this.bridge = bridge;
    }

    public String resolve(String ref) {
        if (ref == null || ref.isBlank()) return null;
        try {
            if (ref.startsWith("env://")) return System.getenv(ref.substring(6));
            if (ref.startsWith("prop://")) return env.getProperty(ref.substring(7));
            if (ref.startsWith("file://")) {
                Path p = Path.of(java.net.URI.create(ref.startsWith("file:///") ? ref : "file:///" + ref.substring(7)));
                return Files.readString(p, StandardCharsets.UTF_8).trim();
            }
            if (ref.startsWith("secret://") || ref.startsWith("vault://")) {
                String key = ref.substring(ref.indexOf("://") + 3);
                if (bridge != null) return bridge.apply(key);
                String v = env.getProperty(key.replace('/', '.'));
                return v != null ? v : env.getProperty(key);
            }
        } catch (IOException | RuntimeException e) {
            return null;
        }
        return null;
    }

    public boolean isResolvable(String ref) {
        String v = resolve(ref);
        return v != null && !v.isEmpty();
    }
}
