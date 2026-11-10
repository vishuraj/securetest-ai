package com.securetest.controlplane;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.PropertySource;
import org.springframework.scheduling.annotation.EnableScheduling;

/**
 * SecureTest AI enterprise control plane (SRS deployment profile "Enterprise Control Plane").
 * <p>
 * Run with {@code java -jar securetest-control-plane-1.0.1-exec.jar}; see the README for the required
 * PostgreSQL and OIDC settings. Built-in defaults live in {@code securetest/controlplane/defaults.properties}.
 */
@SpringBootApplication
@EnableScheduling
@EnableConfigurationProperties(ControlPlaneProperties.class)
@PropertySource("classpath:securetest/controlplane/defaults.properties")
public class ControlPlaneApplication {

    public static void main(String[] args) {
        builder().run(args);
    }

    public static SpringApplicationBuilder builder() {
        return new SpringApplicationBuilder(ControlPlaneApplication.class);
    }
}
