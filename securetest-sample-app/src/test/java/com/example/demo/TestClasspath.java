package com.example.demo;

/**
 * The remote-scan test puts the control plane and the worker on this module's test classpath (Spring Security,
 * JDBC, Flyway, H2). The sample app itself uses none of them, so its test contexts switch those auto-configurations
 * off to stay identical to the real app.
 */
final class TestClasspath {
    private TestClasspath() { }

    static final String EXCLUDE_CONTROL_PLANE_AUTOCONFIG = "spring.autoconfigure.exclude="
            + "org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration,"
            + "org.springframework.boot.autoconfigure.security.servlet.SecurityFilterAutoConfiguration,"
            + "org.springframework.boot.autoconfigure.security.servlet.UserDetailsServiceAutoConfiguration,"
            + "org.springframework.boot.autoconfigure.security.oauth2.resource.servlet.OAuth2ResourceServerAutoConfiguration,"
            + "org.springframework.boot.actuate.autoconfigure.security.servlet.ManagementWebSecurityAutoConfiguration,"
            + "org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration,"
            + "org.springframework.boot.autoconfigure.flyway.FlywayAutoConfiguration";
}
