package com.securetest.controlplane;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Runs the Flyway schema and the registration / finding paths against a real PostgreSQL.
 * Skipped automatically when no Docker engine is available.
 */
@Testcontainers(disabledWithoutDocker = true)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "securetest.control-plane.bootstrap.tenant-slug=acme",
        "securetest.control-plane.bootstrap.enrollment-token=acme-enrollment-token-0001",
        "securetest.control-plane.workers.tokens=worker-fleet-token-0001"
})
class PostgresSchemaTest {

    @Container
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:16-alpine");

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry r) {
        r.add("spring.datasource.url", POSTGRES::getJdbcUrl);
        r.add("spring.datasource.username", POSTGRES::getUsername);
        r.add("spring.datasource.password", POSTGRES::getPassword);
        r.add("spring.security.oauth2.resourceserver.jwt.public-key-location", TestJwt::publicKeyLocation);
    }

    @Autowired TestRestTemplate http;
    @Autowired JdbcClient jdbc;

    @Test
    void schemaMigratesAndRegistrationWorks() {
        List<String> tables = jdbc.sql("SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'")
                .query(String.class).list();
        assertThat(tables).contains("tenant", "organization", "project", "application", "environment", "agent_registration",
                "finding", "scan_job", "report", "audit_event", "enrollment_token", "worker");

        var headers = ControlPlaneApiTest.bearer("acme-enrollment-token-0001");
        var r = http.exchange("/api/v1/agents/register", HttpMethod.POST,
                new HttpEntity<>(ControlPlaneApiTest.agentPayload("orders"), headers), ControlPlaneApiTest.MAP);
        assertThat(r.getStatusCode().value()).isEqualTo(200);

        var inv = http.exchange("/api/v1/inventory", HttpMethod.GET,
                new HttpEntity<>(ControlPlaneApiTest.bearer(TestJwt.token("v", "acme", "VIEWER"))),
                new ParameterizedTypeReference<Map<String, Object>>() { }).getBody();
        assertThat((List<?>) inv.get("applications")).hasSize(1);
        assertThat(http.exchange("/api/v1/scans", HttpMethod.GET,
                new HttpEntity<>(ControlPlaneApiTest.bearer(TestJwt.token("v", "acme", "VIEWER"))), ControlPlaneApiTest.LIST)
                .getStatusCode().value()).isEqualTo(200);
    }
}
