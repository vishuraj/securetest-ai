package com.securetest.controlplane;

import com.securetest.controlplane.store.JobStore;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/** Control plane API on an in-memory database (H2 in PostgreSQL mode, same Flyway schema). */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "spring.datasource.url=jdbc:h2:mem:cp-api;MODE=PostgreSQL;DATABASE_TO_LOWER=TRUE;DEFAULT_NULL_ORDERING=HIGH;DB_CLOSE_DELAY=-1",
        "securetest.control-plane.bootstrap.tenant-slug=acme",
        "securetest.control-plane.bootstrap.enrollment-token=acme-enrollment-token-0001",
        "securetest.control-plane.workers.tokens=worker-fleet-token-0001"
})
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class ControlPlaneApiTest {

    static final String ENROLL = "acme-enrollment-token-0001";
    static final String WORKER = "worker-fleet-token-0001";
    static final ParameterizedTypeReference<Map<String, Object>> MAP = new ParameterizedTypeReference<>() { };
    static final ParameterizedTypeReference<List<Map<String, Object>>> LIST = new ParameterizedTypeReference<>() { };

    @DynamicPropertySource
    static void oidc(DynamicPropertyRegistry r) {
        r.add("spring.security.oauth2.resourceserver.jwt.public-key-location", TestJwt::publicKeyLocation);
    }

    @Autowired TestRestTemplate http;
    @Autowired JobStore jobStore;

    String admin, security, viewer;

    @BeforeEach
    void tokens() {
        admin = TestJwt.token("alice", "acme", "ADMIN");
        security = TestJwt.token("sam", "acme", "SECURITY");
        viewer = TestJwt.token("victor", "acme", "VIEWER");
    }

    static HttpHeaders bearer(String token) {
        HttpHeaders h = new HttpHeaders();
        h.setContentType(MediaType.APPLICATION_JSON);
        if (token != null) h.setBearerAuth(token);
        return h;
    }

    <T> ResponseEntity<T> call(HttpMethod m, String path, String token, Object body, ParameterizedTypeReference<T> type) {
        return http.exchange(path, m, new HttpEntity<>(body, bearer(token)), type);
    }

    static Map<String, Object> agentPayload(String serviceId) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("serviceId", serviceId);
        m.put("application", "Orders");
        m.put("environment", "staging");
        m.put("version", "2.4.1");
        m.put("runtime", Map.of("java", "17.0.12", "springBoot", "3.5.16"));
        m.put("agentVersion", "1.0.0");
        m.put("capabilities", List.of("builtin-http-security", "builtin-static-analysis"));
        return m;
    }

    @Test
    @Order(1)
    void agentRegistrationNeedsAValidEnrollmentToken() {
        assertThat(call(HttpMethod.POST, "/api/v1/agents/register", null, agentPayload("orders"), MAP).getStatusCode().value()).isEqualTo(401);
        assertThat(call(HttpMethod.POST, "/api/v1/agents/register", "wrong-token", agentPayload("orders"), MAP).getStatusCode().value()).isEqualTo(401);
        // a user JWT is not an enrollment token
        assertThat(call(HttpMethod.POST, "/api/v1/agents/register", admin, agentPayload("orders"), MAP).getStatusCode().value()).isEqualTo(401);

        ResponseEntity<Map<String, Object>> first = call(HttpMethod.POST, "/api/v1/agents/register", ENROLL, agentPayload("orders"), MAP);
        assertThat(first.getStatusCode().value()).isEqualTo(200);
        assertThat(first.getBody()).containsEntry("status", "REGISTERED");
        assertThat(call(HttpMethod.POST, "/api/v1/agents/register", ENROLL, agentPayload("orders"), MAP).getBody())
                .containsEntry("status", "UPDATED");
    }

    @Test
    @Order(2)
    @SuppressWarnings("unchecked")
    void inventoryIsTenantIsolated() {
        Map<String, Object> inv = call(HttpMethod.GET, "/api/v1/inventory", viewer, null, MAP).getBody();
        List<Map<String, Object>> apps = (List<Map<String, Object>>) inv.get("applications");
        assertThat(apps).extracting(a -> a.get("serviceId")).containsExactly("orders");
        assertThat((List<?>) apps.get(0).get("agents")).hasSize(1);

        // a second tenant created by a platform admin sees nothing of acme
        String platform = TestJwt.token("root", null, "PLATFORM_ADMIN");
        assertThat(call(HttpMethod.POST, "/api/v1/admin/tenants", admin, Map.of("slug", "globex"), MAP).getStatusCode().value()).isEqualTo(403);
        assertThat(call(HttpMethod.POST, "/api/v1/admin/tenants", platform, Map.of("slug", "globex"), MAP).getStatusCode().value()).isEqualTo(201);
        String globex = TestJwt.token("gina", "globex", "ADMIN");
        Map<String, Object> other = call(HttpMethod.GET, "/api/v1/inventory", globex, null, MAP).getBody();
        assertThat((List<?>) other.get("applications")).isEmpty();
        assertThat(call(HttpMethod.GET, "/api/v1/agents", globex, null, LIST).getBody()).isEmpty();

        // tokens for unknown tenants or without credentials are refused
        assertThat(call(HttpMethod.GET, "/api/v1/inventory", TestJwt.token("x", "nope", "ADMIN"), null, MAP).getStatusCode().value()).isEqualTo(403);
        assertThat(call(HttpMethod.GET, "/api/v1/inventory", null, null, MAP).getStatusCode().value()).isEqualTo(401);
    }

    @Test
    @Order(3)
    @SuppressWarnings("unchecked")
    void jobQueueDispatchesToWorkersAndAggregatesFindings() {
        // worker advertises a passive scanner
        Map<String, Object> worker = Map.of("workerId", "w1", "name", "w1", "version", "1.0.0", "sandbox", "process",
                "scanners", List.of(Map.of("id", "builtin-http-security", "moduleId", "api-security", "name", "HTTP", "mode", "PASSIVE"),
                        Map.of("id", "builtin-port-scan", "moduleId", "network", "name", "Ports", "mode", "ACTIVE")));
        assertThat(call(HttpMethod.POST, "/api/v1/worker/register", "bad", worker, MAP).getStatusCode().value()).isEqualTo(401);
        assertThat(call(HttpMethod.POST, "/api/v1/worker/register", WORKER, worker, MAP).getStatusCode().value()).isEqualTo(200);

        Map<String, Object> scan = new LinkedHashMap<>();
        scan.put("serviceId", "orders");
        scan.put("scannerId", "builtin-http-security");
        scan.put("targetUrl", "http://orders.staging.internal:8080");
        scan.put("options", Map.of("paths", "/"));
        // RBAC: viewers cannot queue scans; active scanners need APPROVE and confirmation; secrets are refused
        assertThat(call(HttpMethod.POST, "/api/v1/scans", viewer, scan, MAP).getStatusCode().value()).isEqualTo(403);
        Map<String, Object> active = new LinkedHashMap<>(scan);
        active.put("scannerId", "builtin-port-scan");
        assertThat(call(HttpMethod.POST, "/api/v1/scans", TestJwt.token("dev", "acme", "DEVELOPER"), active, MAP).getStatusCode().value()).isEqualTo(403);
        assertThat(call(HttpMethod.POST, "/api/v1/scans", security, active, MAP).getStatusCode().value()).isEqualTo(428);
        Map<String, Object> withSecret = new LinkedHashMap<>(scan);
        withSecret.put("options", Map.of("apiToken", "x"));
        assertThat(call(HttpMethod.POST, "/api/v1/scans", security, withSecret, MAP).getStatusCode().value()).isEqualTo(400);

        ResponseEntity<Map<String, Object>> created = call(HttpMethod.POST, "/api/v1/scans", security, scan, MAP);
        assertThat(created.getStatusCode().value()).as(String.valueOf(created.getBody())).isEqualTo(201);
        String jobId = (String) created.getBody().get("id");
        assertThat(created.getBody()).containsEntry("status", "QUEUED");

        // workers only get jobs for scanners they serve
        assertThat(call(HttpMethod.POST, "/api/v1/worker/jobs/claim", WORKER, Map.of("workerId", "w2", "scanners", List.of("other")), MAP)
                .getStatusCode().value()).isEqualTo(204);
        Map<String, Object> claimed = call(HttpMethod.POST, "/api/v1/worker/jobs/claim", WORKER,
                Map.of("workerId", "w1", "scanners", List.of("builtin-http-security")), MAP).getBody();
        assertThat(claimed).containsEntry("jobId", jobId).containsEntry("targetUrl", "http://orders.staging.internal:8080");
        assertThat((Map<String, Object>) claimed.get("application")).containsEntry("serviceId", "orders");
        assertThat(call(HttpMethod.POST, "/api/v1/worker/jobs/claim", WORKER,
                Map.of("workerId", "w3", "scanners", List.of("builtin-http-security")), MAP).getStatusCode().value()).isEqualTo(204);

        // lease expiry re-queues the job; the next claim gets it again
        assertThat(jobStore.reapExpiredLeases(Instant.now().plus(Duration.ofHours(1)))).isEqualTo(1);
        assertThat(call(HttpMethod.POST, "/api/v1/worker/jobs/claim", WORKER,
                Map.of("workerId", "w1", "scanners", List.of("builtin-http-security")), MAP).getBody()).containsEntry("attempt", 2);

        assertThat(call(HttpMethod.POST, "/api/v1/worker/jobs/" + jobId + "/heartbeat", WORKER,
                Map.of("workerId", "w1", "progress", 50, "message", "half way"), MAP).getBody()).containsEntry("cancelRequested", false);
        assertThat(call(HttpMethod.POST, "/api/v1/worker/jobs/" + jobId + "/heartbeat", WORKER,
                Map.of("workerId", "intruder", "progress", 50, "message", "x"), MAP).getStatusCode().value()).isEqualTo(409);

        List<Map<String, Object>> findings = List.of(
                Map.of("moduleId", "api-security", "ruleId", "HDR-CSP", "title", "Content-Security-Policy header missing",
                        "sourceSeverity", "MEDIUM", "asset", "http://orders.staging.internal:8080/", "evidence", "password=hunter2"),
                Map.of("moduleId", "api-security", "ruleId", "HDR-HSTS", "title", "HSTS header missing", "sourceSeverity", "LOW"));
        Map<String, Object> done = call(HttpMethod.POST, "/api/v1/worker/jobs/" + jobId + "/complete", WORKER,
                Map.of("workerId", "w1", "status", "COMPLETED", "findings", findings, "results", Map.of("requests", 12),
                        "log", List.of("scan done")), MAP).getBody();
        assertThat(done).containsEntry("status", "COMPLETED").containsEntry("accepted", 2);
        assertThat(call(HttpMethod.POST, "/api/v1/worker/jobs/" + jobId + "/complete", WORKER,
                Map.of("workerId", "w1", "status", "COMPLETED", "findings", List.of()), MAP).getStatusCode().value()).isEqualTo(409);

        Map<String, Object> job = call(HttpMethod.GET, "/api/v1/scans/" + jobId, viewer, null, MAP).getBody();
        assertThat(job).containsEntry("status", "COMPLETED").containsEntry("findingsCount", 2);

        List<Map<String, Object>> stored = call(HttpMethod.GET, "/api/v1/findings?status=open", viewer, null, LIST).getBody();
        assertThat(stored).hasSize(2).allSatisfy(f -> assertThat(f).containsEntry("source", "builtin-http-security"));
        Map<String, Object> csp = stored.stream().filter(f -> "HDR-CSP".equals(f.get("ruleId"))).findFirst().orElseThrow();
        Map<String, Object> detail = call(HttpMethod.GET, "/api/v1/findings/" + csp.get("id"), viewer, null, MAP).getBody();
        assertThat((String) detail.get("payloadJson")).doesNotContain("hunter2");
        Map<String, Object> summary = call(HttpMethod.GET, "/api/v1/findings/summary", viewer, null, MAP).getBody();
        assertThat(((Number) summary.get("open")).intValue()).isEqualTo(2);

        // other tenants cannot see the job or the findings
        String globex = TestJwt.token("gina", "globex", "ADMIN");
        assertThat(call(HttpMethod.GET, "/api/v1/scans/" + jobId, globex, null, MAP).getStatusCode().value()).isEqualTo(404);
        assertThat(call(HttpMethod.GET, "/api/v1/findings/" + csp.get("id"), globex, null, MAP).getStatusCode().value()).isEqualTo(404);
        assertThat(call(HttpMethod.GET, "/api/v1/findings", globex, null, LIST).getBody()).isEmpty();

        // a second scan that no longer reports HSTS auto-closes it; occurrences are counted
        String second = (String) call(HttpMethod.POST, "/api/v1/scans", security, scan, MAP).getBody().get("id");
        call(HttpMethod.POST, "/api/v1/worker/jobs/claim", WORKER, Map.of("workerId", "w1", "scanners", List.of("builtin-http-security")), MAP);
        call(HttpMethod.POST, "/api/v1/worker/jobs/" + second + "/complete", WORKER,
                Map.of("workerId", "w1", "status", "COMPLETED", "findings", List.of(findings.get(0))), MAP);
        List<Map<String, Object>> after = call(HttpMethod.GET, "/api/v1/findings", viewer, null, LIST).getBody();
        assertThat(after).anySatisfy(f -> assertThat(f).containsEntry("ruleId", "HDR-HSTS").containsEntry("status", "FIXED"));
        assertThat(after).anySatisfy(f -> assertThat(f).containsEntry("ruleId", "HDR-CSP").containsEntry("occurrences", 2));
    }

    @Test
    @Order(4)
    void reportsAndAudit() {
        assertThat(call(HttpMethod.POST, "/api/v1/reports", viewer, Map.of("format", "CSV"), MAP).getStatusCode().value()).isEqualTo(403);
        ResponseEntity<Map<String, Object>> report = call(HttpMethod.POST, "/api/v1/reports", security, Map.of("format", "CSV"), MAP);
        assertThat(report.getStatusCode().value()).isEqualTo(201);
        ResponseEntity<byte[]> csv = http.exchange("/api/v1/reports/" + report.getBody().get("id") + "/content", HttpMethod.GET,
                new HttpEntity<>(bearer(viewer)), byte[].class);
        assertThat(new String(csv.getBody())).contains("Content-Security-Policy header missing");
        ResponseEntity<Map<String, Object>> pdf = call(HttpMethod.POST, "/api/v1/reports", security, Map.of("format", "PDF"), MAP);
        assertThat(pdf.getStatusCode().value()).isEqualTo(201);

        List<Map<String, Object>> audit = call(HttpMethod.GET, "/api/v1/audit", viewer, null, LIST).getBody();
        assertThat(audit).extracting(a -> a.get("action")).contains("AGENT_REGISTERED", "SCAN_QUEUED", "SCAN_COMPLETED", "REPORT_GENERATED");
        assertThat(call(HttpMethod.GET, "/api/v1/audit/verify", viewer, null, MAP).getBody()).containsEntry("valid", true);

        Map<String, Object> token = call(HttpMethod.POST, "/api/v1/enrollment-tokens", admin, Map.of("description", "ci"), MAP).getBody();
        assertThat(call(HttpMethod.POST, "/api/v1/agents/register", (String) token.get("token"), agentPayload("billing"), MAP)
                .getStatusCode().value()).isEqualTo(200);
        assertThat(call(HttpMethod.POST, "/api/v1/enrollment-tokens", security, Map.of(), MAP).getStatusCode().value()).isEqualTo(403);
        call(HttpMethod.POST, "/api/v1/enrollment-tokens/" + token.get("id") + "/revoke", admin, null, MAP);
        assertThat(call(HttpMethod.POST, "/api/v1/agents/register", (String) token.get("token"), agentPayload("billing"), MAP)
                .getStatusCode().value()).isEqualTo(401);
    }

    @Test
    @Order(5)
    void healthIsPublicEverythingElseIsClosed() {
        assertThat(http.getForEntity("/actuator/health", String.class).getStatusCode().value()).isEqualTo(200);
        assertThat(http.getForEntity("/actuator/env", String.class).getStatusCode().value()).isIn(401, 403);
    }
}
