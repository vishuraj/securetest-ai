package com.example.demo;

import com.securetest.controlplane.ControlPlaneApplication;
import com.securetest.worker.WorkerApplication;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.client.HttpStatusCodeException;

import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Supplier;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * End-to-end "Embedded + Remote Worker" profile:
 * <ol>
 *   <li>the control plane starts (in-memory H2 in PostgreSQL mode, Flyway schema, OIDC via a test key pair);</li>
 *   <li>this sample app starts with only connected-mode settings and registers itself through the starter's
 *       {@code ControlPlaneClient} ({@code POST /api/v1/agents/register});</li>
 *   <li>a worker starts and advertises the adapters' scanners;</li>
 *   <li>a security user queues a passive HTTP security scan of the sample app through the control plane API;</li>
 *   <li>the worker claims it, runs the {@code HttpSecurityScanner} in a sandbox process and posts the findings;</li>
 *   <li>the findings are aggregated centrally and are invisible to another tenant.</li>
 * </ol>
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        TestClasspath.EXCLUDE_CONTROL_PLANE_AUTOCONFIG,
        "securetest.data.storage-dir=target/securetest-remote-it",
        "securetest.data.persist=false",
        "securetest.control-plane.enabled=true",
        "securetest.control-plane.enrollment-token-ref=prop://e2e.enrollment-token",
        "e2e.enrollment-token=" + RemoteScanEndToEndTest.ENROLLMENT_TOKEN
})
class RemoteScanEndToEndTest {

    static final String ENROLLMENT_TOKEN = "e2e-enrollment-token-0123456789";
    static final String WORKER_TOKEN = "e2e-worker-fleet-token-0123456789";
    static final String WORKER_ID = "e2e-worker";
    static final ParameterizedTypeReference<Map<String, Object>> MAP = new ParameterizedTypeReference<>() { };
    static final ParameterizedTypeReference<List<Map<String, Object>>> LIST = new ParameterizedTypeReference<>() { };

    static ConfigurableApplicationContext controlPlane;
    static ConfigurableApplicationContext worker;
    static String controlPlaneUrl;

    final RestTemplate rest = new RestTemplate();

    @LocalServerPort
    int appPort;

    @DynamicPropertySource
    static void startControlPlane(DynamicPropertyRegistry registry) {
        if (controlPlane == null) {
            controlPlane = ControlPlaneApplication.builder().run(
                    "--server.port=0",
                    "--spring.main.banner-mode=off",
                    // do not pick up the sample app's application.yml from the shared test classpath
                    "--spring.config.name=securetest-e2e-control-plane",
                    "--spring.datasource.url=jdbc:h2:mem:e2e-cp;MODE=PostgreSQL;DATABASE_TO_LOWER=TRUE;DEFAULT_NULL_ORDERING=HIGH;DB_CLOSE_DELAY=-1",
                    "--spring.security.oauth2.resourceserver.jwt.public-key-location=" + TestJwt.publicKeyLocation(),
                    "--securetest.control-plane.bootstrap.tenant-slug=acme",
                    "--securetest.control-plane.bootstrap.enrollment-token=" + ENROLLMENT_TOKEN,
                    "--securetest.control-plane.workers.tokens=" + WORKER_TOKEN,
                    // the embedded starter is on this test classpath too; the control plane must not serve a dashboard
                    "--securetest.enabled=false");
            controlPlaneUrl = "http://localhost:" + controlPlane.getEnvironment().getProperty("local.server.port");
        }
        registry.add("securetest.control-plane.url", () -> controlPlaneUrl);
    }

    @AfterAll
    static void stopAll() {
        if (worker != null) worker.close();
        if (controlPlane != null) controlPlane.close();
    }

    @Test
    @SuppressWarnings("unchecked")
    void sampleAppRegistersAndARemoteWorkerScansIt() throws Exception {
        String viewer = TestJwt.token("victor", "acme", "VIEWER");
        String security = TestJwt.token("sam", "acme", "SECURITY");

        // 1. the starter registers the sample app (first attempt ~5 s after start-up)
        Map<String, Object> app = await("sample app registration", Duration.ofSeconds(45), () -> {
            Map<String, Object> inv = get("/api/v1/inventory", viewer, MAP);
            return ((List<Map<String, Object>>) inv.get("applications")).stream()
                    .filter(a -> "securetest-demo".equals(a.get("name"))).findFirst();
        });
        List<Map<String, Object>> agents = (List<Map<String, Object>>) app.get("agents");
        assertThat(agents).hasSize(1);
        assertThat(agents.get(0)).containsEntry("agentVersion", "1.0.0");
        assertThat((String) agents.get(0).get("capabilitiesJson")).contains("\"api-security\""); // starter sends module ids
        String applicationId = (String) app.get("id");

        // 2. a worker joins and advertises the remote-capable adapter scanners
        worker = WorkerApplication.builder().run(
                "--spring.main.banner-mode=off",
                "--spring.config.name=securetest-e2e-worker",
                "--securetest.worker.control-plane-url=" + controlPlaneUrl,
                "--securetest.worker.token=" + WORKER_TOKEN,
                "--securetest.worker.id=" + WORKER_ID,
                "--securetest.worker.allowed-targets=localhost",
                "--securetest.worker.poll-interval=500ms",
                "--securetest.worker.heartbeat-interval=2s",
                // no container engine is assumed on CI machines: isolate the scan in a child JVM instead
                "--securetest.worker.sandbox.mode=process",
                "--securetest.worker.sandbox.timeout=2m",
                "--spring.autoconfigure.exclude=org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration,"
                        + "org.springframework.boot.autoconfigure.flyway.FlywayAutoConfiguration,"
                        + "org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration,"
                        + "org.springframework.boot.autoconfigure.security.servlet.UserDetailsServiceAutoConfiguration");
        await("worker scanner catalog", Duration.ofSeconds(30), () -> get("/api/v1/scanners", viewer, LIST).stream()
                .filter(s -> "builtin-http-security".equals(s.get("id")) && "PASSIVE".equals(s.get("mode"))).findFirst());

        // 3. queue a remote scan of the sample app
        Map<String, Object> request = new LinkedHashMap<>();
        request.put("applicationId", applicationId);
        request.put("scannerId", "builtin-http-security");
        request.put("targetUrl", "http://localhost:" + appPort);
        request.put("options", Map.of("paths", "/", "checkExposures", "true", "rate", "20"));
        ResponseEntity<Map<String, Object>> created = exchange(HttpMethod.POST, "/api/v1/scans", security, request, MAP);
        assertThat(created.getStatusCode().value()).isEqualTo(201);
        String jobId = (String) created.getBody().get("id");

        // 4. the worker runs it in the sandbox and posts the findings back
        Map<String, Object> job = await("remote scan", Duration.ofSeconds(120), () -> {
            Map<String, Object> j = get("/api/v1/scans/" + jobId, viewer, MAP);
            return List.of("COMPLETED", "FAILED", "CANCELLED").contains(j.get("status")) ? Optional.of(j) : Optional.empty();
        });
        assertThat(job.get("status")).as("job error: %s, log: %s", job.get("error"), job.get("log")).isEqualTo("COMPLETED");
        assertThat(job).containsEntry("workerId", WORKER_ID);
        assertThat((Integer) job.get("findingsCount")).isGreaterThan(0);
        assertThat((Map<String, Object>) job.get("results")).containsEntry("sandbox", "process");

        // 5. findings are aggregated centrally, normalized and attributed to the application
        List<Map<String, Object>> findings = get("/api/v1/findings?applicationId=" + applicationId, viewer, LIST);
        assertThat(findings).hasSize((Integer) job.get("findingsCount"));
        assertThat(findings).allSatisfy(f -> {
            assertThat(f).containsEntry("source", "builtin-http-security").containsEntry("serviceId", app.get("serviceId"));
            assertThat(f.get("priority")).isNotNull();
            assertThat(f.get("lastScanId")).isEqualTo(jobId);
        });
        Map<String, Object> summary = get("/api/v1/findings/summary", viewer, MAP);
        assertThat(((Number) summary.get("open")).intValue()).isEqualTo(findings.size());
        assertThat(get("/api/v1/audit", viewer, LIST)).extracting(a -> a.get("action"))
                .contains("AGENT_REGISTERED", "SCAN_QUEUED", "SCAN_STARTED", "SCAN_COMPLETED");

        // 6. tenant isolation
        String platform = TestJwt.token("root", null, "PLATFORM_ADMIN");
        assertThat(exchange(HttpMethod.POST, "/api/v1/admin/tenants", platform, Map.of("slug", "globex"), MAP).getStatusCode().value()).isEqualTo(201);
        String globex = TestJwt.token("gina", "globex", "ADMIN");
        assertThat(exchange(HttpMethod.GET, "/api/v1/scans/" + jobId, globex, null, MAP).getStatusCode().value()).isEqualTo(404);
        assertThat(get("/api/v1/findings", globex, LIST)).isEmpty();
    }

    // ------------------------------------------------------------------ helpers

    private <T> ResponseEntity<T> exchange(HttpMethod method, String path, String token, Object body, ParameterizedTypeReference<T> type) {
        HttpHeaders h = new HttpHeaders();
        h.setContentType(MediaType.APPLICATION_JSON);
        h.setBearerAuth(token);
        try {
            return rest.exchange(controlPlaneUrl + path, method, new HttpEntity<>(body, h), type);
        } catch (HttpStatusCodeException e) {
            return ResponseEntity.status(e.getStatusCode()).build();
        }
    }

    private <T> T get(String path, String token, ParameterizedTypeReference<T> type) {
        ResponseEntity<T> r = exchange(HttpMethod.GET, path, token, null, type);
        assertThat(r.getStatusCode().value()).as("GET " + path).isEqualTo(200);
        return r.getBody();
    }

    private static <T> T await(String what, Duration timeout, Supplier<Optional<T>> probe) throws InterruptedException {
        long deadline = System.nanoTime() + timeout.toNanos();
        while (System.nanoTime() < deadline) {
            Optional<T> v = probe.get();
            if (v.isPresent()) return v.get();
            Thread.sleep(500);
        }
        throw new AssertionError("Timed out waiting for " + what);
    }
}
