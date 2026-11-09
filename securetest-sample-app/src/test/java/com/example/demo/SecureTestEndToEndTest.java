package com.example.demo;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Acceptance tests (SRS 16.1) against the sample app, which only adds the starter dependency.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        TestClasspath.EXCLUDE_CONTROL_PLANE_AUTOCONFIG,
        "securetest.data.storage-dir=target/securetest-it",
        "securetest.data.persist=false"
})
class SecureTestEndToEndTest {

    private static final String API = "/securetest/api/v1";
    private static final ParameterizedTypeReference<Map<String, Object>> MAP = new ParameterizedTypeReference<>() { };
    private static final ParameterizedTypeReference<List<Map<String, Object>>> LIST = new ParameterizedTypeReference<>() { };

    @Autowired
    TestRestTemplate http;

    private HttpHeaders mutating() {
        HttpHeaders h = new HttpHeaders();
        h.setContentType(MediaType.APPLICATION_JSON);
        h.set("X-SecureTest-Request", "1");
        return h;
    }

    private ResponseEntity<Map<String, Object>> send(HttpMethod m, String path, Object body) {
        return http.exchange(API + path, m, new HttpEntity<>(body, mutating()), MAP);
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> runScan(String scannerId, Map<String, String> options, boolean confirmed) throws InterruptedException {
        ResponseEntity<Map<String, Object>> r = send(HttpMethod.POST, "/scans", Map.of("scannerId", scannerId, "options", options, "confirmed", confirmed));
        assertThat(r.getStatusCode().value()).as(String.valueOf(r.getBody())).isEqualTo(201);
        String id = (String) ((Map<String, Object>) r.getBody().get("job")).get("id");
        for (int i = 0; i < 120; i++) {
            Map<String, Object> job = http.exchange(API + "/scans/" + id, HttpMethod.GET, null, MAP).getBody();
            String status = (String) job.get("status");
            if (List.of("COMPLETED", "FAILED", "CANCELLED").contains(status)) {
                assertThat(status).as(String.valueOf(job.get("error"))).isEqualTo("COMPLETED");
                return job;
            }
            Thread.sleep(250);
        }
        throw new AssertionError("scan did not finish");
    }

    private void enable(String module) {
        assertThat(send(HttpMethod.PUT, "/modules/" + module + "/configuration", Map.of("enabled", true)).getStatusCode().value()).isEqualTo(200);
    }

    @Test
    void dashboardIsServedWithoutAnyWiring() {
        ResponseEntity<String> index = http.getForEntity("/securetest/", String.class);
        assertThat(index.getStatusCode().value()).isEqualTo(200);
        assertThat(index.getBody()).contains("SecureTest");
        assertThat(index.getHeaders().getFirst("Content-Security-Policy")).contains("default-src 'self'");
        assertThat(http.getForEntity("/securetest/js/app.js", String.class).getStatusCode().value()).isEqualTo(200);
        Map<String, Object> me = http.exchange(API + "/me", HttpMethod.GET, null, MAP).getBody();
        assertThat(me).containsEntry("name", "local-developer");
    }

    @Test
    void modulesDefaultOffExceptHealth() {
        List<Map<String, Object>> modules = http.exchange(API + "/modules", HttpMethod.GET, null, LIST).getBody();
        assertThat(modules).hasSize(12);
        modules.forEach(m -> {
            if (m.get("id").equals("health")) assertThat(m.get("enabled")).isEqualTo(true);
            else if (!List.of("code-quality", "compliance", "api-security").contains(m.get("id"))) assertThat(m.get("enabled")).as((String) m.get("id")).isEqualTo(false);
        });
        Map<String, Object> overview = http.exchange(API + "/overview", HttpMethod.GET, null, MAP).getBody();
        assertThat(overview).containsKeys("application", "runtime", "modules", "findings", "gate");
    }

    @Test
    void mutatingCallsNeedCsrfHeaderAndDisabledModulesRefuseScans() {
        HttpHeaders h = new HttpHeaders();
        h.setContentType(MediaType.APPLICATION_JSON);
        ResponseEntity<String> noCsrf = http.exchange(API + "/scans", HttpMethod.POST, new HttpEntity<>(Map.of("scannerId", "builtin-iac"), h), String.class);
        assertThat(noCsrf.getStatusCode().value()).isEqualTo(403);
        ResponseEntity<Map<String, Object>> disabled = send(HttpMethod.POST, "/scans", Map.of("scannerId", "builtin-iac", "options", Map.of()));
        assertThat(disabled.getStatusCode().value()).isEqualTo(409);
    }

    @Test
    @SuppressWarnings("unchecked")
    void staticAnalysisFindsWeakHashAndProposesFix() throws Exception {
        enable("code-quality");
        Map<String, Object> job = runScan("builtin-static-analysis", Map.of(), false);
        assertThat((Integer) job.get("findingsCount")).isGreaterThan(0);
        Map<String, Object> page = http.exchange(API + "/findings?module=code-quality&q=JAVA-SEC-001&size=10", HttpMethod.GET, null, MAP).getBody();
        List<Map<String, Object>> items = (List<Map<String, Object>>) page.get("items");
        assertThat(items).isNotEmpty();
        Map<String, Object> f = items.get(0);
        assertThat(f.get("filePath").toString()).endsWith("DemoController.java");
        assertThat(f.get("priority")).isEqualTo("HIGH");

        Map<String, Object> source = http.exchange(API + "/findings/" + f.get("id") + "/source", HttpMethod.GET, null, MAP).getBody();
        assertThat(source.get("available")).isEqualTo(true);
        assertThat(source.get("stale")).isEqualTo(false);

        Map<String, Object> preview = send(HttpMethod.POST, "/remediations/preview", Map.of("findingId", f.get("id"))).getBody();
        assertThat(preview.get("automated")).isEqualTo(true);
        Map<String, Object> cs = (Map<String, Object>) preview.get("changeSet");
        String diff = (String) ((List<Map<String, Object>>) cs.get("files")).get(0).get("diff");
        assertThat(diff).contains("-        MessageDigest md = MessageDigest.getInstance(\"MD5\");").contains("SHA-256");
    }

    @Test
    @SuppressWarnings("unchecked")
    void configurationPostureAndPassiveWebChecks() throws Exception {
        enable("compliance");
        runScan("config-posture", Map.of(), false);
        Map<String, Object> page = http.exchange(API + "/findings?module=compliance&q=CFG-HEALTH-DETAILS", HttpMethod.GET, null, MAP).getBody();
        assertThat((List<?>) page.get("items")).isNotEmpty();

        enable("api-security");
        runScan("builtin-http-security", Map.of("baseUrl", "self", "rate", "20"), false);
        Map<String, Object> web = http.exchange(API + "/findings?module=api-security&q=Content-Security-Policy", HttpMethod.GET, null, MAP).getBody();
        assertThat((List<?>) web.get("items")).isNotEmpty();

        ResponseEntity<Map<String, Object>> rejected = send(HttpMethod.POST, "/scans",
                Map.of("scannerId", "builtin-http-security", "options", Map.of("baseUrl", "https://example.org")));
        assertThat(rejected.getStatusCode().value()).isEqualTo(422);
        assertThat(rejected.getBody().get("details").toString()).contains("allowlist");

        ResponseEntity<Map<String, Object>> unconfirmed = send(HttpMethod.POST, "/scans",
                Map.of("scannerId", "builtin-active-probe", "options", Map.of("baseUrl", "self", "endpoints", "/api/items?name=a")));
        assertThat(unconfirmed.getStatusCode().value()).isEqualTo(400);

        Map<String, Object> compliance = http.exchange(API + "/compliance", HttpMethod.GET, null, MAP).getBody();
        assertThat(compliance.get("disclaimer").toString()).contains("not legal certification");
    }

    @Test
    @SuppressWarnings("unchecked")
    void reportsRenderAsPdfAndXlsxAndAuditChainIsValid() throws Exception {
        ResponseEntity<Map<String, Object>> r = send(HttpMethod.POST, "/reports", Map.of("type", "executive", "minPriority", "INFO", "includeClosed", false));
        assertThat(r.getStatusCode().value()).isEqualTo(202);
        String id = (String) r.getBody().get("id");
        String status = "GENERATING";
        for (int i = 0; i < 60 && status.equals("GENERATING"); i++) {
            Thread.sleep(250);
            status = (String) http.exchange(API + "/reports/" + id, HttpMethod.GET, null, MAP).getBody().get("status");
        }
        assertThat(status).isEqualTo("READY");
        byte[] pdf = http.getForObject(API + "/reports/" + id + "/download?format=pdf", byte[].class);
        assertThat(new String(pdf, 0, 5)).isEqualTo("%PDF-");
        byte[] xlsx = http.getForObject(API + "/reports/" + id + "/download?format=xlsx", byte[].class);
        assertThat(xlsx[0]).isEqualTo((byte) 'P');
        assertThat(xlsx[1]).isEqualTo((byte) 'K');

        Map<String, Object> verify = http.exchange(API + "/audit-events/verify", HttpMethod.GET, null, MAP).getBody();
        assertThat(verify.get("valid")).isEqualTo(true);
        Map<String, Object> openapi = http.exchange(API + "/openapi.json", HttpMethod.GET, null, MAP).getBody();
        assertThat(((Map<String, Object>) openapi.get("paths"))).containsKey("/securetest/api/v1/scans");
    }
}
