package com.securetest.autoconfigure.workflowit;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.context.ConfigurableApplicationContext;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

/** Release readiness: checks, waivers, checklist and role-based sign-off. */
class ReleaseReadinessTest {

    @SpringBootApplication
    static class App { }

    private static ConfigurableApplicationContext ctx;
    private static int port;
    private static final HttpClient http = HttpClient.newHttpClient();

    @BeforeAll
    static void start() {
        ctx = new SpringApplicationBuilder(App.class).properties("server.port=0", "spring.main.web-application-type=servlet",
                "securetest.data.persist=false", "securetest.data.storage-dir=target/release-" + System.nanoTime(),
                "securetest.dashboard.authentication.users[0].username=quinn", "securetest.dashboard.authentication.users[0].password={noop}quinn-pass-123",
                "securetest.dashboard.authentication.users[0].roles[0]=QA").run();
        port = ctx.getEnvironment().getRequiredProperty("local.server.port", Integer.class);
    }

    @AfterAll
    static void stop() {
        if (ctx != null) ctx.close();
    }

    private static HttpResponse<String> call(String method, String path, String json, String... headers) throws Exception {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + "/securetest/api/v1" + path)).timeout(Duration.ofSeconds(30))
                .header("X-SecureTest-Request", "1").header("Content-Type", "application/json")
                .method(method, json == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofString(json));
        for (int i = 0; i < headers.length; i += 2) b.header(headers[i], headers[i + 1]);
        return http.send(b.build(), HttpResponse.BodyHandlers.ofString());
    }

    private static String field(String json, String name) {
        Matcher m = Pattern.compile("\"" + name + "\"\\s*:\\s*\"([^\"]*)\"").matcher(json);
        return m.find() ? m.group(1) : null;
    }

    private static String sign(String id, String role, String decision) throws Exception {
        return call("POST", "/releases/" + id + "/signoffs", "{\"role\":\"" + role + "\",\"decision\":\"" + decision + "\"}").body();
    }

    @Test
    void aReleaseIsBlockedUntilItsChecksPassThenSignedOff() throws Exception {
        String created = call("POST", "/releases", "{\"version\":\"2.4.0\",\"name\":\"Spring\",\"items\":[\"Release notes reviewed\"]}").body();
        String id = field(created, "id");
        assertThat(created).contains("\"ready\":false").contains("\"GATE\"").contains("\"VULNERABILITIES\"");

        // a critical finding fails the release gate
        String fid = field(call("POST", "/findings", "{\"title\":\"RCE in upload\",\"severity\":\"CRITICAL\",\"moduleId\":\"vulnerability\"}").body(), "id");
        String blocked = call("GET", "/releases/" + id, null).body();
        assertThat(blocked).containsPattern("\"id\":\"GATE\"[^}]*\"state\":\"FAIL\"");
        assertThat(call("POST", "/releases/" + id + "/signoffs", "{\"role\":\"QA\",\"decision\":\"APPROVE\"}").statusCode()).isEqualTo(409);

        // fix and verify the finding; vulnerabilities were never scanned, so waive that check with a reason
        call("POST", "/findings/" + fid + "/verification", "{\"fixed\":true}");
        assertThat(call("POST", "/releases/" + id + "/checks/VULNERABILITIES/waiver", "{\"reason\":\" \"}").statusCode()).isEqualTo(400);
        call("POST", "/releases/" + id + "/checks/VULNERABILITIES/waiver", "{\"reason\":\"Dependency scan runs in CI for this repo\"}");
        String afterWaiver = call("GET", "/releases/" + id, null).body();
        assertThat(afterWaiver).contains("Checklist: Release notes reviewed").contains("\"state\":\"WAIVED\"");
        call("PUT", "/releases/" + id + "/items/I-1", "{\"done\":true}");
        assertThat(call("GET", "/releases/" + id, null).body()).contains("\"ready\":true");

        // only a QA can sign as QA; a QA cannot sign for security
        String qa = "Basic " + Base64.getEncoder().encodeToString("quinn:quinn-pass-123".getBytes(StandardCharsets.UTF_8));
        assertThat(call("POST", "/releases/" + id + "/signoffs", "{\"role\":\"SECURITY\",\"decision\":\"APPROVE\"}", "X-Forwarded-For", "203.0.113.1", "Authorization", qa).statusCode()).isEqualTo(403);
        assertThat(call("POST", "/releases/" + id + "/signoffs", "{\"role\":\"QA\",\"decision\":\"APPROVE\"}", "X-Forwarded-For", "203.0.113.1", "Authorization", qa).statusCode()).isEqualTo(200);
        assertThat(sign(id, "SECURITY", "APPROVE")).contains("\"status\":\"DRAFT\"");
        String approved = sign(id, "OWNER", "APPROVE");
        assertThat(approved).contains("\"status\":\"APPROVED\"").contains("\"approvedChecks\":[");
        assertThat(call("POST", "/releases/" + id + "/released", "{}").body()).contains("\"status\":\"RELEASED\"");

        String rep = field(call("POST", "/reports", "{\"type\":\"release\",\"releaseId\":\"" + id + "\"}").body(), "id");
        String st = "GENERATING";
        for (int i = 0; i < 80 && "GENERATING".equals(st); i++) {
            Thread.sleep(250);
            st = field(call("GET", "/reports/" + rep, null).body(), "status");
        }
        assertThat(st).isEqualTo("READY");
    }

    @Test
    void aRejectedReleaseCanBeReopened() throws Exception {
        String id = field(call("POST", "/releases", "{\"version\":\"3.0.0-rc1\",\"requiredChecks\":[],\"requiredSignoffs\":[\"SECURITY\"]}").body(), "id");
        assertThat(sign(id, "SECURITY", "REJECT")).contains("\"status\":\"REJECTED\"");
        assertThat(call("POST", "/releases/" + id + "/reopen", "{}").body()).contains("\"status\":\"DRAFT\"");
        assertThat(sign(id, "SECURITY", "APPROVE")).contains("\"status\":\"APPROVED\"");
    }
}
