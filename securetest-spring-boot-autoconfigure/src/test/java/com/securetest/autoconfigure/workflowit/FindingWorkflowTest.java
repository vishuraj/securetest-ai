package com.securetest.autoconfigure.workflowit;

import com.securetest.autoconfigure.service.FindingService;
import com.securetest.core.model.Finding;
import com.securetest.core.model.ScanJob;
import com.securetest.core.model.Severity;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.context.ConfigurableApplicationContext;

import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

/** Tester findings, retest, comments, evidence and Jira / GitHub issues, against fake trackers. */
class FindingWorkflowTest {

    @SpringBootApplication
    static class App { }

    private static ConfigurableApplicationContext ctx;
    private static HttpServer trackers;
    private static int port;
    private static final AtomicReference<String> githubBody = new AtomicReference<>();
    private static final AtomicReference<String> jiraAuth = new AtomicReference<>();
    private static final HttpClient http = HttpClient.newHttpClient();

    @BeforeAll
    static void start() throws Exception {
        trackers = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        trackers.createContext("/repos/acme/shop/issues", ex -> {
            String body;
            int code;
            if (ex.getRequestMethod().equals("POST")) {
                githubBody.set(new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
                body = "{\"number\":7,\"html_url\":\"https://github.com/acme/shop/issues/7\",\"state\":\"open\"}";
                code = 201;
            } else {
                body = "{\"number\":7,\"state\":\"closed\"}";
                code = 200;
            }
            byte[] b = body.getBytes(StandardCharsets.UTF_8);
            ex.sendResponseHeaders(code, b.length);
            ex.getResponseBody().write(b);
            ex.close();
        });
        trackers.createContext("/rest/api/3/issue", ex -> {
            jiraAuth.set(ex.getRequestHeaders().getFirst("Authorization"));
            boolean create = ex.getRequestMethod().equals("POST");
            byte[] b = (create ? "{\"key\":\"SEC-12\"}" : "{\"fields\":{\"status\":{\"name\":\"In Review\"}}}").getBytes(StandardCharsets.UTF_8);
            ex.sendResponseHeaders(create ? 201 : 200, b.length);
            ex.getResponseBody().write(b);
            ex.close();
        });
        trackers.start();
        String base = "http://127.0.0.1:" + trackers.getAddress().getPort();
        ctx = new SpringApplicationBuilder(App.class).properties(
                "server.port=0", "spring.main.web-application-type=servlet",
                "securetest.data.persist=true", "securetest.data.storage-dir=target/workflow-" + System.nanoTime(),
                "securetest.integrations.github.repository=acme/shop", "securetest.integrations.github.api-url=" + base,
                "securetest.integrations.github.token-ref=prop://test.gh", "test.gh=ghp_test",
                "securetest.integrations.jira.url=" + base, "securetest.integrations.jira.project-key=SEC",
                "securetest.integrations.jira.email=qa@acme.test", "securetest.integrations.jira.token-ref=prop://test.jira", "test.jira=jira-token").run();
        port = ctx.getEnvironment().getRequiredProperty("local.server.port", Integer.class);
    }

    @AfterAll
    static void stop() {
        if (ctx != null) ctx.close();
        if (trackers != null) trackers.stop(0);
    }

    private static HttpResponse<String> call(String method, String path, String json) throws Exception {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + "/securetest/api/v1" + path)).timeout(Duration.ofSeconds(30))
                .header("X-SecureTest-Request", "1").header("Content-Type", "application/json")
                .method(method, json == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofString(json));
        return http.send(b.build(), HttpResponse.BodyHandlers.ofString());
    }

    private static String field(String json, String name) {
        Matcher m = Pattern.compile("\"" + name + "\"\\s*:\\s*\"([^\"]*)\"").matcher(json);
        return m.find() ? m.group(1) : null;
    }

    private static String report(String title) throws Exception {
        HttpResponse<String> r = call("POST", "/findings", "{\"title\":\"" + title + "\",\"severity\":\"HIGH\",\"asset\":\"/api/orders/{id}\","
                + "\"stepsToReproduce\":\"1. sign in as alice\\n2. GET /api/orders/42 (bob's order)\",\"evidence\":\"Authorization: Bearer abcdefghijklmnopqrstuvwxyz0123456789\","
                + "\"cwe\":\"CWE-639\"}");
        assertThat(r.statusCode()).as(r.body()).isEqualTo(201);
        return field(r.body(), "id");
    }

    @Test
    void testersReportFindingsAndVerifyFixes() throws Exception {
        String id = report("IDOR on order details");
        String f = call("GET", "/findings/" + id, null).body();
        assertThat(f).contains("\"source\":\"manual\"").contains("\"ruleId\":\"CWE-639\"").contains("bob's order");
        assertThat(f).doesNotContain("abcdefghijklmnopqrstuvwxyz0123456789"); // evidence is redacted

        String retest = call("POST", "/findings/" + id + "/retest", "{}").body();
        assertThat(retest).contains("\"mode\":\"manual\"").contains("AWAITING_TESTER");
        String verified = call("POST", "/findings/" + id + "/verification", "{\"fixed\":true,\"note\":\"403 for bob's order now\"}").body();
        assertThat(verified).contains("\"state\":\"VERIFIED_FIXED\"").contains("\"status\":\"FIXED\"");
    }

    @Test
    void scannerFindingsAreRetestedByTheirScanner() throws Exception {
        assertThat(call("PUT", "/modules/compliance/configuration", "{\"enabled\":true}").statusCode()).isEqualTo(200);
        ScanJob seed = new ScanJob();
        seed.id = "seed-job";
        seed.scannerId = "config-posture";
        seed.scannerName = "Configuration posture";
        seed.moduleId = "compliance";
        seed.requestedBy = "test";
        Finding gone = Finding.of("compliance", "config-posture", "CFG-TEST-GONE", "A misconfiguration that was since fixed", Severity.MEDIUM);
        String id = ctx.getBean(FindingService.class).ingest(seed, List.of(gone), "workspace", false).get(0).id;

        String started = call("POST", "/findings/" + id + "/retest", "{\"confirmed\":true}").body();
        assertThat(started).contains("\"mode\":\"scan\""); // may already be settled on a fast machine
        String state = "PENDING";
        for (int i = 0; i < 120 && "PENDING".equals(state); i++) {
            Thread.sleep(250);
            String body = call("GET", "/findings/" + id, null).body();
            state = field(body.substring(body.indexOf("\"verification\"")), "state");
        }
        assertThat(state).isEqualTo("VERIFIED_FIXED");
        assertThat(call("GET", "/findings/" + id, null).body()).contains("\"status\":\"FIXED\"");
    }

    @Test
    void commentsAndEvidenceAttachments() throws Exception {
        String id = report("Stored XSS in profile name");
        assertThat(call("POST", "/findings/" + id + "/comments", "{\"text\":\"Reproduced on staging too\"}").body()).contains("Reproduced on staging too");

        byte[] png = Base64.getDecoder().decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==");
        String up = call("POST", "/findings/" + id + "/attachments", "{\"name\":\"poc.png\",\"contentType\":\"image/png\",\"dataBase64\":\""
                + Base64.getEncoder().encodeToString(png) + "\"}").body();
        String aid = field(up.substring(up.indexOf("\"attachments\"")), "id");
        HttpResponse<byte[]> img = http.send(HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + "/securetest/api/v1/findings/" + id + "/attachments/" + aid)).build(),
                HttpResponse.BodyHandlers.ofByteArray());
        assertThat(img.statusCode()).isEqualTo(200);
        assertThat(img.body()).isEqualTo(png);
        assertThat(img.headers().firstValue("Content-Type")).hasValue("image/png");
        assertThat(img.headers().firstValue("X-Content-Type-Options")).hasValue("nosniff");

        assertThat(call("POST", "/findings/" + id + "/attachments", "{\"name\":\"x.html\",\"contentType\":\"text/html\",\"dataBase64\":\"PGgxPg==\"}").statusCode()).isEqualTo(400);
    }

    @Test
    void issuesAreCreatedInGitHubAndJira() throws Exception {
        String id = report("Missing rate limit on login");
        assertThat(call("GET", "/integrations/issue-trackers", null).body()).contains("\"id\":\"jira\"").contains("\"id\":\"github\"");

        String gh = call("POST", "/findings/" + id + "/issues", "{\"tracker\":\"github\"}").body();
        assertThat(gh).contains("https://github.com/acme/shop/issues/7");
        assertThat(githubBody.get()).contains("Missing rate limit on login").contains("Steps to reproduce")
                .doesNotContain("abcdefghijklmnopqrstuvwxyz0123456789");
        assertThat(call("POST", "/findings/" + id + "/issues/github/refresh", "{}").body()).contains("\"state\":\"closed\"");
        assertThat(call("POST", "/findings/" + id + "/issues", "{\"tracker\":\"github\"}").statusCode()).isEqualTo(409);

        String jira = call("POST", "/findings/" + id + "/issues", "{\"tracker\":\"jira\"}").body();
        assertThat(jira).contains("SEC-12").contains("/browse/SEC-12");
        assertThat(jiraAuth.get()).startsWith("Basic ");
        assertThat(call("POST", "/findings/" + id + "/issues/jira/refresh", "{}").body()).contains("In Review");
    }
}
