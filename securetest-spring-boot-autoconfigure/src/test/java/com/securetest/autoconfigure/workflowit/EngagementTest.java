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
import java.time.Duration;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

/** A pentest engagement from planning to the completion letter. */
class EngagementTest {

    @SpringBootApplication
    static class App { }

    private static ConfigurableApplicationContext ctx;
    private static int port;
    private static final HttpClient http = HttpClient.newHttpClient();

    @BeforeAll
    static void start() {
        ctx = new SpringApplicationBuilder(App.class).properties("server.port=0", "spring.main.web-application-type=servlet",
                "securetest.data.persist=false", "securetest.data.storage-dir=target/engagement-" + System.nanoTime()).run();
        port = ctx.getEnvironment().getRequiredProperty("local.server.port", Integer.class);
    }

    @AfterAll
    static void stop() {
        if (ctx != null) ctx.close();
    }

    private static HttpResponse<String> call(String method, String path, String json) throws Exception {
        return http.send(HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + "/securetest/api/v1" + path)).timeout(Duration.ofSeconds(30))
                .header("X-SecureTest-Request", "1").header("Content-Type", "application/json")
                .method(method, json == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofString(json)).build(),
                HttpResponse.BodyHandlers.ofString());
    }

    private static String field(String json, String name) {
        Matcher m = Pattern.compile("\"" + name + "\"\\s*:\\s*\"([^\"]*)\"").matcher(json);
        return m.find() ? m.group(1) : null;
    }

    private static String awaitReport(String id) throws Exception {
        String status = "GENERATING";
        for (int i = 0; i < 80 && "GENERATING".equals(status); i++) {
            Thread.sleep(250);
            status = field(call("GET", "/reports/" + id, null).body(), "status");
        }
        return status;
    }

    @Test
    void anEngagementFromPlanningToCompletionLetter() throws Exception {
        String create = "{\"name\":\"Q3 shop API test\",\"type\":\"api\",\"scope\":[\"https://staging.shop.test/api\"],\"lead\":\"dana\",\"testers\":[\"sam\"],"
                + "\"startDate\":\"2026-11-01\",\"endDate\":\"2026-11-14\",\"rulesOfEngagement\":\"No DoS. Weekdays only.\"}";
        assertThat(call("POST", "/engagements", create).statusCode()).isEqualTo(409); // module off by default
        assertThat(call("PUT", "/modules/pentest/configuration", "{\"enabled\":true}").statusCode()).isEqualTo(200);

        HttpResponse<String> created = call("POST", "/engagements", create);
        assertThat(created.statusCode()).as(created.body()).isEqualTo(201);
        String id = field(created.body(), "id");
        assertThat(created.body()).contains("\"methodology\":\"api\"").contains("\"API1\"").contains("\"API10\"");

        assertThat(call("POST", "/engagements/" + id + "/status", "{\"status\":\"COMPLETED\"}").statusCode()).isEqualTo(409); // not started
        assertThat(call("POST", "/engagements/" + id + "/status", "{\"status\":\"IN_PROGRESS\"}").statusCode()).isEqualTo(200);
        assertThat(call("PUT", "/engagements/" + id + "/checklist/API1", "{\"state\":\"FAILED\",\"note\":\"orders of other users readable\"}").statusCode()).isEqualTo(200);
        assertThat(call("PUT", "/engagements/" + id + "/checklist/API4", "{\"state\":\"PASSED\"}").statusCode()).isEqualTo(200);

        String finding = call("POST", "/findings", "{\"title\":\"BOLA on /api/orders/{id}\",\"severity\":\"HIGH\",\"engagementId\":\"" + id + "\"}").body();
        String fid = field(finding, "id");
        String view = call("GET", "/engagements/" + id, null).body();
        assertThat(view).contains(fid).contains("\"coveragePercent\":20").contains("\"open\":1");

        assertThat(call("POST", "/engagements/" + id + "/status", "{\"status\":\"RETEST\"}").statusCode()).isEqualTo(200);
        assertThat(call("GET", "/findings/" + fid, null).body()).contains("AWAITING_TESTER");
        call("POST", "/findings/" + fid + "/verification", "{\"fixed\":true,\"note\":\"403 now\"}");
        assertThat(call("POST", "/engagements/" + id + "/status", "{\"status\":\"COMPLETED\"}").statusCode()).isEqualTo(200);
        assertThat(call("PUT", "/engagements/" + id + "/checklist/API2", "{\"state\":\"PASSED\"}").statusCode()).isEqualTo(409); // closed

        String rep = field(call("POST", "/reports", "{\"type\":\"pentest\",\"engagementId\":\"" + id + "\"}").body(), "id");
        assertThat(awaitReport(rep)).isEqualTo("READY");
        HttpResponse<byte[]> pdf = http.send(HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + "/securetest/api/v1/reports/" + rep + "/download?format=pdf")).build(),
                HttpResponse.BodyHandlers.ofByteArray());
        assertThat(pdf.statusCode()).isEqualTo(200);
        assertThat(new String(pdf.body(), 0, 5)).isEqualTo("%PDF-");

        String letter = field(call("POST", "/reports", "{\"type\":\"attestation\",\"engagementId\":\"" + id + "\"}").body(), "id");
        assertThat(awaitReport(letter)).isEqualTo("READY");
        assertThat(call("POST", "/reports", "{\"type\":\"attestation\"}").statusCode()).isEqualTo(400); // engagement required
    }
}
