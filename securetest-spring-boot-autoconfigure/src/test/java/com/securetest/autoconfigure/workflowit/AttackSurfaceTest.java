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
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

/** Attack-surface register and discovery, using the reserved .invalid domain so no real host is contacted. */
class AttackSurfaceTest {

    @SpringBootApplication
    static class App { }

    private static ConfigurableApplicationContext ctx;
    private static int port;
    private static final HttpClient http = HttpClient.newHttpClient();

    @BeforeAll
    static void start() {
        ctx = new SpringApplicationBuilder(App.class).properties("server.port=0", "spring.main.web-application-type=servlet",
                "securetest.data.persist=false", "securetest.data.storage-dir=target/asm-" + System.nanoTime()).run();
        port = ctx.getEnvironment().getRequiredProperty("local.server.port", Integer.class);
    }

    @AfterAll
    static void stop() {
        if (ctx != null) ctx.close();
    }

    private static HttpResponse<String> call(String method, String path, String json) throws Exception {
        return http.send(HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + "/securetest/api/v1" + path)).timeout(Duration.ofSeconds(60))
                .header("X-SecureTest-Request", "1").header("Content-Type", "application/json")
                .method(method, json == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofString(json)).build(),
                HttpResponse.BodyHandlers.ofString());
    }

    private static String field(String json, String name) {
        Matcher m = Pattern.compile("\"" + name + "\"\\s*:\\s*\"([^\"]*)\"").matcher(json);
        return m.find() ? m.group(1) : null;
    }

    @Test
    void registeredDomainsAreDiscoveredAndChecked() throws Exception {
        assertThat(call("GET", "/attack-surface", null).statusCode()).isEqualTo(409); // module off by default
        call("PUT", "/modules/attack-surface/configuration", "{\"enabled\":true}");

        assertThat(call("POST", "/attack-surface/assets", "{\"host\":\"not a host\"}").statusCode()).isEqualTo(400);
        HttpResponse<String> reg = call("POST", "/attack-surface/assets", "{\"host\":\"https://Shop.INVALID/login\",\"owner\":\"web-team\"}");
        assertThat(reg.statusCode()).as(reg.body()).isEqualTo(201);
        assertThat(reg.body()).contains("\"host\":\"shop.invalid\"").contains("\"kind\":\"DOMAIN\"");

        HttpResponse<String> scan = call("POST", "/scans", "{\"scannerId\":\"attack-surface\",\"options\":{}}");
        assertThat(scan.statusCode()).as(scan.body()).isEqualTo(201);
        String job = field(scan.body().substring(scan.body().indexOf("\"job\"")), "id");
        String status = "QUEUED";
        for (int i = 0; i < 240 && !List.of("COMPLETED", "FAILED").contains(status); i++) {
            Thread.sleep(250);
            status = field(call("GET", "/scans/" + job, null).body(), "status");
        }
        assertThat(status).isEqualTo("COMPLETED");

        String findings = call("GET", "/findings?module=attack-surface", null).body();
        assertThat(findings).contains("ASM-UNRESOLVED").contains("shop.invalid");
        String overview = call("GET", "/attack-surface", null).body();
        assertThat(overview).contains("\"registered\":1").contains("\"lastChecked\"");

        assertThat(call("POST", "/attack-surface/monitoring", "{}").body()).contains("attack-surface");
        assertThat(call("GET", "/attack-surface", null).body()).contains("\"cron\":\"0 0 6 * * *\"");
        assertThat(call("DELETE", "/attack-surface/assets/shop.invalid", null).statusCode()).isEqualTo(200);
    }
}
