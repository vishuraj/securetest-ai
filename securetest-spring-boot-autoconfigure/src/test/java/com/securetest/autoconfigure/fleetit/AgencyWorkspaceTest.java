package com.securetest.autoconfigure.fleetit;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.context.ConfigurableApplicationContext;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * An agency workspace: one hub watching two clients' services, each client with its own secret. Both client services are
 * called "api" and run with the prod profile, so every call must carry the right client's token.
 */
class AgencyWorkspaceTest {

    private static final List<ConfigurableApplicationContext> apps = new ArrayList<>();
    private static final HttpClient http = HttpClient.newHttpClient();
    private static int hub;

    private static int start(String name, String... extra) {
        List<String> p = new ArrayList<>(List.of("server.port=0", "spring.main.web-application-type=servlet", "spring.application.name=" + name,
                "securetest.data.persist=false", "securetest.data.storage-dir=target/agency-" + name + "-" + System.nanoTime()));
        p.addAll(List.of(extra));
        ConfigurableApplicationContext ctx = new SpringApplicationBuilder(FleetApp.class).properties(p.toArray(String[]::new)).run();
        apps.add(ctx);
        return ctx.getEnvironment().getRequiredProperty("local.server.port", Integer.class);
    }

    @BeforeAll
    static void startAgency() {
        int acme = start("api", "spring.profiles.active=prod", "securetest.fleet.token-ref=prop://t", "t=acme-secret-0123456789");
        int globex = start("api", "spring.profiles.active=prod", "securetest.fleet.token-ref=prop://t", "t=globex-secret-9876543210");
        hub = start("agency-hub",
                "securetest.fleet.members[0].name=api", "securetest.fleet.members[0].client=Acme",
                "securetest.fleet.members[0].url=http://127.0.0.1:" + acme, "securetest.fleet.members[0].token-ref=prop://acme",
                "securetest.fleet.members[1].name=api", "securetest.fleet.members[1].client=Globex",
                "securetest.fleet.members[1].url=http://127.0.0.1:" + globex, "securetest.fleet.members[1].token-ref=prop://globex",
                "acme=acme-secret-0123456789", "globex=globex-secret-9876543210");
    }

    @AfterAll
    static void stop() {
        apps.forEach(ConfigurableApplicationContext::close);
    }

    private static HttpResponse<String> call(String method, String path, String json) throws Exception {
        return http.send(HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + hub + path)).timeout(Duration.ofSeconds(30))
                .header("X-SecureTest-Request", "1").header("Content-Type", "application/json")
                .method(method, json == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofString(json)).build(),
                HttpResponse.BodyHandlers.ofString());
    }

    @Test
    void oneHubSeesEveryClientWithItsOwnSecret() throws Exception {
        String view = call("GET", "/securetest/api/v1/fleet?refresh=true", null).body();
        assertThat(view).contains("\"clients\":2").contains("\"name\":\"Acme\"").contains("\"name\":\"Globex\"");
        assertThat(view).contains("\"key\":\"acme.api\"").contains("\"key\":\"globex.api\"");
        assertThat(view).doesNotContain("UNAUTHORIZED").doesNotContain("UNREACHABLE");

        HttpResponse<String> acmeMe = call("GET", "/securetest/fleet/acme.api/api/v1/me", null);
        assertThat(acmeMe.statusCode()).isEqualTo(200);
        assertThat(acmeMe.body()).contains("\"authMethod\":\"fleet:agency-hub\"");
        assertThat(call("GET", "/securetest/fleet/globex.api/api/v1/me", null).statusCode()).isEqualTo(200);

        Matcher m = Pattern.compile("\"id\":\"(R-[A-Z0-9]+)\"").matcher(call("POST", "/securetest/api/v1/reports", "{\"type\":\"portfolio\"}").body());
        assertThat(m.find()).isTrue();
        String status = "GENERATING";
        for (int i = 0; i < 80 && "GENERATING".equals(status); i++) {
            Thread.sleep(250);
            Matcher s = Pattern.compile("\"status\":\"([A-Z]+)\"").matcher(call("GET", "/securetest/api/v1/reports/" + m.group(1), null).body());
            status = s.find() ? s.group(1) : status;
        }
        assertThat(status).isEqualTo("READY");
        String json = call("GET", "/securetest/api/v1/reports/" + m.group(1) + "/download?format=json", null).body();
        assertThat(json).contains("Acme").contains("Globex").contains("Clients");
    }
}
