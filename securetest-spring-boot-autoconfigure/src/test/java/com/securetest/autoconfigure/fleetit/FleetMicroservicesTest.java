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

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Three services of one system, each with only the starter (and Spring Security): "orders" on WebFlux, "users" on MVC
 * listing orders in securetest.fleet.members, and "billing" on MVC finding orders through Spring Cloud service discovery.
 * They trust each other through a shared fleet token.
 */
class FleetMicroservicesTest {

    private static final String TOKEN = "fleet-secret-for-tests-0123456789";
    private static final List<ConfigurableApplicationContext> apps = new ArrayList<>();
    private static final HttpClient http = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).connectTimeout(Duration.ofSeconds(5)).build();
    private static int orders;
    private static int users;
    private static int billing;

    private static int start(String name, String stack, String... extra) {
        List<String> p = new ArrayList<>(List.of(
                "server.port=0",
                "spring.main.web-application-type=" + stack,
                "spring.application.name=" + name,
                "securetest.data.persist=false",
                "securetest.data.storage-dir=target/fleet-" + name,
                "securetest.fleet.token-ref=prop://test.fleet.token",
                "test.fleet.token=" + TOKEN));
        p.addAll(List.of(extra));
        ConfigurableApplicationContext ctx = new SpringApplicationBuilder(FleetApp.class).properties(p.toArray(String[]::new)).run();
        apps.add(ctx);
        return ctx.getEnvironment().getRequiredProperty("local.server.port", Integer.class);
    }

    @BeforeAll
    static void startSystem() {
        orders = start("orders", "reactive");
        users = start("users", "servlet",
                "securetest.fleet.members[0].name=orders",
                "securetest.fleet.members[0].url=http://127.0.0.1:" + orders);
        billing = start("billing", "servlet",
                "spring.cloud.discovery.client.simple.instances.orders[0].uri=http://127.0.0.1:" + orders);
    }

    @AfterAll
    static void stopSystem() {
        apps.forEach(ConfigurableApplicationContext::close);
    }

    private static HttpResponse<String> send(int port, String method, String path, String body, String... headers) throws Exception {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + path)).timeout(Duration.ofSeconds(30))
                .method(method, body == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofString(body));
        if (body != null) b.header("Content-Type", "application/json");
        for (int i = 0; i < headers.length; i += 2) b.header(headers[i], headers[i + 1]);
        return http.send(b.build(), HttpResponse.BodyHandlers.ofString());
    }

    private static HttpResponse<String> get(int port, String path, String... headers) throws Exception {
        return send(port, "GET", path, null, headers);
    }

    @Test
    void aServiceAloneIsAMonolithAndShowsNoCombinedView() throws Exception {
        String me = get(orders, "/securetest/api/v1/me").body();
        assertThat(me).contains("\"mode\":\"monolith\"");
        assertThat(get(orders, "/securetest/api/v1/fleet").body()).contains("\"services\":[]");
    }

    @Test
    void configuredMembersMakeItAMicroserviceSystem() throws Exception {
        assertThat(get(users, "/securetest/api/v1/me").body()).contains("\"mode\":\"microservices\"");
        HttpResponse<String> view = get(users, "/securetest/api/v1/fleet?refresh=true");
        assertThat(view.statusCode()).isEqualTo(200);
        String body = view.body();
        assertThat(body).contains("\"name\":\"users\"").contains("\"name\":\"orders\"");
        assertThat(body).contains("\"status\":\"OK\"").doesNotContain("UNAUTHORIZED").doesNotContain("UNREACHABLE");
        assertThat(body).contains("\"health\":\"UP\"").contains("\"modules\"").contains("\"gate\"");
        assertThat(body).contains("\"services\":2");
    }

    @Test
    void serviceDiscoveryFindsTheOtherServices() throws Exception {
        String body = get(billing, "/securetest/api/v1/fleet?refresh=true").body();
        assertThat(body).contains("\"mode\":\"microservices\"").contains("\"name\":\"orders\"").contains("\"name\":\"billing\"");
        assertThat(body).contains("\"status\":\"OK\"");
    }

    @Test
    void drillDownOpensTheOtherServicesDashboardAsTheSignedInUser() throws Exception {
        get(users, "/securetest/api/v1/fleet?refresh=true");
        HttpResponse<String> redirect = get(users, "/securetest/fleet/orders");
        assertThat(redirect.statusCode()).isEqualTo(302);
        HttpResponse<String> page = get(users, "/securetest/fleet/orders/");
        assertThat(page.statusCode()).isEqualTo(200);
        assertThat(page.body()).contains("SecureTest");
        assertThat(get(users, "/securetest/fleet/orders/js/fleet.js").statusCode()).isEqualTo(200);

        String me = get(users, "/securetest/fleet/orders/api/v1/me").body();
        assertThat(me).contains("\"name\":\"local-developer\"").contains("\"authMethod\":\"fleet:users\"");
    }

    @Test
    void writesThroughTheDrillDownReachTheOtherService() throws Exception {
        String path = "/securetest/fleet/orders/api/v1/modules/cloud-security/configuration";
        assertThat(send(users, "PUT", path, "{\"enabled\":true}").statusCode()).isEqualTo(403); // CSRF header missing
        HttpResponse<String> ok = send(users, "PUT", path, "{\"enabled\":true}", "X-SecureTest-Request", "1");
        assertThat(ok.statusCode()).as(ok.body()).isEqualTo(200);
        String modules = get(orders, "/securetest/api/v1/modules").body();
        assertThat(modules).containsPattern("\"id\":\"cloud-security\"[^}]*\"enabled\":true");
    }

    @Test
    void servicesRejectWrongOrMissingFleetTokens() throws Exception {
        assertThat(get(orders, "/securetest/api/v1/fleet/summary", "X-Forwarded-For", "203.0.113.5").statusCode()).isEqualTo(401);
        assertThat(get(orders, "/securetest/api/v1/fleet/summary", "X-Forwarded-For", "203.0.113.5",
                "X-SecureTest-Fleet-Token", "wrong").statusCode()).isEqualTo(401);
        HttpResponse<String> ok = get(orders, "/securetest/api/v1/fleet/summary", "X-Forwarded-For", "203.0.113.5",
                "X-SecureTest-Fleet-Token", TOKEN, "X-SecureTest-Fleet-User", "alice", "X-SecureTest-Fleet-Roles", "VIEWER");
        assertThat(ok.statusCode()).isEqualTo(200);
        assertThat(ok.body()).contains("\"service\":\"orders\"");
    }
}
