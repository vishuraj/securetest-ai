package com.securetest.autoconfigure.it;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/** A WebFlux application secured by Spring Security that only adds the starter. */
@SpringBootTest(classes = ReactiveSecuredAppTest.App.class, webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "spring.main.web-application-type=reactive",
        "securetest.data.persist=false",
        "securetest.data.storage-dir=target/it-reactive"
})
class ReactiveSecuredAppTest {

    @SpringBootApplication
    @RestController
    static class App {
        @GetMapping("/hello")
        String hello() { return "hi"; }
    }

    @Autowired
    WebTestClient web;

    private WebTestClient client() {
        return web.mutate().responseTimeout(Duration.ofSeconds(30)).build();
    }

    @Test
    void dashboardWorksAndHostSecurityIsUntouched() {
        client().get().uri("/securetest").exchange().expectStatus().isFound().expectHeader().valueEquals("Location", "/securetest/");
        String html = client().get().uri("/securetest/").exchange().expectStatus().isOk().expectBody(String.class).returnResult().getResponseBody();
        assertThat(html).contains("SecureTest");
        client().get().uri("/securetest/js/app.js").exchange().expectStatus().isOk();
        client().get().uri("/securetest/api/v1/me").exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.name").isEqualTo("local-developer");
        // the application's own endpoints are still protected by Spring Security's default chain
        client().get().uri("/hello").exchange().expectStatus().isUnauthorized();
    }

    @Test
    @SuppressWarnings("unchecked")
    void apiWritesAndScansRunOnWebFlux() throws Exception {
        client().put().uri("/securetest/api/v1/modules/compliance/configuration").contentType(MediaType.APPLICATION_JSON)
                .bodyValue(Map.of("enabled", true)).exchange().expectStatus().isForbidden(); // no CSRF header
        client().put().uri("/securetest/api/v1/modules/compliance/configuration").header("X-SecureTest-Request", "1")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(Map.of("enabled", true)).exchange().expectStatus().isOk();
        Map<String, Object> created = client().post().uri("/securetest/api/v1/scans").header("X-SecureTest-Request", "1")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(Map.of("scannerId", "config-posture", "options", Map.of()))
                .exchange().expectStatus().isCreated().expectBody(Map.class).returnResult().getResponseBody();
        String id = (String) ((Map<String, Object>) created.get("job")).get("id");
        String status = "QUEUED";
        for (int i = 0; i < 80 && !List.of("COMPLETED", "FAILED").contains(status); i++) {
            Thread.sleep(250);
            status = (String) client().get().uri("/securetest/api/v1/scans/" + id).exchange().expectBody(Map.class).returnResult().getResponseBody().get("status");
        }
        assertThat(status).isEqualTo("COMPLETED");
        Map<String, Object> openapi = client().get().uri("/securetest/api/v1/openapi.json").exchange().expectStatus().isOk()
                .expectBody(Map.class).returnResult().getResponseBody();
        assertThat((Map<String, Object>) openapi.get("paths")).containsKey("/securetest/api/v1/scans");
    }

    @Test
    void remoteUsersSignInWithTheGeneratedAdmin() throws Exception {
        client().get().uri("/securetest/api/v1/me").header("X-Forwarded-For", "203.0.113.9").exchange()
                .expectStatus().isUnauthorized().expectHeader().exists("WWW-Authenticate");
        String password = Files.readString(Path.of("target/it-reactive/initial-admin-password")).trim();
        client().get().uri("/securetest/api/v1/me").header("X-Forwarded-For", "203.0.113.9").headers(h -> h.setBasicAuth("admin", password))
                .exchange().expectStatus().isOk().expectBody().jsonPath("$.name").isEqualTo("admin");
        client().get().uri("/securetest/api/v1/me").header("X-Forwarded-For", "203.0.113.9").headers(h -> h.setBasicAuth("admin", "wrong"))
                .exchange().expectStatus().isUnauthorized();
    }
}
