package com.securetest.autoconfigure.it;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/** A Spring MVC application with Spring Security, running under the 'prod' profile, that only adds the starter. */
@SpringBootTest(classes = ServletSecuredProductionAppTest.App.class, webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "securetest.data.persist=false",
        "securetest.data.storage-dir=target/it-servlet-prod"
})
@ActiveProfiles("prod")
class ServletSecuredProductionAppTest {

    @SpringBootApplication
    @RestController
    static class App {
        @GetMapping("/hello")
        String hello() { return "hi"; }
    }

    @Autowired
    TestRestTemplate http;

    private String password() throws Exception {
        return Files.readString(Path.of("target/it-servlet-prod/initial-admin-password")).trim();
    }

    @Test
    void dashboardIsOnInProductionButRequiresSignIn() throws Exception {
        ResponseEntity<String> anon = http.getForEntity("/securetest/", String.class);
        assertThat(anon.getStatusCode().value()).isEqualTo(401);
        assertThat(anon.getHeaders().getFirst("WWW-Authenticate")).startsWith("Basic");

        ResponseEntity<String> signedIn = http.withBasicAuth("admin", password()).getForEntity("/securetest/", String.class);
        assertThat(signedIn.getStatusCode().value()).isEqualTo(200);
        assertThat(signedIn.getBody()).contains("SecureTest");

        ResponseEntity<Map> me = http.withBasicAuth("admin", password()).getForEntity("/securetest/api/v1/me", Map.class);
        assertThat(me.getBody()).containsEntry("name", "admin");
        assertThat((Map<String, Object>) me.getBody().get("policy")).containsEntry("productionLike", true);
    }

    @Test
    void hostSecurityStillProtectsTheApplication() {
        HttpHeaders json = new HttpHeaders();
        json.setAccept(java.util.List.of(MediaType.APPLICATION_JSON));
        ResponseEntity<String> r = http.exchange("/hello", HttpMethod.GET, new HttpEntity<>(json), String.class);
        assertThat(r.getStatusCode().value()).isEqualTo(401); // Spring Boot's default security still guards the app itself
        assertThat(r.getBody()).isNotEqualTo("hi");
    }

    @Test
    void apiWritesWorkThroughSpringSecurity() throws Exception {
        HttpHeaders h = new HttpHeaders();
        h.setContentType(MediaType.APPLICATION_JSON);
        h.set("X-SecureTest-Request", "1");
        ResponseEntity<Map> r = http.withBasicAuth("admin", password())
                .exchange("/securetest/api/v1/modules/compliance/configuration", HttpMethod.PUT, new HttpEntity<>(Map.of("enabled", true), h), Map.class);
        assertThat(r.getStatusCode().value()).isEqualTo(200);
        assertThat(r.getBody()).containsEntry("enabled", true);
    }
}
