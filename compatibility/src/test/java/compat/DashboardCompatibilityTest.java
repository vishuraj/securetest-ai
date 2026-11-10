package compat;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringBootVersion;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.env.Environment;

import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/** Default profile: what a developer sees after adding the dependency to a fresh app. */
@SpringBootTest(classes = CompatApp.class, webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "securetest.data.persist=false",
        "securetest.data.storage-dir=target/compat-default"
})
class DashboardCompatibilityTest {

    private static final String CSRF = "X-SecureTest-Request";
    private static final String REMOTE = "X-Forwarded-For";

    @Autowired
    Environment env;

    Http http;

    @BeforeEach
    void client() {
        http = new Http(env.getRequiredProperty("local.server.port", Integer.class));
        System.out.println("Spring Boot " + SpringBootVersion.getVersion());
    }

    @Test
    void dashboardOpens() throws Exception {
        HttpResponse<String> redirect = http.get("/securetest");
        assertThat(redirect.statusCode()).isBetween(301, 308);
        assertThat(redirect.headers().firstValue("Location")).hasValueSatisfying(l -> assertThat(l).endsWith("/securetest/"));

        HttpResponse<String> index = http.get("/securetest/");
        assertThat(index.statusCode()).isEqualTo(200);
        assertThat(index.body()).contains("SecureTest");
        assertThat(http.get("/securetest/js/app.js").statusCode()).isEqualTo(200);

        HttpResponse<String> me = http.get("/securetest/api/v1/me");
        assertThat(me.statusCode()).isEqualTo(200);
        assertThat(Http.field(me.body(), "name")).isEqualTo("local-developer");
    }

    @Test
    void aSingleAppIsAMonolithAndStillServesItsFleetSummary() throws Exception {
        assertThat(http.get("/securetest/api/v1/me").body()).contains("\"mode\":\"monolith\"");
        HttpResponse<String> summary = http.get("/securetest/api/v1/fleet/summary");
        assertThat(summary.statusCode()).isEqualTo(200);
        assertThat(summary.body()).contains("\"health\":\"UP\"").contains("\"modules\"").contains("\"gate\"");
    }

    @Test
    void applicationSecurityIsUnchanged() throws Exception {
        HttpResponse<String> hello = http.get("/hello", "Accept", "application/json");
        assertThat(hello.statusCode()).isEqualTo(401);
    }

    @Test
    void apiWritesAndScansWork() throws Exception {
        String config = "{\"enabled\":true}";
        assertThat(http.send("PUT", "/securetest/api/v1/modules/compliance/configuration", config).statusCode()).isEqualTo(403);
        assertThat(http.send("PUT", "/securetest/api/v1/modules/compliance/configuration", config, CSRF, "1").statusCode()).isEqualTo(200);

        HttpResponse<String> created = http.send("POST", "/securetest/api/v1/scans", "{\"scannerId\":\"config-posture\",\"options\":{}}", CSRF, "1");
        assertThat(created.statusCode()).as(created.body()).isEqualTo(201);
        String id = Http.field(created.body().substring(created.body().indexOf("\"job\"")), "id");
        String status = "QUEUED";
        for (int i = 0; i < 120 && !List.of("COMPLETED", "FAILED").contains(status); i++) {
            Thread.sleep(250);
            status = Http.field(http.get("/securetest/api/v1/scans/" + id).body(), "status");
        }
        assertThat(status).isEqualTo("COMPLETED");

        HttpResponse<String> openapi = http.get("/securetest/api/v1/openapi.json");
        assertThat(openapi.statusCode()).isEqualTo(200);
        assertThat(openapi.body()).contains("/securetest/api/v1/scans");
    }

    @Test
    void remoteUsersSignIn() throws Exception {
        HttpResponse<String> anon = http.get("/securetest/api/v1/me", REMOTE, "203.0.113.9");
        assertThat(anon.statusCode()).isEqualTo(401);
        assertThat(anon.headers().firstValue("WWW-Authenticate")).isPresent();

        String password = Files.readString(Path.of("target/compat-default/initial-admin-password")).trim();
        HttpResponse<String> me = http.get("/securetest/api/v1/me", REMOTE, "203.0.113.9", "Authorization", Http.basic("admin", password));
        assertThat(me.statusCode()).isEqualTo(200);
        assertThat(Http.field(me.body(), "name")).isEqualTo("admin");
        assertThat(http.get("/securetest/api/v1/me", REMOTE, "203.0.113.9", "Authorization", Http.basic("admin", "wrong")).statusCode()).isEqualTo(401);
    }
}
