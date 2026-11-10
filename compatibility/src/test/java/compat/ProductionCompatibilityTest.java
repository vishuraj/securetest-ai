package compat;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.env.Environment;
import org.springframework.test.context.ActiveProfiles;

import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.assertj.core.api.Assertions.assertThat;

/** 'prod' profile: the dashboard stays on, but every request must sign in, even from the same machine. */
@SpringBootTest(classes = CompatApp.class, webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "securetest.data.persist=false",
        "securetest.data.storage-dir=target/compat-prod"
})
@ActiveProfiles("prod")
class ProductionCompatibilityTest {

    @Autowired
    Environment env;

    @Test
    void dashboardRequiresSignInInProduction() throws Exception {
        Http http = new Http(env.getRequiredProperty("local.server.port", Integer.class));
        assertThat(http.get("/securetest/").statusCode()).isEqualTo(401);

        String password = Files.readString(Path.of("target/compat-prod/initial-admin-password")).trim();
        HttpResponse<String> index = http.get("/securetest/", "Authorization", Http.basic("admin", password));
        assertThat(index.statusCode()).isEqualTo(200);
        assertThat(index.body()).contains("SecureTest");
        assertThat(http.get("/hello", "Accept", "application/json").statusCode()).isEqualTo(401);
    }
}
