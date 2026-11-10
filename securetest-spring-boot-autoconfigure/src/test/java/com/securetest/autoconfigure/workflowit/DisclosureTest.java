package com.securetest.autoconfigure.workflowit;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.context.ConfigurableApplicationContext;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;

/** The vulnerability disclosure program: off by default; when on, security.txt, the public form and triage. */
class DisclosureTest {

    @SpringBootApplication
    static class App { }

    private final List<ConfigurableApplicationContext> apps = new ArrayList<>();
    private final HttpClient http = HttpClient.newHttpClient();

    private int start(String stack, String... extra) {
        List<String> p = new ArrayList<>(List.of("server.port=0", "spring.main.web-application-type=" + stack, "securetest.data.persist=false",
                "securetest.data.storage-dir=target/vdp-" + System.nanoTime()));
        p.addAll(List.of(extra));
        ConfigurableApplicationContext ctx = new SpringApplicationBuilder(App.class).properties(p.toArray(String[]::new)).run();
        apps.add(ctx);
        return ctx.getEnvironment().getRequiredProperty("local.server.port", Integer.class);
    }

    @AfterEach
    void stop() {
        apps.forEach(ConfigurableApplicationContext::close);
    }

    private HttpResponse<String> get(int port, String path, String... headers) throws Exception {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + path)).timeout(Duration.ofSeconds(30));
        for (int i = 0; i < headers.length; i += 2) b.header(headers[i], headers[i + 1]);
        return http.send(b.build(), HttpResponse.BodyHandlers.ofString());
    }

    private HttpResponse<String> submit(int port, Map<String, String> form) throws Exception {
        String body = form.entrySet().stream().map(e -> e.getKey() + "=" + URLEncoder.encode(e.getValue(), StandardCharsets.UTF_8)).collect(Collectors.joining("&"));
        return http.send(HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + "/securetest/disclose"))
                .header("Content-Type", "application/x-www-form-urlencoded").header("X-Forwarded-For", "198.51.100.7")
                .POST(HttpRequest.BodyPublishers.ofString(body)).build(), HttpResponse.BodyHandlers.ofString());
    }

    private HttpResponse<String> api(int port, String method, String path, String json) throws Exception {
        return http.send(HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + "/securetest/api/v1" + path))
                .header("X-SecureTest-Request", "1").header("Content-Type", "application/json")
                .method(method, json == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofString(json)).build(), HttpResponse.BodyHandlers.ofString());
    }

    @Test
    void offByDefault() throws Exception {
        int port = start("servlet");
        assertThat(get(port, "/.well-known/security.txt").statusCode()).isIn(401, 403, 404); // nothing served by SecureTest
        assertThat(get(port, "/securetest/disclose", "X-Forwarded-For", "198.51.100.7").statusCode()).isEqualTo(401); // not public
    }

    @Test
    void researchersReportAndTheTeamTriages() throws Exception {
        int port = start("servlet", "securetest.disclosure.enabled=true", "securetest.disclosure.contact[0]=mailto:security@acme.test",
                "securetest.disclosure.policy=https://acme.test/security-policy", "securetest.disclosure.reports-per-hour=2");
        HttpResponse<String> txt = get(port, "/.well-known/security.txt");
        assertThat(txt.statusCode()).isEqualTo(200);
        assertThat(txt.headers().firstValue("Content-Type").orElse("")).startsWith("text/plain");
        assertThat(txt.body()).contains("Contact: mailto:security@acme.test").contains("Contact: http://127.0.0.1:" + port + "/securetest/disclose")
                .contains("Expires: ").contains("Policy: https://acme.test/security-policy").contains("Canonical: http://127.0.0.1:" + port + "/.well-known/security.txt");

        HttpResponse<String> form = get(port, "/securetest/disclose", "X-Forwarded-For", "198.51.100.7");
        assertThat(form.statusCode()).isEqualTo(200);
        assertThat(form.body()).contains("<form method=\"post\">").doesNotContain("<script");

        HttpResponse<String> sent = submit(port, Map.of("title", "Open redirect on /login?next=", "description", "next=https://evil.test is followed",
                "reporterName", "Ana", "reporterEmail", "ana@researcher.test", "publicCredit", "true"));
        assertThat(sent.statusCode()).isEqualTo(200);
        Matcher m = Pattern.compile("(VDP-\\d{4})").matcher(sent.body());
        assertThat(m.find()).isTrue();
        String id = m.group(1);
        assertThat(submit(port, Map.of("title", "spam", "description", "buy now", "website", "http://spam.test")).statusCode()).isEqualTo(200); // honeypot: dropped
        assertThat(submit(port, Map.of("title", "missing description", "description", " ")).statusCode()).isEqualTo(400);
        assertThat(submit(port, Map.of("title", "Second", "description", "x")).statusCode()).isEqualTo(200);
        assertThat(submit(port, Map.of("title", "Third", "description", "y")).statusCode()).isEqualTo(429); // 2 per hour

        String list = api(port, "GET", "/disclosures", null).body();
        assertThat(list).contains(id).contains("Open redirect").doesNotContain("spam.test").doesNotContain("198.51.100.7");
        String triaged = api(port, "POST", "/disclosures/" + id + "/triage", "{\"decision\":\"ACCEPTED\",\"severity\":\"MEDIUM\",\"moduleId\":\"api-security\"}").body();
        Matcher f = Pattern.compile("\"findingId\":\"(F-\\d+)\"").matcher(triaged);
        assertThat(f.find()).isTrue();
        assertThat(api(port, "GET", "/findings/" + f.group(1), null).body()).contains("\"disclosureId\":\"" + id + "\"").contains("\"reportedBy\":\"Ana\"");
    }

    @Test
    void securityTxtOnWebFlux() throws Exception {
        int port = start("reactive", "securetest.disclosure.enabled=true", "securetest.disclosure.contact[0]=mailto:security@acme.test");
        HttpResponse<String> txt = get(port, "/.well-known/security.txt");
        assertThat(txt.statusCode()).isEqualTo(200);
        assertThat(txt.body()).contains("Contact: mailto:security@acme.test").contains("/securetest/disclose");
    }
}
