package compat;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;

/** Plain JDK HTTP calls, so the tests use no Spring Boot test API that differs between Boot versions. */
final class Http {

    private final HttpClient client = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER)
            .connectTimeout(Duration.ofSeconds(10)).build();
    private final String base;

    Http(int port) {
        this.base = "http://127.0.0.1:" + port;
    }

    HttpResponse<String> send(String method, String path, String body, String... headers) throws Exception {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(base + path)).timeout(Duration.ofSeconds(30))
                .method(method, body == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofString(body));
        if (body != null) b.header("Content-Type", "application/json");
        for (int i = 0; i < headers.length; i += 2) b.header(headers[i], headers[i + 1]);
        return client.send(b.build(), HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
    }

    HttpResponse<String> get(String path, String... headers) throws Exception {
        return send("GET", path, null, headers);
    }

    static String basic(String user, String password) {
        return "Basic " + Base64.getEncoder().encodeToString((user + ":" + password).getBytes(StandardCharsets.UTF_8));
    }

    /** Reads a top-level string field from a JSON object without a JSON library. */
    static String field(String json, String name) {
        java.util.regex.Matcher m = java.util.regex.Pattern.compile("\"" + name + "\"\\s*:\\s*\"([^\"]*)\"").matcher(json);
        return m.find() ? m.group(1) : null;
    }
}
