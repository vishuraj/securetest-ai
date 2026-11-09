package com.securetest.worker;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.securetest.worker.sandbox.SandboxProtocol;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Map;
import java.util.Optional;

/** Worker side of the {@code /api/v1/worker/**} API. */
public class ControlPlaneClient {

    public static class ControlPlaneException extends IOException {
        public final int status;

        ControlPlaneException(int status, String message) {
            super(message);
            this.status = status;
        }
    }

    private final String baseUrl;
    private final String token;
    private final ObjectMapper mapper = SandboxProtocol.mapper();
    private final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build();

    public ControlPlaneClient(String baseUrl, String token) {
        if (baseUrl == null || baseUrl.isBlank()) throw new IllegalStateException("securetest.worker.control-plane-url is required");
        if (token == null || token.isBlank()) throw new IllegalStateException("securetest.worker.token is required");
        this.baseUrl = baseUrl.replaceAll("/+$", "");
        this.token = token.trim();
    }

    public void register(Object body) throws IOException, InterruptedException {
        post("/api/v1/worker/register", body);
    }

    /** @return the claimed job, or empty when the queue has nothing for this worker */
    @SuppressWarnings("unchecked")
    public Optional<Map<String, Object>> claim(Object body) throws IOException, InterruptedException {
        String json = post("/api/v1/worker/jobs/claim", body);
        return json == null || json.isBlank() ? Optional.empty() : Optional.of(mapper.readValue(json, Map.class));
    }

    @SuppressWarnings("unchecked")
    public Map<String, Object> heartbeat(String jobId, Object body) throws IOException, InterruptedException {
        return mapper.readValue(post("/api/v1/worker/jobs/" + jobId + "/heartbeat", body), Map.class);
    }

    public void complete(String jobId, Object body) throws IOException, InterruptedException {
        post("/api/v1/worker/jobs/" + jobId + "/complete", body);
    }

    private String post(String path, Object body) throws IOException, InterruptedException {
        HttpRequest req = HttpRequest.newBuilder(URI.create(baseUrl + path))
                .timeout(Duration.ofSeconds(60))
                .header("Content-Type", "application/json")
                .header("Authorization", "Bearer " + token)
                .POST(HttpRequest.BodyPublishers.ofString(mapper.writeValueAsString(body)))
                .build();
        HttpResponse<String> res = http.send(req, HttpResponse.BodyHandlers.ofString());
        if (res.statusCode() == 204) return null;
        if (res.statusCode() >= 300) {
            String b = res.body() == null ? "" : res.body();
            throw new ControlPlaneException(res.statusCode(), "Control plane returned HTTP " + res.statusCode() + " for " + path
                    + (b.isBlank() ? "" : ": " + (b.length() > 300 ? b.substring(0, 300) : b)));
        }
        return res.body();
    }
}
