package com.securetest.core.util;

import com.securetest.core.spi.HttpProbe;
import com.securetest.core.spi.TargetGuard;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Map;

/** HttpProbe implementation: allowlist check on every request, no redirects, bounded body, request pacing. */
public class GuardedHttpProbe implements HttpProbe {

    private static final int MAX_BODY = 1024 * 1024;

    private final TargetGuard guard;
    private final HttpClient client;
    private final Duration requestTimeout;
    private final long minIntervalNanos;
    private long lastRequest;

    /** @param maxRequestsPerSecond pacing limit; 0 = unlimited */
    public GuardedHttpProbe(TargetGuard guard, Duration connectTimeout, Duration requestTimeout, int maxRequestsPerSecond) {
        this.guard = guard;
        this.requestTimeout = requestTimeout;
        this.minIntervalNanos = maxRequestsPerSecond > 0 ? 1_000_000_000L / maxRequestsPerSecond : 0;
        this.client = HttpClient.newBuilder()
                .connectTimeout(connectTimeout)
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();
    }

    @Override
    public HttpResult send(String method, String url, Map<String, String> headers, String body)
            throws IOException, InterruptedException {
        URI uri = guard.requireAllowedUrl(url);
        pace();
        HttpRequest.Builder b = HttpRequest.newBuilder(uri).timeout(requestTimeout)
                .header("User-Agent", "SecureTest-Scanner/1.0");
        headers.forEach(b::header);
        HttpRequest.BodyPublisher pub = body == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofString(body);
        b.method(method, pub);
        long start = System.nanoTime();
        HttpResponse<InputStream> resp = client.send(b.build(), HttpResponse.BodyHandlers.ofInputStream());
        String text;
        try (InputStream in = resp.body()) {
            text = new String(in.readNBytes(MAX_BODY), StandardCharsets.UTF_8);
        }
        long ms = (System.nanoTime() - start) / 1_000_000;
        return new HttpResult(uri.toString(), resp.statusCode(), resp.headers().map(), text, ms);
    }

    private synchronized void pace() throws InterruptedException {
        if (minIntervalNanos == 0) return;
        long now = System.nanoTime();
        long wait = lastRequest + minIntervalNanos - now;
        if (wait > 0) Thread.sleep(wait / 1_000_000, (int) (wait % 1_000_000));
        lastRequest = System.nanoTime();
    }
}
