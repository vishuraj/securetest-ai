package com.securetest.core.spi;

import java.io.IOException;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/** Allowlist-enforcing HTTP client handed to scanners. Redirects are never followed automatically. */
public interface HttpProbe {

    HttpResult send(String method, String url, Map<String, String> headers, String body)
            throws IOException, InterruptedException;

    default HttpResult get(String url) throws IOException, InterruptedException {
        return send("GET", url, Map.of(), null);
    }

    default HttpResult get(String url, Map<String, String> headers) throws IOException, InterruptedException {
        return send("GET", url, headers, null);
    }

    record HttpResult(String url, int status, Map<String, List<String>> headers, String body, long durationMs) {

        public String header(String name) {
            for (Map.Entry<String, List<String>> e : headers.entrySet()) {
                if (e.getKey() != null && e.getKey().equalsIgnoreCase(name) && !e.getValue().isEmpty()) {
                    return e.getValue().get(0);
                }
            }
            return null;
        }

        public List<String> headerValues(String name) {
            for (Map.Entry<String, List<String>> e : headers.entrySet()) {
                if (e.getKey() != null && e.getKey().toLowerCase(Locale.ROOT).equals(name.toLowerCase(Locale.ROOT))) {
                    return e.getValue();
                }
            }
            return List.of();
        }

        public boolean success() { return status >= 200 && status < 300; }
    }
}
