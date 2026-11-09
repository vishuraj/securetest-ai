package com.securetest.autoconfigure.web;

import com.securetest.autoconfigure.security.ApiException;
import com.securetest.core.spi.ScanRejectedException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Structured error bodies shared by the Servlet and WebFlux exception handlers. */
final class ApiErrors {

    private static final Logger log = LoggerFactory.getLogger(ApiErrors.class);

    private ApiErrors() { }

    static ResponseEntity<Map<String, Object>> of(Throwable e, String path, String correlationId) {
        if (e instanceof ApiException a) return body(a.status(), a.code(), a.getMessage(), a.details(), path, correlationId);
        if (e instanceof ScanRejectedException) return body(422, "rejected", e.getMessage(), List.of(), path, correlationId);
        if (e instanceof SecurityException) return body(403, "forbidden", e.getMessage(), List.of(), path, correlationId);
        if (e instanceof IllegalArgumentException || e.getClass().getSimpleName().contains("NotReadable") || e.getClass().getSimpleName().contains("ServerWebInput")) {
            return body(400, "bad_request", e.getMessage() == null ? "Bad request" : e.getMessage().split("\n")[0], List.of(), path, correlationId);
        }
        log.warn("SecureTest API error on {}: {}", path, e.toString());
        return body(500, "internal_error", "Unexpected error (correlation id " + correlationId + ")", List.of(), path, correlationId);
    }

    private static ResponseEntity<Map<String, Object>> body(int status, String code, String message, List<?> details, String path, String correlationId) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("timestamp", Instant.now().toString());
        m.put("status", status);
        m.put("error", code);
        m.put("message", message);
        if (details != null && !details.isEmpty()) m.put("details", details);
        m.put("correlationId", correlationId);
        m.put("path", path);
        return ResponseEntity.status(status).body(m);
    }
}
