package com.securetest.autoconfigure.web;

import com.securetest.autoconfigure.security.ApiException;
import com.securetest.autoconfigure.security.Authz;
import com.securetest.core.spi.ScanRejectedException;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Structured error responses for the SecureTest API only (never affects host controllers). */
@RestControllerAdvice(basePackages = "com.securetest.autoconfigure.web")
public class ApiExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(ApiExceptionHandler.class);

    @ExceptionHandler(ApiException.class)
    public ResponseEntity<Map<String, Object>> api(ApiException e, HttpServletRequest req) {
        return body(e.status(), e.code(), e.getMessage(), e.details(), req);
    }

    @ExceptionHandler(ScanRejectedException.class)
    public ResponseEntity<Map<String, Object>> rejected(ScanRejectedException e, HttpServletRequest req) {
        return body(422, "rejected", e.getMessage(), List.of(), req);
    }

    @ExceptionHandler(SecurityException.class)
    public ResponseEntity<Map<String, Object>> security(SecurityException e, HttpServletRequest req) {
        return body(403, "forbidden", e.getMessage(), List.of(), req);
    }

    @ExceptionHandler({IllegalArgumentException.class, HttpMessageNotReadableException.class})
    public ResponseEntity<Map<String, Object>> bad(Exception e, HttpServletRequest req) {
        return body(400, "bad_request", e.getMessage() == null ? "Bad request" : e.getMessage().split("\n")[0], List.of(), req);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, Object>> other(Exception e, HttpServletRequest req) {
        log.warn("SecureTest API error on {}: {}", req.getRequestURI(), e.toString());
        return body(500, "internal_error", "Unexpected error (correlation id " + Authz.correlationId() + ")", List.of(), req);
    }

    private static ResponseEntity<Map<String, Object>> body(int status, String code, String message, List<?> details, HttpServletRequest req) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("timestamp", Instant.now().toString());
        m.put("status", status);
        m.put("error", code);
        m.put("message", message);
        if (details != null && !details.isEmpty()) m.put("details", details);
        m.put("correlationId", Authz.correlationId());
        m.put("path", req.getRequestURI());
        return ResponseEntity.status(status).body(m);
    }
}
