package com.securetest.autoconfigure.security;

import java.util.List;

/** Structured API error (SRS 11: structured error responses). */
public class ApiException extends RuntimeException {

    private final int status;
    private final String code;
    private final transient List<?> details;

    public ApiException(int status, String code, String message) {
        this(status, code, message, List.of());
    }

    public ApiException(int status, String code, String message, List<?> details) {
        super(message);
        this.status = status;
        this.code = code;
        this.details = details;
    }

    public int status() { return status; }
    public String code() { return code; }
    public List<?> details() { return details; }

    public static ApiException notFound(String what) { return new ApiException(404, "not_found", what + " not found"); }
    public static ApiException forbidden(String message) { return new ApiException(403, "forbidden", message); }
    public static ApiException badRequest(String message) { return new ApiException(400, "bad_request", message); }
    public static ApiException conflict(String message) { return new ApiException(409, "conflict", message); }
}
