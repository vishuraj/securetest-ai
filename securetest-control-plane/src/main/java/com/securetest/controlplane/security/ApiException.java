package com.securetest.controlplane.security;

import org.springframework.http.HttpStatus;

/** Error with an HTTP status, rendered as {@code {"error": ..., "message": ...}}. */
public class ApiException extends RuntimeException {
    private final HttpStatus status;

    public ApiException(HttpStatus status, String message) {
        super(message);
        this.status = status;
    }

    public HttpStatus status() { return status; }

    public static ApiException notFound(String what) { return new ApiException(HttpStatus.NOT_FOUND, what + " not found"); }
    public static ApiException forbidden(String why) { return new ApiException(HttpStatus.FORBIDDEN, why); }
    public static ApiException badRequest(String why) { return new ApiException(HttpStatus.BAD_REQUEST, why); }
}
