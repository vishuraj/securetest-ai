package com.securetest.autoconfigure.web;

import com.securetest.autoconfigure.security.RequestInfo;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.Map;

/** Structured error responses for the SecureTest API on Spring MVC (never affects host controllers). */
@RestControllerAdvice(basePackages = "com.securetest.autoconfigure.web")
public class ApiExceptionHandler {

    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, Object>> handle(Exception e, HttpServletRequest req) {
        Object info = req.getAttribute(RequestInfo.REQUEST_ATTRIBUTE);
        return ApiErrors.of(e, req.getRequestURI(), info instanceof RequestInfo r ? r.correlationId() : null);
    }
}
