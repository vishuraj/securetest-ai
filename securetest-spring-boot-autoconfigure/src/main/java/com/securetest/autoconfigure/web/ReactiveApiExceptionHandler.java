package com.securetest.autoconfigure.web;

import com.securetest.autoconfigure.security.RequestInfo;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.server.ServerWebExchange;

import java.util.Map;

/** Structured error responses for the SecureTest API on WebFlux (never affects host controllers). */
@RestControllerAdvice(basePackages = "com.securetest.autoconfigure.web")
public class ReactiveApiExceptionHandler {

    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, Object>> handle(Exception e, ServerWebExchange exchange) {
        RequestInfo info = exchange.getAttribute(RequestInfo.REQUEST_ATTRIBUTE);
        return ApiErrors.of(e, exchange.getRequest().getPath().value(), info == null ? null : info.correlationId());
    }
}
