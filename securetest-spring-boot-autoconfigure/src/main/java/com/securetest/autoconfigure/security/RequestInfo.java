package com.securetest.autoconfigure.security;

/** Non-authenticated request facts for endpoints that run without a dashboard user (e.g. webhook ingestion). */
public record RequestInfo(String remoteAddress, String correlationId, String path, String query) {

    public RequestInfo(String remoteAddress, String correlationId, String path) {
        this(remoteAddress, correlationId, path, null);
    }

    public static final String REQUEST_ATTRIBUTE = RequestInfo.class.getName();
}
