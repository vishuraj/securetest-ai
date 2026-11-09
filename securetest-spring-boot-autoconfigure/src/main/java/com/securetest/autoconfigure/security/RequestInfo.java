package com.securetest.autoconfigure.security;

/** Non-authenticated request facts for endpoints that run without a dashboard user (e.g. webhook ingestion). */
public record RequestInfo(String remoteAddress, String correlationId, String path) {

    public static final String REQUEST_ATTRIBUTE = RequestInfo.class.getName();
}
