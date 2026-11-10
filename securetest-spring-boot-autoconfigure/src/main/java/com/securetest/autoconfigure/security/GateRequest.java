package com.securetest.autoconfigure.security;

/** Read-only view of an HTTP request, implemented for Servlet and WebFlux. */
public interface GateRequest {

    /** Path below the servlet context path / WebFlux base path, e.g. {@code /securetest/api/v1/me}. */
    String path();

    String method();

    /** Raw (still encoded) query string without '?', or null. */
    default String query() { return null; }

    String remoteAddress();

    String header(String name);

    String parameter(String name);

    String cookie(String name);

    String scheme();

    String serverName();

    int serverPort();

    /** Servlet context path or WebFlux base path ("" when none). */
    String contextPath();

    boolean secure();

    /** Authenticated host-application user name (container authentication), or null. */
    String userName();

    /** True when the host application's authenticated user has this role/authority. */
    boolean isUserInRole(String role);
}
