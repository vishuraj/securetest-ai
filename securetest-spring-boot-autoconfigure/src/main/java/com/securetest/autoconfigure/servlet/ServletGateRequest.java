package com.securetest.autoconfigure.servlet;

import com.securetest.autoconfigure.security.GateRequest;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;

/** {@link GateRequest} over a Servlet request. */
public class ServletGateRequest implements GateRequest {

    private final HttpServletRequest req;

    public ServletGateRequest(HttpServletRequest req) {
        this.req = req;
    }

    @Override
    public String path() {
        String uri = req.getRequestURI();
        String ctx = req.getContextPath();
        return ctx != null && !ctx.isEmpty() && uri.startsWith(ctx) ? uri.substring(ctx.length()) : uri;
    }

    @Override public String method() { return req.getMethod(); }
    @Override public String remoteAddress() { return req.getRemoteAddr(); }
    @Override public String header(String name) { return req.getHeader(name); }
    @Override public String parameter(String name) { return req.getParameter(name); }

    @Override
    public String cookie(String name) {
        if (req.getCookies() == null) return null;
        for (Cookie c : req.getCookies()) if (name.equals(c.getName())) return c.getValue();
        return null;
    }

    @Override public String scheme() { return req.getScheme(); }
    @Override public String serverName() { return req.getServerName(); }
    @Override public int serverPort() { return req.getServerPort(); }
    @Override public String contextPath() { return req.getContextPath() == null ? "" : req.getContextPath(); }
    @Override public boolean secure() { return req.isSecure(); }
    @Override public String userName() { return req.getUserPrincipal() == null ? null : req.getUserPrincipal().getName(); }
    @Override public boolean isUserInRole(String role) { return req.isUserInRole(role); }
}
