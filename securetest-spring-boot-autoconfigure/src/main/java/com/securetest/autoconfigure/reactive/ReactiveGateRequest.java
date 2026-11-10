package com.securetest.autoconfigure.reactive;

import com.securetest.autoconfigure.security.GateRequest;
import org.springframework.http.HttpCookie;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.web.server.ServerWebExchange;

import java.net.InetSocketAddress;
import java.security.Principal;
import java.util.Collection;
import java.util.Set;
import java.util.stream.Collectors;

/** {@link GateRequest} over a WebFlux exchange. */
public class ReactiveGateRequest implements GateRequest {

    private final ServerWebExchange exchange;
    private final ServerHttpRequest req;
    private final Principal principal;
    private final Set<String> authorities;

    public ReactiveGateRequest(ServerWebExchange exchange, Principal principal) {
        this.exchange = exchange;
        this.req = exchange.getRequest();
        this.principal = principal;
        this.authorities = authorities(principal);
    }

    /** Reads Spring Security authorities reflectively so Spring Security stays an optional dependency. */
    private static Set<String> authorities(Principal p) {
        if (p == null) return Set.of();
        try {
            Object a = p.getClass().getMethod("getAuthorities").invoke(p);
            if (a instanceof Collection<?> c) {
                return c.stream().map(x -> {
                    try {
                        return String.valueOf(x.getClass().getMethod("getAuthority").invoke(x));
                    } catch (ReflectiveOperationException e) {
                        return String.valueOf(x);
                    }
                }).collect(Collectors.toSet());
            }
        } catch (ReflectiveOperationException | RuntimeException ignored) {
            // not a Spring Security Authentication
        }
        return Set.of();
    }

    @Override
    public String path() {
        return req.getPath().pathWithinApplication().value();
    }

    @Override public String method() { return req.getMethod().name(); }
    @Override public String query() { return req.getURI().getRawQuery(); }

    @Override
    public String remoteAddress() {
        InetSocketAddress a = req.getRemoteAddress();
        return a == null || a.getAddress() == null ? null : a.getAddress().getHostAddress();
    }

    @Override public String header(String name) { return req.getHeaders().getFirst(name); }
    @Override public String parameter(String name) { return req.getQueryParams().getFirst(name); }

    @Override
    public String cookie(String name) {
        HttpCookie c = req.getCookies().getFirst(name);
        return c == null ? null : c.getValue();
    }

    @Override public String scheme() { return req.getURI().getScheme(); }
    @Override public String serverName() { return req.getURI().getHost(); }

    @Override
    public int serverPort() {
        int p = req.getURI().getPort();
        return p != -1 ? p : ("https".equals(scheme()) ? 443 : 80);
    }

    @Override public String contextPath() { return req.getPath().contextPath().value(); }
    @Override public boolean secure() { return req.getSslInfo() != null || "https".equals(scheme()); }
    @Override public String userName() { return principal == null ? null : principal.getName(); }

    @Override
    public boolean isUserInRole(String role) {
        return authorities.contains(role) || authorities.contains("ROLE_" + role);
    }

    ServerWebExchange exchange() { return exchange; }
}
