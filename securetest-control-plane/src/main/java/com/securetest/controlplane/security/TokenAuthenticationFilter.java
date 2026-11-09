package com.securetest.controlplane.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Optional;
import java.util.function.Function;

/** Authenticates machine callers (agents, workers) by an opaque bearer token. */
public class TokenAuthenticationFilter extends OncePerRequestFilter {

    private final Function<String, Optional<Authentication>> resolver;

    public TokenAuthenticationFilter(Function<String, Optional<Authentication>> resolver) {
        this.resolver = resolver;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
            throws ServletException, IOException {
        String header = req.getHeader("Authorization");
        if (header != null && header.regionMatches(true, 0, "Bearer ", 0, 7)) {
            String token = header.substring(7).trim();
            if (!token.isEmpty()) {
                resolver.apply(token).ifPresent(a -> SecurityContextHolder.getContext().setAuthentication(a));
            }
        }
        chain.doFilter(req, res);
    }
}
