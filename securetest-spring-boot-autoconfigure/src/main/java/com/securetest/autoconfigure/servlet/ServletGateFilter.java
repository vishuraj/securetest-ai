package com.securetest.autoconfigure.servlet;

import com.securetest.autoconfigure.security.DashboardGate;
import com.securetest.autoconfigure.security.GateResponse;
import com.securetest.autoconfigure.security.RequestInfo;
import com.securetest.autoconfigure.security.SecureTestPrincipal;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.MDC;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/** Applies the {@link DashboardGate} to dashboard requests on Spring MVC. */
public class ServletGateFilter extends OncePerRequestFilter {

    private final DashboardGate gate;

    public ServletGateFilter(DashboardGate gate) {
        this.gate = gate;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !gate.applies(new ServletGateRequest(request).path());
    }

    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain) throws ServletException, IOException {
        DashboardGate.Decision d = gate.handle(new ServletGateRequest(req));
        GateResponse g = d.response();
        g.headers().forEach(res::setHeader);
        g.cookies().forEach(c -> res.addHeader("Set-Cookie", c));
        if (!d.proceed()) {
            res.setStatus(g.status());
            if (g.body() != null) {
                res.setContentType(g.contentType());
                res.setCharacterEncoding("UTF-8");
                res.getWriter().write(g.body());
            }
            return;
        }
        req.setAttribute(RequestInfo.REQUEST_ATTRIBUTE, d.info());
        if (d.principal() != null) req.setAttribute(SecureTestPrincipal.REQUEST_ATTRIBUTE, d.principal());
        MDC.put("correlationId", d.info().correlationId());
        try {
            chain.doFilter(req, res);
        } finally {
            MDC.remove("correlationId");
        }
    }
}
