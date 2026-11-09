package com.securetest.autoconfigure.security;

import com.securetest.autoconfigure.SecureTestProperties;
import com.securetest.autoconfigure.security.Rbac.Role;
import com.securetest.autoconfigure.support.SecretResolver;
import com.securetest.core.util.Hashing;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.net.InetAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.EnumSet;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Protects the dashboard and its API (SEC-001..006, SRS 9.1):
 * loopback binding, authentication (local-dev / basic / container), CSRF defence, rate limiting,
 * correlation ids and strict security headers.
 */
public class SecureTestSecurityFilter extends OncePerRequestFilter {

    public static final String CORRELATION_ATTRIBUTE = "securetest.correlationId";
    public static final String CSRF_HEADER = "X-SecureTest-Request";
    private static final Logger log = LoggerFactory.getLogger(SecureTestSecurityFilter.class);
    private static final String CSP = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
            + "connect-src 'self'; font-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none'";

    private final SecureTestProperties props;
    private final SecretResolver secrets;
    private final String basePath;
    private final Map<String, double[]> buckets = new ConcurrentHashMap<>();
    private final OidcAuthenticator oidc;
    private final com.securetest.autoconfigure.service.AuditService audit;

    public SecureTestSecurityFilter(SecureTestProperties props, SecretResolver secrets) {
        this(props, secrets, null, null);
    }

    public SecureTestSecurityFilter(SecureTestProperties props, SecretResolver secrets, OidcAuthenticator oidc,
                                    com.securetest.autoconfigure.service.AuditService audit) {
        this.props = props;
        this.secrets = secrets;
        this.basePath = props.normalizedPath();
        this.oidc = oidc;
        this.audit = audit;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String uri = path(request);
        return !(uri.equals(basePath) || uri.startsWith(basePath + "/"));
    }

    private static String path(HttpServletRequest request) {
        String uri = request.getRequestURI();
        String ctx = request.getContextPath();
        return ctx != null && !ctx.isEmpty() && uri.startsWith(ctx) ? uri.substring(ctx.length()) : uri;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain) throws ServletException, IOException {
        String correlationId = sanitize(req.getHeader("X-Correlation-Id"));
        if (correlationId == null) correlationId = UUID.randomUUID().toString();
        req.setAttribute(CORRELATION_ATTRIBUTE, correlationId);
        res.setHeader("X-Correlation-Id", correlationId);
        MDC.put("correlationId", correlationId);
        try {
            headers(res, path(req).startsWith(basePath + "/api/"));
            boolean loopback = isLoopback(req.getRemoteAddr());
            if (loopbackOnly() && !loopback) {
                deny(res, 403, "The SecureTest dashboard only accepts local connections (securetest.dashboard.bind-address=127.0.0.1).");
                return;
            }
            String uri = path(req);
            boolean api = uri.startsWith(basePath + "/api/");
            boolean ingest = uri.equals(basePath + "/api/v1/integrations/events");
            if (api && !rateLimit(req.getRemoteAddr())) {
                res.setHeader("Retry-After", "1");
                deny(res, 429, "Too many requests");
                return;
            }
            if (ingest) { // machine-to-machine, token checked by the controller
                chain.doFilter(req, res);
                return;
            }
            if ("oidc".equals(provider()) && oidc != null) {
                if (uri.equals(basePath + "/oidc/login")) { oidc.startLogin(req, res, basePath); return; }
                if (uri.equals(basePath + "/oidc/logout")) { oidc.logout(req, res, basePath); return; }
                if (uri.equals(basePath + "/oidc/callback")) {
                    OidcAuthenticator.LoginResult r = oidc.callback(req, res, basePath);
                    if (audit != null) {
                        audit.record(r.user() == null ? "anonymous" : r.user(), req.getRemoteAddr(), "auth.login", "oidc",
                                r.success() ? "OK" : "DENIED", Map.of("detail", r.message()));
                    }
                    return;
                }
            }
            SecureTestPrincipal principal = authenticate(req, loopback);
            if (principal == null && "oidc".equals(provider()) && oidc != null && !api) {
                res.sendRedirect(req.getContextPath() + basePath + "/oidc/login");
                return;
            }
            if (principal == null) {
                if ("basic".equals(provider())) res.setHeader("WWW-Authenticate", "Basic realm=\"SecureTest\", charset=\"UTF-8\"");
                deny(res, 401, "Authentication required");
                return;
            }
            if (api && !isSafe(req.getMethod())) {
                if (!"1".equals(req.getHeader(CSRF_HEADER))) {
                    deny(res, 403, "Missing " + CSRF_HEADER + " header (CSRF protection)");
                    return;
                }
                String origin = req.getHeader("Origin");
                if (origin != null && !sameOrigin(origin, req)) {
                    deny(res, 403, "Cross-origin request rejected");
                    return;
                }
            }
            req.setAttribute(SecureTestPrincipal.REQUEST_ATTRIBUTE, principal);
            chain.doFilter(req, res);
        } finally {
            MDC.remove("correlationId");
        }
    }

    private String provider() {
        return props.getDashboard().getAuthentication().getProvider().toLowerCase(Locale.ROOT);
    }

    public boolean loopbackOnly() {
        String b = props.getDashboard().getBindAddress();
        return b == null || b.isBlank() || b.equals("127.0.0.1") || b.equals("::1") || b.equalsIgnoreCase("localhost") || b.equals("loopback");
    }

    private SecureTestPrincipal authenticate(HttpServletRequest req, boolean loopback) {
        SecureTestProperties.Authentication auth = props.getDashboard().getAuthentication();
        if (!auth.isEnabled()) {
            // explicitly disabled: still only acceptable on loopback (warned at startup otherwise)
            return loopback ? new SecureTestPrincipal("anonymous-local", EnumSet.of(Role.ADMIN), "none", req.getRemoteAddr()) : null;
        }
        return switch (provider()) {
            case "basic" -> basic(req);
            case "container" -> container(req);
            case "oidc" -> oidc == null ? null : oidc.principal(req);
            default -> loopback ? new SecureTestPrincipal("local-developer", EnumSet.of(Role.ADMIN), "local-dev", req.getRemoteAddr()) : null;
        };
    }

    private SecureTestPrincipal basic(HttpServletRequest req) {
        String h = req.getHeader("Authorization");
        if (h == null || !h.regionMatches(true, 0, "Basic ", 0, 6)) return null;
        String decoded;
        try {
            decoded = new String(Base64.getDecoder().decode(h.substring(6).trim()), StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            return null;
        }
        int idx = decoded.indexOf(':');
        if (idx < 0) return null;
        String user = decoded.substring(0, idx);
        String pass = decoded.substring(idx + 1);
        for (SecureTestProperties.User u : props.getDashboard().getAuthentication().getUsers()) {
            if (u.getUsername() != null && u.getUsername().equals(user) && passwordMatches(u.getPassword(), pass)) {
                Set<Role> roles = EnumSet.noneOf(Role.class);
                for (String r : u.getRoles()) {
                    try { roles.add(Role.parse(r)); } catch (IllegalArgumentException ignored) { /* unknown role */ }
                }
                return new SecureTestPrincipal(user, roles, "basic", req.getRemoteAddr());
            }
        }
        log.warn("SecureTest: failed dashboard login for user '{}' from {}", user.replaceAll("[\\r\\n]", ""), req.getRemoteAddr());
        return null;
    }

    private boolean passwordMatches(String configured, String supplied) {
        if (configured == null) return false;
        String expected;
        String actual;
        if (configured.startsWith("{sha256}")) {
            expected = configured.substring(8).toLowerCase(Locale.ROOT);
            actual = Hashing.sha256(supplied);
        } else if (configured.startsWith("{env}")) {
            expected = System.getenv(configured.substring(5));
            actual = supplied;
        } else if (com.securetest.core.util.Redactor.isReference(configured)) {
            expected = secrets.resolve(configured);
            actual = supplied;
        } else {
            expected = configured.startsWith("{noop}") ? configured.substring(6) : configured;
            actual = supplied;
        }
        return expected != null && MessageDigest.isEqual(expected.getBytes(StandardCharsets.UTF_8), actual.getBytes(StandardCharsets.UTF_8));
    }

    private SecureTestPrincipal container(HttpServletRequest req) {
        if (req.getUserPrincipal() == null) return null;
        Set<Role> roles = EnumSet.noneOf(Role.class);
        for (Role r : Role.values()) {
            if (req.isUserInRole("SECURETEST_" + r.name())) roles.add(r);
        }
        props.getDashboard().getAuthentication().getRoleMapping().forEach((hostRole, stRole) -> {
            if (req.isUserInRole(hostRole)) {
                try { roles.add(Role.parse(stRole)); } catch (IllegalArgumentException ignored) { /* bad mapping */ }
            }
        });
        if (roles.isEmpty()) return null; // authenticated but not authorized for SecureTest
        return new SecureTestPrincipal(req.getUserPrincipal().getName(), roles, "container", req.getRemoteAddr());
    }

    private boolean rateLimit(String client) {
        int limit = Math.max(1, props.getSecurity().getApiRateLimit());
        long now = System.nanoTime();
        if (buckets.size() > 10_000) buckets.clear();
        double[] b = buckets.computeIfAbsent(client, k -> new double[] {limit * 3.0, now});
        synchronized (b) {
            double elapsed = (now - (long) b[1]) / 1e9;
            b[0] = Math.min(limit * 3.0, b[0] + elapsed * limit);
            b[1] = now;
            if (b[0] < 1) return false;
            b[0] -= 1;
            return true;
        }
    }

    private static void headers(HttpServletResponse res, boolean api) {
        res.setHeader("Content-Security-Policy", CSP);
        res.setHeader("X-Content-Type-Options", "nosniff");
        res.setHeader("X-Frame-Options", "DENY");
        res.setHeader("Referrer-Policy", "no-referrer");
        res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
        res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
        res.setHeader("Cache-Control", api ? "no-store" : "no-cache");
    }

    private static void deny(HttpServletResponse res, int status, String message) throws IOException {
        res.setStatus(status);
        res.setContentType("application/json");
        res.setCharacterEncoding("UTF-8");
        res.getWriter().write("{\"status\":" + status + ",\"error\":\"" + message.replace("\"", "'") + "\"}");
    }

    private static boolean isSafe(String method) {
        return method.equals("GET") || method.equals("HEAD") || method.equals("OPTIONS");
    }

    private static boolean sameOrigin(String origin, HttpServletRequest req) {
        try {
            URI o = URI.create(origin);
            int port = o.getPort() == -1 ? ("https".equals(o.getScheme()) ? 443 : 80) : o.getPort();
            String host = req.getServerName();
            return o.getHost() != null && o.getHost().equalsIgnoreCase(host) && port == req.getServerPort();
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    static boolean isLoopback(String addr) {
        if (addr == null) return false;
        try {
            return InetAddress.getByName(addr).isLoopbackAddress();
        } catch (Exception e) {
            return false;
        }
    }

    private static String sanitize(String id) {
        return id != null && id.matches("[A-Za-z0-9._-]{1,100}") ? id : null;
    }
}
