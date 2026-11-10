package com.securetest.autoconfigure.security;

import com.securetest.autoconfigure.SecureTestProperties;
import com.securetest.autoconfigure.fleet.FleetService;
import com.securetest.autoconfigure.security.Rbac.Role;
import com.securetest.autoconfigure.service.AuditService;
import com.securetest.autoconfigure.support.SecretResolver;
import com.securetest.core.util.Hashing;
import com.securetest.core.util.Redactor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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
import java.util.function.BooleanSupplier;

/**
 * Web-stack-neutral protection of the dashboard and its API (SEC-001..006, SRS 9.1), used by both the Servlet filter
 * and the WebFlux filter:
 * <ul>
 *   <li>authentication: {@code auto} (default) = local developer on the same machine, sign-in everywhere else
 *       (generated admin password unless you configure users); {@code local-dev}, {@code basic}, {@code container},
 *       {@code oidc};</li>
 *   <li>optional loopback-only mode ({@code bind-address: 127.0.0.1});</li>
 *   <li>CSRF defence for API writes, per-client rate limiting, correlation ids and strict security headers.</li>
 * </ul>
 * Requests are only treated as "local" when they come from a loopback address <em>and</em> carry no proxy forwarding
 * headers, so a reverse proxy on the same host never turns remote users into local administrators.
 */
public class DashboardGate {

    public static final String CSRF_HEADER = "X-SecureTest-Request";
    private static final Logger log = LoggerFactory.getLogger(DashboardGate.class);
    private static final String CSP = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
            + "connect-src 'self'; font-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none'";

    /** Outcome: either continue to the controllers with a principal (null only for webhook ingestion), or answered. */
    public record Decision(boolean proceed, SecureTestPrincipal principal, RequestInfo info, GateResponse response) { }

    private final SecureTestProperties props;
    private final SecretResolver secrets;
    private final OidcAuthenticator oidc;
    private final AuditService audit;
    private final InitialAdminCredential initialAdmin;
    private final BooleanSupplier productionLike;
    private final String basePath;
    private final Map<String, double[]> buckets = new ConcurrentHashMap<>();
    private volatile boolean warnedPlainHttp;

    public DashboardGate(SecureTestProperties props, SecretResolver secrets, OidcAuthenticator oidc, AuditService audit,
                         InitialAdminCredential initialAdmin, BooleanSupplier productionLike) {
        this.props = props;
        this.secrets = secrets;
        this.oidc = oidc;
        this.audit = audit;
        this.initialAdmin = initialAdmin;
        this.productionLike = productionLike;
        this.basePath = props.normalizedPath();
    }

    public String basePath() { return basePath; }

    public boolean applies(String path) {
        return path.equals(basePath) || path.startsWith(basePath + "/");
    }

    public Decision handle(GateRequest req) throws IOException {
        GateResponse res = new GateResponse();
        String correlationId = sanitize(req.header("X-Correlation-Id"));
        if (correlationId == null) correlationId = UUID.randomUUID().toString();
        res.header("X-Correlation-Id", correlationId);
        String uri = req.path();
        // the dashboard API, also when it is another service's API reached through the "All services" drill-down
        boolean api = uri.startsWith(basePath + "/api/") || (uri.startsWith(basePath + "/fleet/") && uri.indexOf("/api/", basePath.length() + 7) > 0);
        headers(res, api);
        RequestInfo info = new RequestInfo(req.remoteAddress(), correlationId, uri, req.query());
        boolean local = isLocal(req);
        if (loopbackOnly() && !local) {
            res.json(403, "The SecureTest dashboard only accepts local connections (securetest.dashboard.bind-address=127.0.0.1).");
            return new Decision(false, null, info, res);
        }
        if (api && !rateLimit(req.remoteAddress())) {
            res.header("Retry-After", "1");
            res.json(429, "Too many requests");
            return new Decision(false, null, info, res);
        }
        if (uri.equals(basePath + "/api/v1/integrations/events")) { // machine-to-machine, token checked by the controller
            return new Decision(true, null, info, res);
        }
        String provider = provider();
        if ("oidc".equals(provider) && oidc != null) {
            if (uri.equals(basePath + "/oidc/login")) { oidc.startLogin(req, res, basePath); return new Decision(false, null, info, res); }
            if (uri.equals(basePath + "/oidc/logout")) { oidc.logout(req, res, basePath); return new Decision(false, null, info, res); }
            if (uri.equals(basePath + "/oidc/callback")) {
                OidcAuthenticator.LoginResult r = oidc.callback(req, res, basePath);
                if (audit != null) {
                    audit.record(r.user() == null ? "anonymous" : r.user(), req.remoteAddress(), "auth.login", "oidc",
                            r.success() ? "OK" : "DENIED", Map.of("detail", r.message()));
                }
                return new Decision(false, null, info, res);
            }
        }
        String fleetToken = req.header(FleetService.TOKEN_HEADER);
        if (fleetToken != null) { // another SecureTest service (the "All services" view), acting for its signed-in user
            SecureTestPrincipal fleet = fleetPrincipal(req, fleetToken);
            if (fleet == null) {
                if (audit != null) audit.record("fleet", req.remoteAddress(), "auth.fleet", "dashboard", "DENIED", Map.of());
                res.json(401, "Invalid fleet token");
                return new Decision(false, null, info, res);
            }
            // no CSRF check: browsers cannot send this header cross-site, and the caller proved it holds the shared secret
            return new Decision(true, fleet.withCorrelationId(correlationId), info, res);
        }
        SecureTestPrincipal principal = authenticate(req, local, provider);
        if (principal == null) {
            if ("oidc".equals(provider) && oidc != null && !api) {
                res.redirect(req.contextPath() + basePath + "/oidc/login");
            } else {
                if (usesBasic(provider)) res.header("WWW-Authenticate", "Basic realm=\"SecureTest\", charset=\"UTF-8\"");
                res.json(401, "Authentication required");
            }
            return new Decision(false, null, info, res);
        }
        if (api && !isSafe(req.method())) {
            if (!"1".equals(req.header(CSRF_HEADER))) {
                res.json(403, "Missing " + CSRF_HEADER + " header (CSRF protection)");
                return new Decision(false, null, info, res);
            }
            String origin = req.header("Origin");
            if (origin != null && !sameOrigin(origin, req)) {
                res.json(403, "Cross-origin request rejected");
                return new Decision(false, null, info, res);
            }
        }
        return new Decision(true, principal.withCorrelationId(correlationId), info, res);
    }

    // ------------------------------------------------------------------ authentication

    public String provider() {
        SecureTestProperties.Authentication auth = props.getDashboard().getAuthentication();
        if (!auth.isEnabled()) return "none";
        return auth.getProvider() == null ? "auto" : auth.getProvider().toLowerCase(Locale.ROOT);
    }

    private static boolean usesBasic(String provider) {
        return provider.equals("auto") || provider.equals("basic");
    }

    /** Generated admin sign-in is offered in auto/basic mode when no users are configured. */
    public boolean generatedAdminActive() {
        return usesBasic(provider()) && props.getDashboard().getAuthentication().getUsers().isEmpty() && initialAdmin != null;
    }

    private SecureTestPrincipal authenticate(GateRequest req, boolean local, String provider) {
        return switch (provider) {
            // explicitly disabled: only acceptable for local, non-production use (warned at startup)
            case "none" -> local && !productionLike.getAsBoolean() ? new SecureTestPrincipal("anonymous-local", EnumSet.of(Role.ADMIN), "none", req.remoteAddress()) : null;
            case "local-dev" -> local ? new SecureTestPrincipal("local-developer", EnumSet.of(Role.ADMIN), "local-dev", req.remoteAddress()) : null;
            case "basic" -> basic(req);
            case "container" -> container(req);
            case "oidc" -> oidc == null ? null : oidc.principal(req);
            default -> { // auto
                if (local && !productionLike.getAsBoolean()) {
                    yield new SecureTestPrincipal("local-developer", EnumSet.of(Role.ADMIN), "local-dev", req.remoteAddress());
                }
                yield basic(req);
            }
        };
    }

    /** Trusts a call from another service of the same system when it presents the shared fleet token. */
    private SecureTestPrincipal fleetPrincipal(GateRequest req, String presented) {
        String expected = secrets.resolve(props.getFleet().getTokenRef());
        if (expected == null || expected.isBlank()) return null;
        if (!MessageDigest.isEqual(expected.trim().getBytes(StandardCharsets.UTF_8), presented.trim().getBytes(StandardCharsets.UTF_8))) return null;
        String user = req.header(FleetService.USER_HEADER);
        user = user == null || !user.matches("[A-Za-z0-9_.@+-]{1,128}") ? "fleet" : user;
        EnumSet<Role> roles = EnumSet.noneOf(Role.class);
        String rh = req.header(FleetService.ROLES_HEADER);
        if (rh != null) {
            for (String r : rh.split(",")) {
                try {
                    roles.add(Role.valueOf(r.trim().toUpperCase(Locale.ROOT)));
                } catch (IllegalArgumentException ignored) {
                    // unknown role names are dropped
                }
            }
        }
        if (roles.isEmpty()) roles.add(Role.VIEWER);
        String via = req.header(FleetService.VIA_HEADER);
        via = via == null || !via.matches("[A-Za-z0-9_.-]{1,64}") ? "fleet" : "fleet:" + via;
        return new SecureTestPrincipal(user, roles, via, req.remoteAddress());
    }

    private SecureTestPrincipal basic(GateRequest req) {
        String h = req.header("Authorization");
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
        if (!req.secure() && !warnedPlainHttp && !isLocal(req)) {
            warnedPlainHttp = true;
            log.warn("SecureTest: dashboard credentials are being sent over plain HTTP from {}. Serve the application over HTTPS.", req.remoteAddress());
        }
        for (SecureTestProperties.User u : props.getDashboard().getAuthentication().getUsers()) {
            if (u.getUsername() != null && u.getUsername().equals(user) && passwordMatches(u.getPassword(), pass)) {
                Set<Role> roles = EnumSet.noneOf(Role.class);
                for (String r : u.getRoles()) {
                    try { roles.add(Role.parse(r)); } catch (IllegalArgumentException ignored) { /* unknown role */ }
                }
                return new SecureTestPrincipal(user, roles, "basic", req.remoteAddress());
            }
        }
        if (generatedAdminActive() && initialAdmin.matches(user, pass)) {
            return new SecureTestPrincipal(InitialAdminCredential.USERNAME, EnumSet.of(Role.ADMIN), "basic", req.remoteAddress());
        }
        log.warn("SecureTest: failed dashboard login for user '{}' from {}", user.replaceAll("[\\r\\n]", ""), req.remoteAddress());
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
        } else if (Redactor.isReference(configured)) {
            expected = secrets.resolve(configured);
            actual = supplied;
        } else {
            expected = configured.startsWith("{noop}") ? configured.substring(6) : configured;
            actual = supplied;
        }
        return expected != null && MessageDigest.isEqual(expected.getBytes(StandardCharsets.UTF_8), actual.getBytes(StandardCharsets.UTF_8));
    }

    private SecureTestPrincipal container(GateRequest req) {
        if (req.userName() == null) return null;
        Set<Role> roles = EnumSet.noneOf(Role.class);
        for (Role r : Role.values()) {
            if (req.isUserInRole("SECURETEST_" + r.name())) roles.add(r);
        }
        props.getDashboard().getAuthentication().getRoleMapping().forEach((hostRole, stRole) -> {
            if (req.isUserInRole(hostRole)) {
                try { roles.add(Role.parse(stRole)); } catch (IllegalArgumentException ignored) { /* bad mapping */ }
            }
        });
        if (roles.isEmpty()) return null;
        return new SecureTestPrincipal(req.userName(), roles, "container", req.remoteAddress());
    }

    // ------------------------------------------------------------------ helpers

    /** Explicit loopback-only mode: bind-address 127.0.0.1 / ::1 / localhost. Default ("auto") allows signed-in remote access. */
    public boolean loopbackOnly() {
        String b = props.getDashboard().getBindAddress();
        return b != null && (b.equals("127.0.0.1") || b.equals("::1") || b.equalsIgnoreCase("localhost") || b.equalsIgnoreCase("loopback"));
    }

    static boolean isLocal(GateRequest req) {
        if (req.header("X-Forwarded-For") != null || req.header("Forwarded") != null || req.header("X-Real-IP") != null) return false;
        String addr = req.remoteAddress();
        if (addr == null) return false;
        try {
            return InetAddress.getByName(addr).isLoopbackAddress();
        } catch (Exception e) {
            return false;
        }
    }

    private boolean rateLimit(String client) {
        int limit = Math.max(1, props.getSecurity().getApiRateLimit());
        long now = System.nanoTime();
        if (buckets.size() > 10_000) buckets.clear();
        double[] b = buckets.computeIfAbsent(String.valueOf(client), k -> new double[] {limit * 3.0, now});
        synchronized (b) {
            double elapsed = (now - (long) b[1]) / 1e9;
            b[0] = Math.min(limit * 3.0, b[0] + elapsed * limit);
            b[1] = now;
            if (b[0] < 1) return false;
            b[0] -= 1;
            return true;
        }
    }

    private static void headers(GateResponse res, boolean api) {
        res.header("Content-Security-Policy", CSP);
        res.header("X-Content-Type-Options", "nosniff");
        res.header("X-Frame-Options", "DENY");
        res.header("Referrer-Policy", "no-referrer");
        res.header("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
        res.header("Cross-Origin-Opener-Policy", "same-origin");
        res.header("Cache-Control", api ? "no-store" : "no-cache");
    }

    private static boolean isSafe(String method) {
        return method.equals("GET") || method.equals("HEAD") || method.equals("OPTIONS");
    }

    private static boolean sameOrigin(String origin, GateRequest req) {
        try {
            URI o = URI.create(origin);
            int port = o.getPort() == -1 ? ("https".equals(o.getScheme()) ? 443 : 80) : o.getPort();
            String forwardedHost = req.header("X-Forwarded-Host");
            if (forwardedHost != null) return o.getHost() != null && forwardedHost.split(",")[0].trim().split(":")[0].equalsIgnoreCase(o.getHost());
            return o.getHost() != null && o.getHost().equalsIgnoreCase(req.serverName()) && port == req.serverPort();
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    private static String sanitize(String id) {
        return id != null && id.matches("[A-Za-z0-9._-]{1,100}") ? id : null;
    }
}
