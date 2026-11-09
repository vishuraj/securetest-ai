package com.securetest.autoconfigure.security;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.securetest.autoconfigure.SecureTestProperties;
import com.securetest.autoconfigure.security.Rbac.Role;
import com.securetest.autoconfigure.support.SecretResolver;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.math.BigInteger;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * OpenID Connect sign-in for the dashboard (SEC-001): authorization-code flow with PKCE (S256), state and nonce,
 * ID-token signature verification against the provider's JWKS (RS256/384/512, ES256), issuer/audience/expiry checks,
 * roles from a configurable claim, and opaque server-side sessions in an HttpOnly SameSite cookie.
 */
public class OidcAuthenticator {

    public static final String COOKIE = "SECURETEST_SESSION";
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Duration SKEW = Duration.ofSeconds(60);

    record Pending(String nonce, String verifier, String next, Instant created) { }

    record Session(String name, Set<Role> roles, Instant expires, String idToken) { }

    /** Outcome of the callback, for audit. */
    public record LoginResult(boolean success, String user, String message) { }

    private final SecureTestProperties.Oidc cfg;
    private final Map<String, String> roleMapping;
    private final SecretResolver secrets;
    private final ObjectMapper json = new ObjectMapper();
    private final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).followRedirects(HttpClient.Redirect.NEVER).build();
    private final Map<String, Pending> pending = new ConcurrentHashMap<>();
    private final Map<String, Session> sessions = new ConcurrentHashMap<>();
    private final Map<String, PublicKey> keys = new ConcurrentHashMap<>();
    private volatile JsonNode discovery;
    private volatile Instant discoveredAt = Instant.EPOCH;

    public OidcAuthenticator(SecureTestProperties.Oidc cfg, Map<String, String> roleMapping, SecretResolver secrets) {
        this.cfg = cfg;
        this.roleMapping = roleMapping;
        this.secrets = secrets;
    }

    // ------------------------------------------------------------------ session lookup

    public SecureTestPrincipal principal(HttpServletRequest req) {
        String id = cookie(req);
        if (id == null) return null;
        Session s = sessions.get(id);
        if (s == null) return null;
        if (Instant.now().isAfter(s.expires())) {
            sessions.remove(id);
            return null;
        }
        return new SecureTestPrincipal(s.name(), s.roles(), "oidc", req.getRemoteAddr());
    }

    private static String cookie(HttpServletRequest req) {
        if (req.getCookies() == null) return null;
        for (Cookie c : req.getCookies()) if (COOKIE.equals(c.getName())) return c.getValue();
        return null;
    }

    // ------------------------------------------------------------------ login

    public void startLogin(HttpServletRequest req, HttpServletResponse res, String basePath) throws IOException {
        JsonNode d = discovery();
        purgePending();
        String state = random(24);
        String nonce = random(24);
        String verifier = random(48);
        String next = req.getParameter("next");
        if (next == null || !next.startsWith("#") && !next.startsWith("/")) next = "";
        pending.put(state, new Pending(nonce, verifier, next, Instant.now()));
        String url = d.path("authorization_endpoint").asText()
                + (d.path("authorization_endpoint").asText().contains("?") ? "&" : "?")
                + "response_type=code"
                + "&client_id=" + enc(cfg.getClientId())
                + "&redirect_uri=" + enc(redirectUri(req, basePath))
                + "&scope=" + enc(cfg.getScopes())
                + "&state=" + enc(state)
                + "&nonce=" + enc(nonce)
                + "&code_challenge=" + enc(b64(sha256(verifier.getBytes(StandardCharsets.US_ASCII))))
                + "&code_challenge_method=S256";
        res.sendRedirect(url);
    }

    public LoginResult callback(HttpServletRequest req, HttpServletResponse res, String basePath) throws IOException {
        String state = req.getParameter("state");
        Pending p = state == null ? null : pending.remove(state);
        if (p == null || p.created().isBefore(Instant.now().minus(Duration.ofMinutes(10)))) {
            return fail(res, 400, null, "Sign-in expired or the state parameter is invalid. Start again.");
        }
        if (req.getParameter("error") != null) {
            return fail(res, 401, null, "Identity provider returned: " + req.getParameter("error"));
        }
        String code = req.getParameter("code");
        if (code == null) return fail(res, 400, null, "Missing authorization code.");
        JsonNode d = discovery();
        StringBuilder form = new StringBuilder("grant_type=authorization_code")
                .append("&code=").append(enc(code))
                .append("&redirect_uri=").append(enc(redirectUri(req, basePath)))
                .append("&client_id=").append(enc(cfg.getClientId()))
                .append("&code_verifier=").append(enc(p.verifier()));
        String secret = secrets.resolve(cfg.getClientSecretRef());
        if (secret != null && !secret.isBlank()) form.append("&client_secret=").append(enc(secret));
        JsonNode token;
        try {
            HttpResponse<String> r = http.send(HttpRequest.newBuilder(URI.create(d.path("token_endpoint").asText()))
                    .timeout(Duration.ofSeconds(10)).header("Content-Type", "application/x-www-form-urlencoded").header("Accept", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(form.toString())).build(), HttpResponse.BodyHandlers.ofString());
            if (r.statusCode() != 200) return fail(res, 401, null, "Token exchange failed (HTTP " + r.statusCode() + ").");
            token = json.readTree(r.body());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return fail(res, 503, null, "Interrupted");
        }
        String idToken = token.path("id_token").asText(null);
        if (idToken == null) return fail(res, 401, null, "No id_token in the token response.");
        JsonNode claims;
        try {
            claims = verify(idToken, p.nonce());
        } catch (SecurityException e) {
            return fail(res, 401, null, "ID token rejected: " + e.getMessage());
        }
        String user = claims.path(cfg.getUsernameClaim()).asText(claims.path("email").asText(claims.path("sub").asText()));
        Set<Role> roles = roles(claims);
        if (roles.isEmpty()) return fail(res, 403, user, "Signed in as " + user + ", but no SecureTest role is mapped for this account.");
        String sid = random(32);
        Instant expires = Instant.now().plus(cfg.getSessionTimeout());
        sessions.put(sid, new Session(user, roles, expires, idToken));
        Cookie c = new Cookie(COOKIE, sid);
        c.setHttpOnly(true);
        c.setSecure(req.isSecure());
        c.setPath(cookiePath(req, basePath));
        c.setMaxAge((int) cfg.getSessionTimeout().toSeconds());
        c.setAttribute("SameSite", "Lax");
        res.addCookie(c);
        res.sendRedirect(req.getContextPath() + basePath + "/" + p.next());
        return new LoginResult(true, user, "roles " + roles);
    }

    public void logout(HttpServletRequest req, HttpServletResponse res, String basePath) throws IOException {
        String id = cookie(req);
        Session s = id == null ? null : sessions.remove(id);
        Cookie c = new Cookie(COOKIE, "");
        c.setPath(cookiePath(req, basePath));
        c.setMaxAge(0);
        c.setHttpOnly(true);
        res.addCookie(c);
        String end = discoverySafe().path("end_session_endpoint").asText(null);
        if (end != null && s != null) {
            res.sendRedirect(end + (end.contains("?") ? "&" : "?") + "id_token_hint=" + enc(s.idToken())
                    + "&post_logout_redirect_uri=" + enc(origin(req) + req.getContextPath() + basePath + "/"));
        } else {
            res.sendRedirect(req.getContextPath() + basePath + "/");
        }
    }

    private LoginResult fail(HttpServletResponse res, int status, String user, String message) throws IOException {
        res.setStatus(status);
        res.setContentType("text/html;charset=UTF-8");
        String safe = message.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
        res.getWriter().write("<!doctype html><title>SecureTest sign-in</title><body style=\"font-family:system-ui;padding:40px\">"
                + "<h1>Sign-in failed</h1><p>" + safe + "</p><p><a href=\"oidc/login\">Try again</a></p></body>");
        return new LoginResult(false, user, message);
    }

    // ------------------------------------------------------------------ token verification

    JsonNode verify(String jwt, String expectedNonce) {
        String[] parts = jwt.split("\\.");
        if (parts.length != 3) throw new SecurityException("malformed JWT");
        JsonNode header;
        JsonNode claims;
        try {
            header = json.readTree(Base64.getUrlDecoder().decode(parts[0]));
            claims = json.readTree(Base64.getUrlDecoder().decode(parts[1]));
        } catch (IOException | IllegalArgumentException e) {
            throw new SecurityException("undecodable JWT");
        }
        String alg = header.path("alg").asText();
        String javaAlg = switch (alg) {
            case "RS256" -> "SHA256withRSA";
            case "RS384" -> "SHA384withRSA";
            case "RS512" -> "SHA512withRSA";
            case "ES256" -> "SHA256withECDSA";
            default -> throw new SecurityException("unsupported alg " + alg);
        };
        PublicKey key = key(header.path("kid").asText(""));
        try {
            Signature sig = Signature.getInstance(javaAlg);
            sig.initVerify(key);
            sig.update((parts[0] + "." + parts[1]).getBytes(StandardCharsets.US_ASCII));
            byte[] s = Base64.getUrlDecoder().decode(parts[2]);
            if (alg.startsWith("ES")) s = joseToDer(s);
            if (!sig.verify(s)) throw new SecurityException("bad signature");
        } catch (SecurityException e) {
            throw e;
        } catch (Exception e) {
            throw new SecurityException("signature check failed: " + e.getMessage());
        }
        Instant now = Instant.now();
        String issuer = discoverySafe().path("issuer").asText(cfg.getIssuerUri());
        if (!issuer.equals(claims.path("iss").asText())) throw new SecurityException("unexpected issuer");
        JsonNode aud = claims.path("aud");
        boolean audOk = aud.isArray() ? contains(aud, cfg.getClientId()) : cfg.getClientId().equals(aud.asText());
        if (!audOk) throw new SecurityException("token not issued for this client");
        if (!claims.has("exp") || now.minus(SKEW).isAfter(Instant.ofEpochSecond(claims.path("exp").asLong()))) throw new SecurityException("token expired");
        if (claims.has("nbf") && now.plus(SKEW).isBefore(Instant.ofEpochSecond(claims.path("nbf").asLong()))) throw new SecurityException("token not yet valid");
        if (expectedNonce != null && !expectedNonce.equals(claims.path("nonce").asText())) throw new SecurityException("nonce mismatch");
        return claims;
    }

    private static boolean contains(JsonNode arr, String v) {
        for (JsonNode n : arr) if (v.equals(n.asText())) return true;
        return false;
    }

    private PublicKey key(String kid) {
        PublicKey k = keys.get(kid);
        if (k != null) return k;
        loadJwks();
        k = keys.get(kid);
        if (k == null && keys.size() == 1 && kid.isEmpty()) k = keys.values().iterator().next();
        if (k == null) throw new SecurityException("unknown signing key " + kid);
        return k;
    }

    private synchronized void loadJwks() {
        try {
            HttpResponse<String> r = http.send(HttpRequest.newBuilder(URI.create(discovery().path("jwks_uri").asText())).timeout(Duration.ofSeconds(10)).GET().build(),
                    HttpResponse.BodyHandlers.ofString());
            for (JsonNode k : json.readTree(r.body()).path("keys")) {
                if (k.has("use") && !"sig".equals(k.path("use").asText())) continue;
                String kid = k.path("kid").asText("");
                switch (k.path("kty").asText()) {
                    case "RSA" -> keys.put(kid, KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(
                            new BigInteger(1, Base64.getUrlDecoder().decode(k.path("n").asText())),
                            new BigInteger(1, Base64.getUrlDecoder().decode(k.path("e").asText())))));
                    case "EC" -> {
                        if (!"P-256".equals(k.path("crv").asText())) continue;
                        AlgorithmParameters params = AlgorithmParameters.getInstance("EC");
                        params.init(new ECGenParameterSpec("secp256r1"));
                        ECParameterSpec spec = params.getParameterSpec(ECParameterSpec.class);
                        ECPoint point = new ECPoint(new BigInteger(1, Base64.getUrlDecoder().decode(k.path("x").asText())),
                                new BigInteger(1, Base64.getUrlDecoder().decode(k.path("y").asText())));
                        keys.put(kid, KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(point, spec)));
                    }
                    default -> { }
                }
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } catch (Exception e) {
            throw new SecurityException("cannot load JWKS: " + e.getMessage());
        }
    }

    private static byte[] joseToDer(byte[] rs) {
        int half = rs.length / 2;
        byte[] r = trim(java.util.Arrays.copyOfRange(rs, 0, half));
        byte[] s = trim(java.util.Arrays.copyOfRange(rs, half, rs.length));
        int len = 2 + r.length + 2 + s.length;
        byte[] der = new byte[2 + len];
        der[0] = 0x30;
        der[1] = (byte) len;
        der[2] = 0x02;
        der[3] = (byte) r.length;
        System.arraycopy(r, 0, der, 4, r.length);
        der[4 + r.length] = 0x02;
        der[5 + r.length] = (byte) s.length;
        System.arraycopy(s, 0, der, 6 + r.length, s.length);
        return der;
    }

    private static byte[] trim(byte[] v) {
        int i = 0;
        while (i < v.length - 1 && v[i] == 0 && (v[i + 1] & 0x80) == 0) i++;
        byte[] t = java.util.Arrays.copyOfRange(v, i, v.length);
        if ((t[0] & 0x80) != 0) {
            byte[] p = new byte[t.length + 1];
            System.arraycopy(t, 0, p, 1, t.length);
            return p;
        }
        return t;
    }

    // ------------------------------------------------------------------ roles

    Set<Role> roles(JsonNode claims) {
        List<String> values = new ArrayList<>();
        JsonNode node = claims;
        for (String part : cfg.getRolesClaim().split("\\.")) node = node.path(part);
        if (node.isArray()) node.forEach(n -> values.add(n.asText()));
        else if (node.isTextual()) values.addAll(List.of(node.asText().split("[ ,]+")));
        Set<Role> roles = EnumSet.noneOf(Role.class);
        for (String v : values) {
            String mapped = roleMapping.get(v);
            if (mapped != null) {
                try { roles.add(Role.parse(mapped)); } catch (IllegalArgumentException ignored) { /* bad mapping */ }
            } else if (v.toUpperCase(Locale.ROOT).startsWith("SECURETEST_")) {
                try { roles.add(Role.parse(v)); } catch (IllegalArgumentException ignored) { /* not a role */ }
            }
        }
        if (roles.isEmpty() && cfg.getDefaultRole() != null && !cfg.getDefaultRole().isBlank()) roles.add(Role.parse(cfg.getDefaultRole()));
        return roles;
    }

    // ------------------------------------------------------------------ helpers

    private JsonNode discovery() throws IOException {
        if (discovery != null && discoveredAt.isAfter(Instant.now().minus(Duration.ofHours(1)))) return discovery;
        String url = cfg.getIssuerUri().replaceAll("/$", "") + "/.well-known/openid-configuration";
        try {
            HttpResponse<String> r = http.send(HttpRequest.newBuilder(URI.create(url)).timeout(Duration.ofSeconds(10)).GET().build(), HttpResponse.BodyHandlers.ofString());
            if (r.statusCode() != 200) throw new IOException("OIDC discovery returned HTTP " + r.statusCode());
            discovery = json.readTree(r.body());
            discoveredAt = Instant.now();
            return discovery;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("interrupted");
        }
    }

    private JsonNode discoverySafe() {
        try {
            return discovery();
        } catch (IOException e) {
            return json.createObjectNode();
        }
    }

    private String redirectUri(HttpServletRequest req, String basePath) {
        if (cfg.getRedirectUri() != null && !cfg.getRedirectUri().isBlank()) return cfg.getRedirectUri();
        return origin(req) + req.getContextPath() + basePath + "/oidc/callback";
    }

    private static String origin(HttpServletRequest req) {
        int port = req.getServerPort();
        boolean dflt = ("http".equals(req.getScheme()) && port == 80) || ("https".equals(req.getScheme()) && port == 443);
        return req.getScheme() + "://" + req.getServerName() + (dflt ? "" : ":" + port);
    }

    private static String cookiePath(HttpServletRequest req, String basePath) {
        return (req.getContextPath() == null ? "" : req.getContextPath()) + basePath;
    }

    private void purgePending() {
        Instant cutoff = Instant.now().minus(Duration.ofMinutes(10));
        pending.values().removeIf(p -> p.created().isBefore(cutoff));
        Instant now = Instant.now();
        sessions.values().removeIf(s -> now.isAfter(s.expires()));
        if (pending.size() > 10_000) pending.clear();
    }

    private static String random(int bytes) {
        byte[] b = new byte[bytes];
        RANDOM.nextBytes(b);
        return b64(b);
    }

    private static String b64(byte[] b) { return Base64.getUrlEncoder().withoutPadding().encodeToString(b); }

    private static byte[] sha256(byte[] b) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(b);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static String enc(String s) { return URLEncoder.encode(s == null ? "" : s, StandardCharsets.UTF_8); }

    public Map<String, Object> status() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("issuer", cfg.getIssuerUri());
        m.put("clientId", cfg.getClientId());
        m.put("activeSessions", sessions.size());
        return m;
    }
}
