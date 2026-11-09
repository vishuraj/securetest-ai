package com.securetest.autoconfigure;

import com.securetest.autoconfigure.security.OidcAuthenticator;
import com.securetest.autoconfigure.security.Rbac.Role;
import com.securetest.autoconfigure.security.SecureTestPrincipal;
import com.securetest.autoconfigure.support.SecretResolver;
import com.sun.net.httpserver.HttpServer;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.mock.web.MockHttpServletRequest;
import com.securetest.autoconfigure.security.GateResponse;
import com.securetest.autoconfigure.servlet.ServletGateRequest;

import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

class OidcAuthenticatorTest {

    private HttpServer idp;
    private KeyPair keys;
    private String issuer;
    private final AtomicReference<String> nonce = new AtomicReference<>();
    private final AtomicReference<String> verifierSeen = new AtomicReference<>();
    private volatile String audience = "securetest";

    private static String b64(byte[] b) { return Base64.getUrlEncoder().withoutPadding().encodeToString(b); }

    private String sign(String payload) throws Exception {
        String h = b64("{\"alg\":\"RS256\",\"kid\":\"k1\"}".getBytes(StandardCharsets.UTF_8));
        String p = b64(payload.getBytes(StandardCharsets.UTF_8));
        Signature s = Signature.getInstance("SHA256withRSA");
        s.initSign(keys.getPrivate());
        s.update((h + "." + p).getBytes(StandardCharsets.US_ASCII));
        return h + "." + p + "." + b64(s.sign());
    }

    @BeforeEach
    void start() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(2048);
        keys = g.generateKeyPair();
        idp = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        issuer = "http://127.0.0.1:" + idp.getAddress().getPort();
        idp.createContext("/.well-known/openid-configuration", ex -> respond(ex, "{\"issuer\":\"" + issuer + "\",\"authorization_endpoint\":\"" + issuer
                + "/auth\",\"token_endpoint\":\"" + issuer + "/token\",\"jwks_uri\":\"" + issuer + "/jwks\"}"));
        idp.createContext("/jwks", ex -> {
            RSAPublicKey k = (RSAPublicKey) keys.getPublic();
            respond(ex, "{\"keys\":[{\"kty\":\"RSA\",\"kid\":\"k1\",\"use\":\"sig\",\"n\":\"" + b64(unsigned(k.getModulus().toByteArray()))
                    + "\",\"e\":\"" + b64(k.getPublicExponent().toByteArray()) + "\"}]}");
        });
        idp.createContext("/token", ex -> {
            String form = new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            for (String kv : form.split("&")) if (kv.startsWith("code_verifier=")) verifierSeen.set(kv.substring(14));
            long exp = Instant.now().plusSeconds(300).getEpochSecond();
            try {
                String idToken = sign("{\"iss\":\"" + issuer + "\",\"aud\":\"" + audience + "\",\"sub\":\"u1\",\"preferred_username\":\"alice\",\"exp\":" + exp
                        + ",\"nonce\":\"" + nonce.get() + "\",\"realm_access\":{\"roles\":[\"sec-team\",\"other\"]}}");
                respond(ex, "{\"id_token\":\"" + idToken + "\",\"access_token\":\"x\",\"token_type\":\"Bearer\"}");
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
        idp.start();
    }

    private static byte[] unsigned(byte[] b) { return b[0] == 0 ? java.util.Arrays.copyOfRange(b, 1, b.length) : b; }

    private static void respond(com.sun.net.httpserver.HttpExchange ex, String body) throws java.io.IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().add("Content-Type", "application/json");
        ex.sendResponseHeaders(200, bytes.length);
        ex.getResponseBody().write(bytes);
        ex.close();
    }

    @AfterEach
    void stop() { idp.stop(0); }

    private OidcAuthenticator authenticator() {
        SecureTestProperties.Oidc cfg = new SecureTestProperties.Oidc();
        cfg.setIssuerUri(issuer);
        cfg.setClientId("securetest");
        cfg.setRolesClaim("realm_access.roles");
        return new OidcAuthenticator(cfg, Map.of("sec-team", "SECURITY"), new SecretResolver(new MockEnvironment(), null));
    }

    private static Map<String, String> query(String url) {
        Map<String, String> m = new HashMap<>();
        for (String kv : URI.create(url).getRawQuery().split("&")) {
            String[] p = kv.split("=", 2);
            m.put(p[0], URLDecoder.decode(p[1], StandardCharsets.UTF_8));
        }
        return m;
    }

    @Test
    void fullAuthorizationCodeFlowWithPkce() throws Exception {
        OidcAuthenticator oidc = authenticator();
        GateResponse redirect = new GateResponse();
        oidc.startLogin(new ServletGateRequest(new MockHttpServletRequest("GET", "/securetest/oidc/login")), redirect, "/securetest");
        Map<String, String> q = query(redirect.headers().get("Location"));
        assertThat(redirect.headers().get("Location")).startsWith(issuer + "/auth?");
        assertThat(q).containsEntry("code_challenge_method", "S256").containsEntry("client_id", "securetest").containsKeys("state", "nonce");
        nonce.set(q.get("nonce"));

        MockHttpServletRequest cb = new MockHttpServletRequest("GET", "/securetest/oidc/callback");
        cb.setParameter("state", q.get("state"));
        cb.setParameter("code", "abc");
        GateResponse res = new GateResponse();
        OidcAuthenticator.LoginResult r = oidc.callback(new ServletGateRequest(cb), res, "/securetest");
        assertThat(r.success()).as(r.message()).isTrue();
        assertThat(verifierSeen.get()).isNotBlank();
        assertThat(res.cookies()).hasSize(1);
        String setCookie = res.cookies().get(0);
        assertThat(setCookie).startsWith(OidcAuthenticator.COOKIE + "=").contains("HttpOnly").contains("SameSite=Lax");
        Cookie session = new Cookie(OidcAuthenticator.COOKIE, setCookie.substring(setCookie.indexOf('=') + 1, setCookie.indexOf(';')));

        MockHttpServletRequest next = new MockHttpServletRequest("GET", "/securetest/api/v1/me");
        next.setCookies(session);
        SecureTestPrincipal p = oidc.principal(new ServletGateRequest(next));
        assertThat(p.name()).isEqualTo("alice");
        assertThat(p.roles()).containsExactly(Role.SECURITY);

        // state is single-use
        GateResponse replay = new GateResponse();
        assertThat(oidc.callback(new ServletGateRequest(cb), replay, "/securetest").success()).isFalse();
        assertThat(replay.status()).isEqualTo(400);
    }

    @Test
    void rejectsWrongAudienceAndUnmappedUsers() throws Exception {
        OidcAuthenticator oidc = authenticator();
        GateResponse redirect = new GateResponse();
        oidc.startLogin(new ServletGateRequest(new MockHttpServletRequest("GET", "/securetest/oidc/login")), redirect, "/securetest");
        Map<String, String> q = query(redirect.headers().get("Location"));
        nonce.set(q.get("nonce"));
        audience = "some-other-client";
        MockHttpServletRequest cb = new MockHttpServletRequest("GET", "/securetest/oidc/callback");
        cb.setParameter("state", q.get("state"));
        cb.setParameter("code", "abc");
        GateResponse res = new GateResponse();
        OidcAuthenticator.LoginResult r = oidc.callback(new ServletGateRequest(cb), res, "/securetest");
        assertThat(r.success()).isFalse();
        assertThat(r.message()).contains("not issued for this client");
        assertThat(res.cookies()).isEmpty();
    }

    @Test
    void rejectsTamperedSignature() throws Exception {
        OidcAuthenticator oidc = authenticator();
        String good = sign("{\"iss\":\"" + issuer + "\",\"aud\":\"securetest\",\"exp\":" + (Instant.now().getEpochSecond() + 60) + "}");
        String[] parts = good.split("\\.");
        String forged = parts[0] + "." + b64(("{\"iss\":\"" + issuer + "\",\"aud\":\"securetest\",\"exp\":9999999999,\"realm_access\":{\"roles\":[\"SECURETEST_ADMIN\"]}}")
                .getBytes(StandardCharsets.UTF_8)) + "." + parts[2];
        MockHttpServletRequest req = new MockHttpServletRequest();
        req.setCookies(new Cookie(OidcAuthenticator.COOKIE, "made-up-session"));
        assertThat(oidc.principal(new ServletGateRequest(req))).isNull();
        try {
            var m = OidcAuthenticator.class.getDeclaredMethod("verify", String.class, String.class);
            m.setAccessible(true);
            m.invoke(oidc, forged, null);
            throw new AssertionError("forged token accepted");
        } catch (java.lang.reflect.InvocationTargetException e) {
            assertThat(e.getCause()).isInstanceOf(SecurityException.class).hasMessageContaining("signature");
        }
    }
}
