package com.example.demo;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.List;

/** Stand-in for an OIDC provider: an RSA key pair whose public key the control plane trusts. */
public final class TestJwt {

    private static final KeyPair KEYS;
    private static final Path PUBLIC_KEY;

    static {
        try {
            KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
            g.initialize(2048);
            KEYS = g.generateKeyPair();
            PUBLIC_KEY = Files.createTempFile("securetest-oidc", ".pem");
            PUBLIC_KEY.toFile().deleteOnExit();
            Files.writeString(PUBLIC_KEY, "-----BEGIN PUBLIC KEY-----\n"
                    + Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(KEYS.getPublic().getEncoded())
                    + "\n-----END PUBLIC KEY-----\n");
        } catch (Exception e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    private TestJwt() { }

    /** Value for {@code spring.security.oauth2.resourceserver.jwt.public-key-location}. */
    public static String publicKeyLocation() { return PUBLIC_KEY.toUri().toString(); }

    public static String token(String subject, String tenant, String... roles) {
        try {
            JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder()
                    .subject(subject)
                    .issuer("https://idp.test")
                    .issueTime(new Date())
                    .expirationTime(Date.from(Instant.now().plusSeconds(600)))
                    .claim("roles", List.of(roles));
            if (tenant != null) claims.claim("tenant", tenant);
            SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), claims.build());
            jwt.sign(new RSASSASigner(KEYS.getPrivate()));
            return jwt.serialize();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
