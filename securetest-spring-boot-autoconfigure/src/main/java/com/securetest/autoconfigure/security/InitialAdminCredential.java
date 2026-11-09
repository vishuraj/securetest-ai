package com.securetest.autoconfigure.security;

import com.securetest.core.util.Hashing;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Zero-configuration sign-in for remote and production access, like Spring Security's generated password:
 * user {@code admin} with a random password that is created once, stored in the SecureTest data directory
 * ({@code initial-admin-password}) and printed to the log at startup. Configure your own users, OIDC or container
 * authentication to replace it.
 */
public class InitialAdminCredential {

    private static final Logger log = LoggerFactory.getLogger("SecureTest");
    public static final String USERNAME = "admin";

    private final Path file;
    private final String passwordHash;
    private final String password;
    private boolean generatedNow;

    public InitialAdminCredential(Path storageDir) {
        this.file = storageDir.resolve("initial-admin-password");
        String pw = null;
        try {
            if (Files.isRegularFile(file)) {
                pw = Files.readString(file, StandardCharsets.UTF_8).trim();
            }
        } catch (IOException e) {
            log.debug("cannot read {}", file, e);
        }
        if (pw == null || pw.length() < 16) {
            byte[] b = new byte[18];
            new SecureRandom().nextBytes(b);
            pw = Base64.getUrlEncoder().withoutPadding().encodeToString(b);
            generatedNow = true;
            try {
                Files.createDirectories(storageDir);
                Files.writeString(file, pw + System.lineSeparator(), StandardCharsets.UTF_8);
                try {
                    Files.setPosixFilePermissions(file, PosixFilePermissions.fromString("rw-------"));
                } catch (UnsupportedOperationException | IOException ignored) {
                    // Windows: inherits the user-profile ACL
                }
            } catch (IOException e) {
                log.warn("SecureTest: could not store the generated admin password ({}); it changes on every restart.", e.getMessage());
            }
        }
        this.password = pw;
        this.passwordHash = Hashing.sha256(pw);
    }

    public boolean matches(String user, String supplied) {
        return USERNAME.equals(user) && supplied != null
                && MessageDigest.isEqual(passwordHash.getBytes(StandardCharsets.UTF_8), Hashing.sha256(supplied).getBytes(StandardCharsets.UTF_8));
    }

    /**
     * The password is printed only when it is first generated (afterwards only the file location is logged), so it does
     * not keep appearing in shipped production logs.
     */
    public void announce(String dashboardUrl) {
        if (!generatedNow) {
            log.info("SecureTest: remote/production sign-in is user '{}' with the password stored in {}", USERNAME, file.toAbsolutePath());
            return;
        }
        log.warn("""

                ----------------------------------------------------------------------
                SecureTest dashboard sign-in for remote / production access
                  URL:      {}
                  User:     {}
                  Password: {}
                  (stored in {}; set securetest.dashboard.authentication.users,
                   provider=oidc or provider=container to use your own sign-in)
                ----------------------------------------------------------------------""",
                dashboardUrl, USERNAME, password, file.toAbsolutePath());
    }

    public Path file() { return file; }
}
