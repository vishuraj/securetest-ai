package com.securetest.autoconfigure.disclosure;

import com.securetest.autoconfigure.SecureTestProperties;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

/** Builds /.well-known/security.txt (RFC 9116) for the vulnerability disclosure program. */
public final class SecurityTxt {

    public static final String PATH = "/.well-known/security.txt";
    private static final Instant STARTED = Instant.now().truncatedTo(ChronoUnit.DAYS);

    private SecurityTxt() { }

    /** The file, or null when the disclosure program is off. {@code origin} is scheme://host[:port] plus the context path. */
    public static String render(SecureTestProperties props, String origin) {
        SecureTestProperties.Disclosure d = props.getDisclosure();
        if (!d.isEnabled()) return null;
        StringBuilder sb = new StringBuilder();
        for (String c : d.getContact()) if (c != null && !c.isBlank()) sb.append("Contact: ").append(clean(c)).append('\n');
        if (d.isForm()) sb.append("Contact: ").append(origin).append(props.normalizedPath()).append("/disclose\n");
        sb.append("Expires: ").append(STARTED.plus(d.getExpiresAfter())).append('\n');
        if (d.getEncryption() != null) sb.append("Encryption: ").append(clean(d.getEncryption())).append('\n');
        if (d.getAcknowledgments() != null) sb.append("Acknowledgments: ").append(clean(d.getAcknowledgments())).append('\n');
        if (d.getPreferredLanguages() != null) sb.append("Preferred-Languages: ").append(clean(d.getPreferredLanguages())).append('\n');
        if (d.getPolicy() != null) sb.append("Policy: ").append(clean(d.getPolicy())).append('\n');
        sb.append("Canonical: ").append(origin).append(PATH).append('\n');
        return sb.toString();
    }

    private static String clean(String v) {
        return v.replaceAll("[\\r\\n]", " ").trim();
    }
}
