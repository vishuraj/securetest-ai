package com.securetest.adapters.builtin;

import com.securetest.core.model.Enums.Confidence;
import com.securetest.core.model.Enums.FieldType;
import com.securetest.core.model.Finding;
import com.securetest.core.model.ModuleCatalog;
import com.securetest.core.model.Severity;
import com.securetest.core.spi.FieldSpec;
import com.securetest.core.spi.PreflightCheck;
import com.securetest.core.spi.ScanContext;
import com.securetest.core.spi.Scanner;
import com.securetest.core.spi.ScannerDescriptor;

import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import java.net.InetSocketAddress;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/** TLS / certificate posture for allowlisted hosts (SRS 5.9). Performs standard TLS handshakes only. */
public class TlsScanner implements Scanner {

    public static final String ID = "builtin-tls";

    @Override
    public ScannerDescriptor descriptor() {
        return ScannerDescriptor.builder(ID, ModuleCatalog.NETWORK_SECURITY, "TLS & certificate check")
                .purpose("Connects to each host:port with a normal TLS handshake and checks certificate trust, expiry, hostname match, "
                        + "key size, signature algorithm, negotiated protocol and cipher suite.")
                .access("One TLS handshake (plus a validation handshake) per allowlisted host.")
                .requiresTarget()
                .field(FieldSpec.required("hosts", "Hosts", FieldType.LIST, "", "Comma-separated host[:port] entries (default port 443). Each must be allowlisted."))
                .field(FieldSpec.number("expiryWarningDays", "Expiry warning (days)", 30, 1, 365, ""))
                .build();
    }

    @Override
    public List<PreflightCheck> preflight(ScanContext ctx) {
        List<PreflightCheck> out = new ArrayList<>();
        String hosts = ctx.option("hosts", "");
        if (hosts.isBlank()) out.add(PreflightCheck.error("Hosts", "At least one host is required."));
        for (String h : hosts.split(",")) {
            if (h.isBlank()) continue;
            String host = h.trim().split(":")[0];
            out.add(ctx.targets().isAllowedHost(host) ? PreflightCheck.ok("Allowlist " + host, "authorized")
                    : PreflightCheck.error("Allowlist " + host, "not on the target allowlist"));
        }
        return out;
    }

    @Override
    public void scan(ScanContext ctx) throws Exception {
        List<Map<String, Object>> rows = new ArrayList<>();
        String[] entries = ctx.option("hosts", "").split(",");
        int i = 0;
        for (String e : entries) {
            ctx.checkCancelled();
            if (e.isBlank()) continue;
            String[] hp = e.trim().split(":");
            String host = ctx.targets().requireAllowedHost(hp[0]);
            int port = hp.length > 1 ? Integer.parseInt(hp[1]) : 443;
            rows.add(check(ctx, host, port));
            ctx.progress(100 * ++i / entries.length, "Checked " + host + ":" + port);
        }
        ctx.putResult("tlsHosts", rows);
    }

    private Map<String, Object> check(ScanContext ctx, String host, int port) throws Exception {
        Map<String, Object> row = new LinkedHashMap<>();
        String asset = host + ":" + port;
        row.put("host", asset);
        // 1. inspect with a permissive trust manager to read the chain even if invalid
        SSLContext inspect = SSLContext.getInstance("TLS");
        inspect.init(null, new TrustManager[] {new X509TrustManager() {
            public void checkClientTrusted(X509Certificate[] c, String a) { }
            public void checkServerTrusted(X509Certificate[] c, String a) { }
            public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
        }}, null);
        X509Certificate leaf;
        String protocol;
        String cipher;
        try (SSLSocket s = (SSLSocket) inspect.getSocketFactory().createSocket()) {
            s.connect(new InetSocketAddress(host, port), 5000);
            s.setSoTimeout(5000);
            SSLParameters params = s.getSSLParameters();
            if (!host.matches("[0-9.:]+")) params.setServerNames(List.of(new SNIHostName(host)));
            s.setSSLParameters(params);
            s.startHandshake();
            Certificate[] chain = s.getSession().getPeerCertificates();
            leaf = (X509Certificate) chain[0];
            protocol = s.getSession().getProtocol();
            cipher = s.getSession().getCipherSuite();
        } catch (Exception ex) {
            row.put("error", ex.getMessage());
            ctx.report(f(asset, "TLS-HANDSHAKE", "TLS handshake failed on " + asset, Severity.MEDIUM)
                    .description("Could not complete a TLS handshake: " + ex.getMessage())
                    .remediation("Verify that the port serves TLS and supports TLS 1.2 or 1.3."));
            return row;
        }
        row.put("protocol", protocol);
        row.put("cipher", cipher);
        row.put("subject", leaf.getSubjectX500Principal().getName());
        row.put("issuer", leaf.getIssuerX500Principal().getName());
        row.put("notAfter", leaf.getNotAfter().toInstant().toString());
        String evidence = "Subject: " + leaf.getSubjectX500Principal().getName() + "\nIssuer: " + leaf.getIssuerX500Principal().getName()
                + "\nValid until: " + leaf.getNotAfter().toInstant() + "\nProtocol: " + protocol + "\nCipher: " + cipher;

        // 2. trust validation with the JVM default trust store
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init((KeyStore) null);
        SSLContext strict = SSLContext.getInstance("TLS");
        strict.init(null, tmf.getTrustManagers(), null);
        try (SSLSocket s = (SSLSocket) strict.getSocketFactory().createSocket()) {
            s.connect(new InetSocketAddress(host, port), 5000);
            SSLParameters params = s.getSSLParameters();
            params.setEndpointIdentificationAlgorithm("HTTPS");
            if (!host.matches("[0-9.:]+")) params.setServerNames(List.of(new SNIHostName(host)));
            s.setSSLParameters(params);
            s.startHandshake();
            row.put("trusted", true);
        } catch (Exception ex) {
            row.put("trusted", false);
            boolean selfSigned = leaf.getSubjectX500Principal().equals(leaf.getIssuerX500Principal());
            boolean hostname = ex.getMessage() != null && ex.getMessage().toLowerCase(Locale.ROOT).contains("no subject alternative");
            ctx.report(f(asset, hostname ? "TLS-HOSTNAME" : "TLS-UNTRUSTED",
                    hostname ? "Certificate does not match host name " + host : (selfSigned ? "Self-signed certificate on " : "Untrusted certificate chain on ") + asset,
                    Severity.HIGH).evidence(evidence + "\nValidation error: " + ex.getMessage())
                    .description("Clients that validate certificates will reject the connection, and users may be trained to ignore warnings.")
                    .remediation("Install a certificate issued by a trusted CA whose SAN covers the host name, including the full intermediate chain."));
        }
        // 3. expiry
        long days = Duration.between(Instant.now(), leaf.getNotAfter().toInstant()).toDays();
        row.put("daysToExpiry", days);
        int warn = ctx.intOption("expiryWarningDays", 30, 1, 365);
        if (days < 0) {
            ctx.report(f(asset, "TLS-EXPIRED", "Certificate expired " + (-days) + " day(s) ago on " + asset, Severity.CRITICAL).evidence(evidence)
                    .description("Expired certificates break clients and indicate missing certificate lifecycle management.")
                    .remediation("Renew the certificate now and automate renewal (ACME / cert-manager)."));
        } else if (days < warn) {
            ctx.report(f(asset, "TLS-EXPIRING", "Certificate expires in " + days + " day(s) on " + asset, days < 14 ? Severity.HIGH : Severity.MEDIUM)
                    .evidence(evidence).description("The certificate will expire soon.").remediation("Renew and automate renewal."));
        }
        // 4. key & signature
        if (leaf.getPublicKey() instanceof RSAPublicKey rsa && rsa.getModulus().bitLength() < 2048) {
            ctx.report(f(asset, "TLS-WEAK-KEY", "Weak RSA key (" + rsa.getModulus().bitLength() + " bits) on " + asset, Severity.HIGH).evidence(evidence)
                    .description("RSA keys below 2048 bits are considered breakable.").remediation("Reissue with RSA 2048+ or ECDSA P-256."));
        }
        String sig = leaf.getSigAlgName().toUpperCase(Locale.ROOT);
        if (sig.contains("SHA1") || sig.contains("MD5")) {
            ctx.report(f(asset, "TLS-WEAK-SIG", "Weak certificate signature (" + leaf.getSigAlgName() + ") on " + asset, Severity.HIGH).evidence(evidence)
                    .description("SHA-1/MD5 signatures are collision-prone.").remediation("Reissue the certificate with SHA-256 or stronger."));
        }
        // 5. protocol & cipher
        if (protocol.equals("TLSv1") || protocol.equals("TLSv1.1") || protocol.startsWith("SSL")) {
            ctx.report(f(asset, "TLS-OLD-PROTOCOL", "Obsolete protocol " + protocol + " negotiated on " + asset, Severity.HIGH).evidence(evidence)
                    .description("TLS 1.0/1.1 are deprecated (RFC 8996).").remediation("Allow only TLS 1.2 and 1.3."));
        }
        String c = cipher.toUpperCase(Locale.ROOT);
        if (c.contains("_CBC_") || c.contains("3DES") || c.contains("RC4") || c.contains("NULL") || c.contains("EXPORT") || (c.contains("TLS_RSA_") && !c.contains("ECDHE"))) {
            ctx.report(f(asset, "TLS-WEAK-CIPHER", "Weak cipher suite preferred on " + asset + ": " + cipher, Severity.MEDIUM).evidence(evidence)
                    .description("The server prefers a cipher without forward secrecy or with legacy CBC/3DES/RC4 constructions.")
                    .remediation("Prefer ECDHE with AES-GCM or ChaCha20-Poly1305 suites; disable CBC, 3DES, RC4 and static RSA key exchange."));
        }
        return row;
    }

    private static Finding f(String asset, String rule, String title, Severity s) {
        return Finding.of(ModuleCatalog.NETWORK_SECURITY, ID, rule, title, s).asset(asset).category("TLS").confidence(Confidence.HIGH)
                .tags("OWASP-A02", "ASVS-9.1", "PCI-4.2", "CIS-TLS", "ISO27001-A.8.24");
    }
}
