package com.securetest.autoconfigure.asm;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.securetest.autoconfigure.service.NotificationService;
import com.securetest.core.model.Enums.Confidence;
import com.securetest.core.model.Finding;
import com.securetest.core.model.ModuleCatalog;
import com.securetest.core.model.Severity;
import com.securetest.core.spi.FieldSpec;
import com.securetest.core.spi.HttpProbe;
import com.securetest.core.spi.PreflightCheck;
import com.securetest.core.spi.ScanContext;
import com.securetest.core.spi.Scanner;
import com.securetest.core.spi.ScannerDescriptor;

import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.function.BooleanSupplier;
import java.util.regex.Pattern;

/**
 * Discovers and checks the hosts under registered domains: common subdomains (DNS), optionally certificate-transparency
 * logs (crt.sh), then for each live host its HTTP(S) answer, TLS certificate and exposed admin tools.
 */
public class AttackSurfaceScanner implements Scanner {

    public static final String ID = "attack-surface";

    private static final List<String> SMALL = List.of("www", "api", "app", "admin", "dev", "staging", "test", "beta", "portal", "auth",
            "login", "sso", "mail", "vpn", "cdn", "static", "assets", "status", "docs", "git");
    private static final List<String> MORE = List.of("qa", "uat", "demo", "sandbox", "internal", "intranet", "dashboard", "grafana",
            "kibana", "jenkins", "ci", "gitlab", "jira", "confluence", "prometheus", "monitor", "metrics", "db", "phpmyadmin", "backup",
            "old", "legacy", "m", "mobile", "shop", "pay", "files", "upload", "s3", "graphql", "gateway", "partner", "support", "help");
    private static final Set<String> SENSITIVE = Set.of("admin", "jenkins", "ci", "gitlab", "git", "grafana", "kibana", "prometheus",
            "phpmyadmin", "db", "backup", "internal", "intranet", "monitor", "metrics", "jira", "confluence");
    private static final Pattern VERSIONED_BANNER = Pattern.compile(".*/\\d+(\\.\\d+)+.*");

    private final AttackSurfaceService inventory;
    private final NotificationService notifications;
    private final BooleanSupplier externalIntelligenceAllowed;
    private final ObjectMapper json = new ObjectMapper();

    public AttackSurfaceScanner(AttackSurfaceService inventory, NotificationService notifications, BooleanSupplier externalIntelligenceAllowed) {
        this.inventory = inventory;
        this.notifications = notifications;
        this.externalIntelligenceAllowed = externalIntelligenceAllowed;
    }

    @Override
    public ScannerDescriptor descriptor() {
        return ScannerDescriptor.builder(ID, ModuleCatalog.ATTACK_SURFACE, "Attack surface discovery")
                .purpose("Finds the hosts under your registered domains (common subdomain names, optionally public certificate logs) and checks each "
                        + "live host: HTTPS availability, redirects, certificate expiry, version banners and exposed admin tools.")
                .access("DNS lookups, one HTTPS and one HTTP request and one TLS handshake per host under registered domains only. "
                        + "Certificate-log lookups call crt.sh and need securetest.security.allow-external-intelligence=true.")
                .field(FieldSpec.select("wordlist", "Subdomain names", "small", List.of("small", "large"), "small: 20 common names; large: 55"))
                .field(FieldSpec.flag("certificateLogs", "Search public certificate logs (crt.sh)", false, "Sends your domain names to crt.sh"))
                .field(FieldSpec.number("expiryWarningDays", "Certificate expiry warning (days)", 30, 1, 365, ""))
                .build();
    }

    @Override
    public List<PreflightCheck> preflight(ScanContext ctx) {
        List<PreflightCheck> out = new ArrayList<>();
        out.add(inventory.registered().isEmpty() ? PreflightCheck.error("Assets", "Register at least one domain or host on the Attack Surface page.")
                : PreflightCheck.ok("Assets", inventory.registered().size() + " registered"));
        if (Boolean.parseBoolean(ctx.option("certificateLogs", "false")) && !externalIntelligenceAllowed.getAsBoolean()) {
            out.add(PreflightCheck.error("Certificate logs", "Set securetest.security.allow-external-intelligence=true to query crt.sh."));
        }
        return out;
    }

    @Override
    public void scan(ScanContext ctx) throws Exception {
        int warnDays = Integer.parseInt(ctx.option("expiryWarningDays", "30"));
        boolean large = "large".equals(ctx.option("wordlist", "small"));
        boolean ct = Boolean.parseBoolean(ctx.option("certificateLogs", "false")) && externalIntelligenceAllowed.getAsBoolean();
        Set<String> candidates = new LinkedHashSet<>();
        Map<String, String> parentOf = new java.util.HashMap<>();
        for (AttackSurfaceService.Asset a : inventory.registered()) {
            candidates.add(a.host);
            if (!"DOMAIN".equals(a.kind)) continue;
            List<String> names = new ArrayList<>(SMALL);
            if (large) names.addAll(MORE);
            for (String n : names) {
                candidates.add(n + "." + a.host);
                parentOf.put(n + "." + a.host, a.host);
            }
            if (ct) for (String h : certificateLog(ctx, a.host)) { candidates.add(h); parentOf.put(h, a.host); }
        }
        ctx.log(candidates.size() + " candidate host(s)");
        int done = 0;
        int live = 0;
        for (String host : candidates) {
            if (ctx.cancelled()) return;
            ctx.progress(5 + 90 * done++ / Math.max(1, candidates.size()), host);
            if (!inventory.covers(host) || !ctx.targets().isAllowedHost(host)) continue;
            AttackSurfaceService.Asset seen = new AttackSurfaceService.Asset();
            seen.host = host;
            seen.kind = "HOST";
            seen.parent = parentOf.get(host);
            try {
                for (InetAddress ia : InetAddress.getAllByName(host)) seen.addresses.add(ia.getHostAddress());
                seen.resolves = !seen.addresses.isEmpty();
            } catch (UnknownHostException e) {
                seen.resolves = false;
            }
            boolean registered = seen.parent == null;
            if (!seen.resolves) {
                if (registered) {
                    ctx.report(finding("ASM-UNRESOLVED", "Registered host does not resolve: " + host, Severity.LOW, host)
                            .description("The registered host has no DNS record. If it still has a CNAME at your DNS provider, check it is not dangling (subdomain takeover).")
                            .remediation("Remove the asset, or fix its DNS record."));
                    inventory.observe(seen);
                }
                continue;
            }
            live++;
            check(ctx, seen, warnDays);
            boolean isNew = inventory.observe(seen);
            if (isNew) {
                ctx.report(finding("ASM-NEW-HOST", "New host found: " + host, Severity.INFO, host)
                        .description("Discovered under " + seen.parent + " (" + String.join(", ", seen.addresses) + "). Confirm it is yours and is meant to be reachable.")
                        .remediation("Add it to your asset register with an owner, or take it offline."));
                notifications.publish("asset.discovered", "New host under " + seen.parent + ": " + host, Map.of("host", host));
            }
        }
        ctx.putResult("liveHosts", live);
        ctx.putResult("checked", candidates.size());
        ctx.progress(100, "Done");
    }

    private void check(ScanContext ctx, AttackSurfaceService.Asset a, int warnDays) {
        String label = a.host.substring(0, a.host.indexOf('.') > 0 ? a.host.indexOf('.') : a.host.length());
        HttpProbe.HttpResult https = get(ctx, "https://" + a.host + "/");
        HttpProbe.HttpResult http = get(ctx, "http://" + a.host + "/");
        a.httpsStatus = https == null ? null : https.status();
        a.httpStatus = http == null ? null : http.status();
        HttpProbe.HttpResult any = https != null ? https : http;
        if (any != null) {
            List<String> server = any.headers().getOrDefault("server", any.headers().getOrDefault("Server", List.of()));
            a.server = server.isEmpty() ? null : server.get(0);
        }
        if (https != null) certificate(a);

        if (http != null && https == null && http.status() < 400) {
            ctx.report(finding("ASM-NO-HTTPS", "Served without HTTPS: " + a.host, Severity.MEDIUM, a.host)
                    .description("The host answers over plain HTTP (" + http.status() + ") and not over HTTPS.").remediation("Serve it over HTTPS and redirect HTTP."));
        } else if (http != null && https != null && http.status() >= 200 && http.status() < 300) {
            ctx.report(finding("ASM-NO-REDIRECT", "HTTP is not redirected to HTTPS: " + a.host, Severity.LOW, a.host)
                    .description("Plain HTTP returns " + http.status() + " instead of redirecting.").remediation("Redirect HTTP to HTTPS and enable HSTS."));
        }
        if (a.certificateExpires != null) {
            long days = Duration.between(Instant.now(), a.certificateExpires).toDays();
            if (days < 0) {
                ctx.report(finding("ASM-CERT-EXPIRED", "Certificate expired: " + a.host, Severity.CRITICAL, a.host)
                        .description("Expired " + (-days) + " day(s) ago (issuer: " + a.certificateIssuer + ").").remediation("Renew the certificate now."));
                notifications.publish("certificate.expiring", "Certificate expired on " + a.host, Map.of("host", a.host));
            } else if (days <= warnDays) {
                ctx.report(finding("ASM-CERT-EXPIRING", "Certificate expires in " + days + " day(s): " + a.host, days <= 7 ? Severity.HIGH : Severity.MEDIUM, a.host)
                        .description("Expires " + a.certificateExpires + " (issuer: " + a.certificateIssuer + ").").remediation("Renew it, or check automatic renewal."));
                notifications.publish("certificate.expiring", "Certificate on " + a.host + " expires in " + days + " day(s)", Map.of("host", a.host));
            }
        }
        if (a.server != null && VERSIONED_BANNER.matcher(a.server).matches()) {
            a.tags.add("version-banner");
            ctx.report(finding("ASM-VERSION-BANNER", "Server version disclosed: " + a.host, Severity.LOW, a.host)
                    .description("Server header: " + a.server).remediation("Remove version numbers from the Server header."));
        }
        if (SENSITIVE.contains(label.toLowerCase(Locale.ROOT)) && any != null && any.status() < 400) {
            a.tags.add("sensitive");
            ctx.report(finding("ASM-EXPOSED-TOOL", "Internal tool reachable from the internet: " + a.host, Severity.MEDIUM, a.host)
                    .description("A host named '" + label + "' answers " + any.status() + " without asking for credentials.")
                    .remediation("Put it behind a VPN or SSO, or restrict it by IP."));
        }
    }

    private static HttpProbe.HttpResult get(ScanContext ctx, String url) {
        try {
            return ctx.http().get(url);
        } catch (Exception e) {
            return null;
        }
    }

    /** Reads the presented certificate's expiry and issuer (trust is checked separately by the TLS scanner). */
    private static void certificate(AttackSurfaceService.Asset a) {
        try {
            SSLContext tls = SSLContext.getInstance("TLS");
            tls.init(null, new TrustManager[]{new X509TrustManager() {
                public void checkClientTrusted(X509Certificate[] c, String t) { }
                public void checkServerTrusted(X509Certificate[] c, String t) { }
                public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
            }}, null);
            try (SSLSocket s = (SSLSocket) tls.getSocketFactory().createSocket()) {
                s.connect(new InetSocketAddress(a.host, 443), 3000);
                s.setSoTimeout(3000);
                SSLParameters p = s.getSSLParameters();
                p.setServerNames(List.of(new SNIHostName(a.host)));
                s.setSSLParameters(p);
                s.startHandshake();
                if (s.getSession().getPeerCertificates()[0] instanceof X509Certificate c) {
                    a.certificateExpires = c.getNotAfter().toInstant();
                    a.certificateIssuer = c.getIssuerX500Principal().getName();
                }
            }
        } catch (Exception ignored) {
            // no TLS or handshake failed: reported by the HTTPS check
        }
    }

    private List<String> certificateLog(ScanContext ctx, String domain) {
        List<String> out = new ArrayList<>();
        try {
            // external intelligence (opt-in), like OSV lookups: not a scan target, so not subject to the target allowlist
            java.net.http.HttpResponse<String> r = java.net.http.HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build().send(
                    java.net.http.HttpRequest.newBuilder(java.net.URI.create("https://crt.sh/?q=%25." + domain + "&output=json"))
                            .timeout(Duration.ofSeconds(30)).header("Accept", "application/json").build(),
                    java.net.http.HttpResponse.BodyHandlers.ofString());
            if (r.statusCode() != 200) return out;
            JsonNode arr = json.readTree(r.body());
            for (JsonNode n : arr) {
                for (String name : n.path("name_value").asText("").split("\\n")) {
                    String h = name.trim().toLowerCase(Locale.ROOT).replaceFirst("^\\*\\.", "");
                    if (h.endsWith("." + domain) && out.size() < 500 && !out.contains(h)) out.add(h);
                }
            }
            ctx.log("Certificate logs: " + out.size() + " name(s) for " + domain);
        } catch (Exception e) {
            ctx.log("Certificate logs unavailable for " + domain + ": " + e.getMessage());
        }
        return out;
    }

    private static Finding finding(String rule, String title, Severity sev, String host) {
        return Finding.of(ModuleCatalog.ATTACK_SURFACE, ID, rule, title, sev).asset(host).category("External attack surface")
                .confidence(Confidence.HIGH).exposure("internet");
    }
}
