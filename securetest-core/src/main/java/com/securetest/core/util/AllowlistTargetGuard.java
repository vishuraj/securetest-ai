package com.securetest.core.util;

import com.securetest.core.spi.ScanRejectedException;
import com.securetest.core.spi.TargetGuard;

import java.math.BigInteger;
import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Allowlist-based scope authorization. Entries may be:
 * <ul>
 *   <li>{@code self} – loopback names and the host application's own address;</li>
 *   <li>an exact host name or IP ({@code staging.example.com}, {@code 10.1.2.3});</li>
 *   <li>a wildcard domain ({@code *.staging.example.com});</li>
 *   <li>a CIDR block ({@code 10.20.0.0/16}).</li>
 * </ul>
 * Cloud metadata endpoints are always refused unless listed explicitly by IP (SSRF protection).
 */
public class AllowlistTargetGuard implements TargetGuard {

    private static final Set<String> METADATA = Set.of("169.254.169.254", "fd00:ec2:0:0:0:0:0:254", "metadata.google.internal", "100.100.100.200");
    private static final Set<String> LOOPBACK = Set.of("localhost", "127.0.0.1", "::1", "0:0:0:0:0:0:0:1", "[::1]");

    private final List<String> entries;
    private final String selfBaseUrl;
    private final boolean enforce;

    public AllowlistTargetGuard(List<String> entries, String selfBaseUrl, boolean enforce) {
        this.entries = new ArrayList<>();
        for (String e : entries) if (e != null && !e.isBlank()) this.entries.add(e.trim().toLowerCase(Locale.ROOT));
        this.selfBaseUrl = selfBaseUrl;
        this.enforce = enforce;
    }

    @Override
    public URI requireAllowedUrl(String url) {
        if (url == null || url.isBlank()) throw new ScanRejectedException("Target URL is required.");
        URI uri;
        try {
            uri = URI.create(url.trim());
        } catch (IllegalArgumentException e) {
            throw new ScanRejectedException("Invalid target URL: " + e.getMessage());
        }
        String scheme = uri.getScheme() == null ? "" : uri.getScheme().toLowerCase(Locale.ROOT);
        if (!scheme.equals("http") && !scheme.equals("https")) {
            throw new ScanRejectedException("Only http and https targets are supported (got '" + scheme + "').");
        }
        if (uri.getUserInfo() != null) throw new ScanRejectedException("Credentials in target URLs are not allowed; use a secret reference.");
        requireAllowedHost(uri.getHost());
        return uri;
    }

    @Override
    public String requireAllowedHost(String host) {
        if (host == null || host.isBlank()) throw new ScanRejectedException("Target host is required.");
        if (!isAllowedHost(host)) {
            throw new ScanRejectedException("Target '" + host + "' is not on the authorized target allowlist "
                    + "(securetest.security.target-allowlist). Add it only if you are authorized to test it.");
        }
        return host;
    }

    @Override
    public boolean isAllowedHost(String rawHost) {
        String host = rawHost.toLowerCase(Locale.ROOT).replace("[", "").replace("]", "");
        if (host.contains("/") || host.contains("@") || host.contains(" ")) return false;
        if (METADATA.contains(host) && !entries.contains(host)) return false;
        List<InetAddress> resolved = resolve(host);
        for (InetAddress a : resolved) {
            if (METADATA.contains(a.getHostAddress()) && !entries.contains(a.getHostAddress())) return false;
        }
        if (!enforce) return true;
        for (String e : entries) {
            if (e.equals("self")) {
                if (LOOPBACK.contains(host) || resolved.stream().anyMatch(InetAddress::isLoopbackAddress)) return true;
                if (selfBaseUrl != null) {
                    String selfHost = URI.create(selfBaseUrl).getHost();
                    if (selfHost != null && selfHost.equalsIgnoreCase(host)) return true;
                }
            } else if (e.startsWith("*.")) {
                if (host.endsWith(e.substring(1)) || host.equals(e.substring(2))) return true;
            } else if (e.contains("/")) {
                for (InetAddress a : resolved) if (inCidr(a, e)) return true;
            } else if (e.equals(host)) {
                return true;
            }
        }
        return false;
    }

    private static List<InetAddress> resolve(String host) {
        try {
            return List.of(InetAddress.getAllByName(host));
        } catch (UnknownHostException | SecurityException e) {
            return List.of();
        }
    }

    static boolean inCidr(InetAddress addr, String cidr) {
        try {
            String[] parts = cidr.split("/");
            InetAddress net = InetAddress.getByName(parts[0]);
            int prefix = Integer.parseInt(parts[1]);
            byte[] a = addr.getAddress();
            byte[] n = net.getAddress();
            if (a.length != n.length) return false;
            int bits = a.length * 8;
            BigInteger mask = BigInteger.ONE.shiftLeft(bits).subtract(BigInteger.ONE)
                    .shiftRight(prefix).not().and(BigInteger.ONE.shiftLeft(bits).subtract(BigInteger.ONE));
            return new BigInteger(1, a).and(mask).equals(new BigInteger(1, n).and(mask));
        } catch (Exception e) {
            return false;
        }
    }

    @Override public String selfBaseUrl() { return selfBaseUrl; }
    @Override public List<String> allowlist() { return List.copyOf(entries); }
}
