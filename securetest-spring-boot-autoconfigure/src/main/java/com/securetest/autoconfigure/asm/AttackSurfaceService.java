package com.securetest.autoconfigure.asm;

import com.fasterxml.jackson.core.type.TypeReference;
import com.securetest.autoconfigure.security.ApiException;
import com.securetest.autoconfigure.support.LocalStore;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;

/**
 * External attack-surface inventory (Detectify / Intruder style): the domains and hosts a team registers, plus the hosts
 * discovered under them. Registering a domain authorizes SecureTest to check it and its subdomains.
 */
public class AttackSurfaceService {

    private static final Pattern HOST = Pattern.compile("(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z]{2,63}");
    private static final Pattern IPV4 = Pattern.compile("(\\d{1,3}\\.){3}\\d{1,3}");

    public static class Asset {
        public String host;
        /** DOMAIN (checked with its subdomains) or HOST (that host only). */
        public String kind;
        /** MANUAL (registered) or DISCOVERED. */
        public String source;
        public String parent;
        public String owner;
        public String addedBy;
        public Instant firstSeen;
        public Instant lastSeen;
        public Instant lastChecked;
        public boolean resolves;
        public List<String> addresses = new ArrayList<>();
        public Integer httpsStatus;
        public Integer httpStatus;
        public String server;
        public Instant certificateExpires;
        public String certificateIssuer;
        public List<String> tags = new ArrayList<>();
    }

    private final LocalStore store;
    private final Map<String, Asset> assets;

    public AttackSurfaceService(LocalStore store) {
        this.store = store;
        this.assets = new ConcurrentHashMap<>(store.load("attack-surface", new TypeReference<Map<String, Asset>>() { }, LinkedHashMap::new));
        store.register("attack-surface", () -> new LinkedHashMap<>(assets));
    }

    public static String normalize(String raw) {
        if (raw == null) throw ApiException.badRequest("host is required");
        String h = raw.trim().toLowerCase(Locale.ROOT);
        h = h.replaceFirst("^[a-z]+://", "");
        int slash = h.indexOf('/');
        if (slash >= 0) h = h.substring(0, slash);
        int colon = h.indexOf(':');
        if (colon >= 0) h = h.substring(0, colon);
        if (h.startsWith("*.")) h = h.substring(2);
        if (h.endsWith(".")) h = h.substring(0, h.length() - 1);
        if (!HOST.matcher(h).matches() && !IPV4.matcher(h).matches()) throw ApiException.badRequest("Not a valid domain or host name: " + raw);
        return h;
    }

    public List<Asset> list() {
        return assets.values().stream().sorted(Comparator.comparing((Asset a) -> a.parent == null ? a.host : a.parent).thenComparing(a -> a.host)).toList();
    }

    public List<Asset> registered() {
        return assets.values().stream().filter(a -> "MANUAL".equals(a.source)).toList();
    }

    public synchronized Asset register(String raw, String kind, String owner, String actor) {
        String host = normalize(raw);
        String k = kind == null ? (IPV4.matcher(host).matches() ? "HOST" : "DOMAIN") : kind.toUpperCase(Locale.ROOT);
        if (!k.equals("DOMAIN") && !k.equals("HOST")) throw ApiException.badRequest("kind must be DOMAIN or HOST");
        if (k.equals("DOMAIN") && IPV4.matcher(host).matches()) throw ApiException.badRequest("An IP address can only be registered as a HOST");
        if (registered().size() >= 200) throw ApiException.conflict("At most 200 registered assets");
        Asset a = assets.getOrDefault(host, new Asset());
        a.host = host;
        a.kind = k;
        a.source = "MANUAL";
        a.parent = null;
        a.owner = owner;
        a.addedBy = actor;
        if (a.firstSeen == null) a.firstSeen = Instant.now();
        assets.put(host, a);
        store.markDirty("attack-surface");
        return a;
    }

    public synchronized void remove(String host) {
        String h = normalize(host);
        Asset a = assets.remove(h);
        if (a == null) throw ApiException.notFound("Asset " + host);
        if ("DOMAIN".equals(a.kind)) assets.values().removeIf(x -> h.equals(x.parent));
        store.markDirty("attack-surface");
    }

    /** Target allowlist entries for registered assets: each domain with its subdomains, each host on its own. */
    public List<String> allowlistEntries() {
        List<String> out = new ArrayList<>();
        for (Asset a : registered()) {
            if ("DOMAIN".equals(a.kind)) out.add("*." + a.host); else out.add(a.host);
        }
        return out;
    }

    /** True when the host is a registered asset or under a registered domain. */
    public boolean covers(String host) {
        String h = host.toLowerCase(Locale.ROOT);
        for (Asset a : registered()) {
            if (h.equals(a.host)) return true;
            if ("DOMAIN".equals(a.kind) && h.endsWith("." + a.host)) return true;
        }
        return false;
    }

    /** Records a check of a host. Returns true when it was not known before (a newly discovered asset). */
    public synchronized boolean observe(Asset observed) {
        Asset a = assets.get(observed.host);
        boolean isNew = a == null;
        if (isNew) {
            a = observed;
            a.source = "DISCOVERED";
            a.firstSeen = Instant.now();
            assets.put(a.host, a);
        } else {
            a.resolves = observed.resolves;
            a.addresses = observed.addresses;
            a.httpsStatus = observed.httpsStatus;
            a.httpStatus = observed.httpStatus;
            a.server = observed.server;
            a.certificateExpires = observed.certificateExpires;
            a.certificateIssuer = observed.certificateIssuer;
            a.tags = observed.tags;
        }
        if (a.resolves) a.lastSeen = Instant.now();
        a.lastChecked = Instant.now();
        store.markDirty("attack-surface");
        return isNew;
    }
}
