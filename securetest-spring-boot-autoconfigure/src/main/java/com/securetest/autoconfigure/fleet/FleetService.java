package com.securetest.autoconfigure.fleet;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.securetest.autoconfigure.SecureTestProperties;
import com.securetest.autoconfigure.security.ApiException;
import com.securetest.autoconfigure.security.SecureTestPrincipal;
import com.securetest.autoconfigure.service.FindingService;
import com.securetest.autoconfigure.service.StatusService;
import com.securetest.autoconfigure.service.TelemetryService;
import com.securetest.autoconfigure.support.AppContext;
import com.securetest.autoconfigure.support.AppRole;
import com.securetest.autoconfigure.support.SecretResolver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.env.Environment;

import java.io.IOException;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Predicate;
import java.util.stream.Collectors;

/**
 * The "All services" view of a microservice system. Every service that has the starter can show it: it finds the other
 * services (Spring Cloud service discovery, Kubernetes, or a configured list), asks each one for a compact summary, and
 * proxies a service's own dashboard so users can drill in through a single URL and a single sign-in.
 * <p>
 * Services trust each other's calls through a shared token ({@code securetest.fleet.token-ref}). A monolith never shows
 * the view: the architecture is detected at runtime.
 */
public class FleetService {

    public static final String TOKEN_HEADER = "X-SecureTest-Fleet-Token";
    public static final String USER_HEADER = "X-SecureTest-Fleet-User";
    public static final String ROLES_HEADER = "X-SecureTest-Fleet-Roles";
    public static final String VIA_HEADER = "X-SecureTest-Fleet-Via";

    private static final Logger log = LoggerFactory.getLogger(FleetService.class);

    /** Service-registry clients: their presence means the app is part of a microservice system. */
    private static final Map<String, String> REGISTRY_CLIENTS = new LinkedHashMap<>();
    static {
        REGISTRY_CLIENTS.put("org.springframework.cloud.netflix.eureka.EurekaDiscoveryClient", "Eureka client");
        REGISTRY_CLIENTS.put("org.springframework.cloud.consul.discovery.ConsulDiscoveryClient", "Consul client");
        REGISTRY_CLIENTS.put("org.springframework.cloud.zookeeper.discovery.ZookeeperDiscoveryClient", "Zookeeper discovery client");
        REGISTRY_CLIENTS.put("com.alibaba.cloud.nacos.discovery.NacosDiscoveryClient", "Nacos client");
        REGISTRY_CLIENTS.put("org.springframework.cloud.kubernetes.fabric8.discovery.KubernetesDiscoveryClient", "Kubernetes discovery");
        REGISTRY_CLIENTS.put("org.springframework.cloud.kubernetes.client.discovery.KubernetesInformerDiscoveryClient", "Kubernetes discovery");
    }

    private static final Set<String> FORWARDED_REQUEST_HEADERS = Set.of("accept", "accept-language", "content-type", "x-securetest-request",
            "x-correlation-id", "if-none-match", "if-modified-since", "idempotency-key");
    private static final Set<String> FORWARDED_RESPONSE_HEADERS = Set.of("content-type", "content-disposition", "cache-control", "etag",
            "last-modified", "location", "retry-after");

    /** One instance in the view. */
    record Target(String key, String service, String instanceId, String baseUrl, boolean self) { }

    /** A proxied response. */
    public record Forwarded(int status, Map<String, String> headers, byte[] body) { }

    private final SecureTestProperties props;
    private final AppContext app;
    private final AppRole role;
    private final StatusService status;
    private final TelemetryService telemetry;
    private final FindingService findings;
    private final SecretResolver secrets;
    private final Environment env;
    private final List<FleetDiscovery> discovery;
    private final Predicate<String> classPresent;
    private final ObjectMapper json = new ObjectMapper();
    private final HttpClient http;
    private final ExecutorService pool;
    private final Set<String> localHosts;

    private volatile List<Target> targets = List.of();
    private volatile long targetsAt;
    private volatile Map<String, Object> view;
    private volatile long viewAt;

    public FleetService(SecureTestProperties props, AppContext app, AppRole role, StatusService status, TelemetryService telemetry,
                        FindingService findings, SecretResolver secrets, Environment env, List<FleetDiscovery> discovery,
                        Predicate<String> classPresent) {
        this.props = props;
        this.app = app;
        this.role = role;
        this.status = status;
        this.telemetry = telemetry;
        this.findings = findings;
        this.secrets = secrets;
        this.env = env;
        this.discovery = discovery == null ? List.of() : List.copyOf(discovery);
        this.classPresent = classPresent;
        this.http = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).connectTimeout(fleet().getTimeout()).build();
        AtomicInteger seq = new AtomicInteger();
        this.pool = Executors.newFixedThreadPool(8, r -> {
            Thread t = new Thread(r, "securetest-fleet-" + seq.incrementAndGet());
            t.setDaemon(true);
            return t;
        });
        this.localHosts = localHosts();
    }

    private SecureTestProperties.Fleet fleet() {
        return props.getFleet();
    }

    // ------------------------------------------------------------------ architecture

    /** Monolith or microservices, and why. Decides whether the dashboard shows the "All services" view. */
    public Map<String, Object> architecture() {
        String reason = microserviceReason();
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("mode", reason == null ? "monolith" : "microservices");
        m.put("reason", reason == null ? "No service discovery, configured services or Spring Cloud infrastructure found" : reason);
        m.put("role", role.id());
        m.put("roleDetail", role.detail());
        m.put("fleetTokenConfigured", token() != null);
        return m;
    }

    public boolean microservices() {
        return microserviceReason() != null;
    }

    private String microserviceReason() {
        String setting = fleet().getEnabled() == null ? "auto" : fleet().getEnabled().trim().toLowerCase(Locale.ROOT);
        if (setting.equals("false")) return null;
        if (setting.equals("true")) return "securetest.fleet.enabled=true";
        if (!fleet().getMembers().isEmpty()) return "Services listed in securetest.fleet.members";
        if (role.infra()) return role.detail();
        for (Map.Entry<String, String> e : REGISTRY_CLIENTS.entrySet()) {
            if (classPresent.test(e.getKey())) return e.getValue();
        }
        String imports = env.getProperty("spring.config.import", "");
        if (imports.contains("configserver:") || env.containsProperty("spring.cloud.config.uri")) return "Spring Cloud Config client";
        if (targets(false).stream().anyMatch(t -> !t.self())) return "Other services found by service discovery";
        return null;
    }

    // ------------------------------------------------------------------ this service's summary

    /** Compact status of this instance, served to the other services. */
    public Map<String, Object> localSummary() {
        Map<String, Object> runtime = telemetry.snapshot(false);
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("service", app.name());
        m.put("instanceId", selfInstanceId());
        m.put("role", role.id());
        m.put("roleDetail", role.detail());
        var info = app.info();
        Map<String, Object> a = new LinkedHashMap<>();
        a.put("name", info.name());
        a.put("environment", info.environment());
        a.put("version", info.version());
        a.put("javaVersion", info.javaVersion());
        a.put("springBootVersion", info.springBootVersion());
        m.put("application", a);
        m.put("uptimeSeconds", runtime.get("uptimeSeconds"));
        Object health = telemetry.health().get("status");
        m.put("health", health == null ? "UNKNOWN" : String.valueOf(health));
        m.put("http", runtime.get("http"));
        Map<String, Object> jvm = new LinkedHashMap<>();
        if (runtime.get("memory") instanceof Map<?, ?> mem) jvm.put("heapPercent", mem.get("heapPercent"));
        if (runtime.get("cpu") instanceof Map<?, ?> cpu) jvm.put("cpuPercent", cpu.get("processPercent"));
        if (runtime.get("threads") instanceof Map<?, ?> th) jvm.put("threads", th.get("live"));
        m.put("jvm", jvm);
        Map<String, Object> gate = status.gate();
        m.put("gate", Map.of("status", gate.get("status"), "reasons", gate.get("reasons")));
        m.put("findings", findings.summary().get("open"));
        m.put("modules", status.moduleStatus());
        m.put("generatedAt", Instant.now().toString());
        return m;
    }

    // ------------------------------------------------------------------ the combined view

    /** All services with their summaries. Cached for {@code securetest.fleet.cache-ttl}. */
    public Map<String, Object> view(boolean refresh) {
        long now = System.currentTimeMillis();
        Map<String, Object> cached = view;
        if (!refresh && cached != null && now - viewAt < fleet().getCacheTtl().toMillis()) return cached;
        List<Target> ts = targets(refresh);
        List<CompletableFuture<Map<String, Object>>> calls = new ArrayList<>();
        for (Target t : ts) {
            calls.add(t.self() ? CompletableFuture.completedFuture(entry(t, "OK", null, localSummary()))
                    : CompletableFuture.supplyAsync(() -> fetch(t), pool));
        }
        List<Map<String, Object>> instances = calls.stream().map(CompletableFuture::join).toList();

        Map<String, List<Map<String, Object>>> byService = new LinkedHashMap<>();
        for (Map<String, Object> i : instances) byService.computeIfAbsent((String) i.get("service"), k -> new ArrayList<>()).add(i);
        List<Map<String, Object>> services = new ArrayList<>();
        for (Map.Entry<String, List<Map<String, Object>>> e : byService.entrySet()) services.add(service(e.getKey(), e.getValue()));
        services.sort(Comparator.comparing((Map<String, Object> s) -> !Boolean.TRUE.equals(s.get("self")))
                .thenComparing(s -> "infra".equals(s.get("role")))
                .thenComparing(s -> String.valueOf(s.get("name"))));

        Map<String, Object> totals = new LinkedHashMap<>();
        totals.put("services", services.size());
        totals.put("instances", instances.size());
        totals.put("reporting", instances.stream().filter(i -> "OK".equals(i.get("status"))).count());
        totals.put("down", instances.stream().filter(i -> "OK".equals(i.get("status")) && isDown(health(i))).count()
                + instances.stream().filter(i -> "UNREACHABLE".equals(i.get("status"))).count());
        totals.put("gateFailing", services.stream().filter(s -> "FAIL".equals(s.get("gate"))).count());
        totals.put("openCritical", services.stream().mapToInt(s -> intOf(s.get("openCritical"))).sum());
        totals.put("openHigh", services.stream().mapToInt(s -> intOf(s.get("openHigh"))).sum());

        Map<String, Object> m = new LinkedHashMap<>();
        m.put("architecture", architecture());
        m.put("sources", sources());
        m.put("self", ts.stream().filter(Target::self).map(Target::key).findFirst().orElse(null));
        m.put("totals", totals);
        m.put("services", services);
        m.put("generatedAt", Instant.now().toString());
        view = m;
        viewAt = now;
        return m;
    }

    private Map<String, Object> service(String name, List<Map<String, Object>> instances) {
        Map<String, Object> s = new LinkedHashMap<>();
        s.put("name", name);
        s.put("self", instances.stream().anyMatch(i -> Boolean.TRUE.equals(i.get("self"))));
        List<Map<String, Object>> ok = instances.stream().filter(i -> "OK".equals(i.get("status"))).toList();
        Map<String, Object> first = ok.isEmpty() ? null : summary(ok.get(0));
        s.put("role", first == null ? null : first.get("role"));
        s.put("roleDetail", first == null ? null : first.get("roleDetail"));
        s.put("total", instances.size());
        s.put("reporting", ok.size());
        s.put("up", ok.stream().filter(i -> "UP".equals(health(i))).count());
        long down = ok.stream().filter(i -> isDown(health(i))).count();
        long up = ok.stream().filter(i -> "UP".equals(health(i))).count();
        s.put("health", ok.isEmpty() ? (instances.stream().anyMatch(i -> "UNREACHABLE".equals(i.get("status"))) ? "DOWN" : "UNKNOWN")
                : down == 0 ? (up == ok.size() ? "UP" : "UNKNOWN") : up > 0 ? "DEGRADED" : "DOWN");
        s.put("gate", ok.isEmpty() ? null : ok.stream().anyMatch(i -> "FAIL".equals(nested(summary(i), "gate", "status"))) ? "FAIL" : "PASS");
        // findings are per codebase: take the instance with the most open findings rather than adding replicas up
        s.put("openCritical", ok.stream().mapToInt(i -> intOf(nested(summary(i), "findings", "CRITICAL"))).max().orElse(0));
        s.put("openHigh", ok.stream().mapToInt(i -> intOf(nested(summary(i), "findings", "HIGH"))).max().orElse(0));
        s.put("ratePerSecond", Math.round(ok.stream().mapToDouble(i -> doubleOf(nested(summary(i), "http", "ratePerSecond"))).sum() * 100) / 100.0);
        s.put("p95Ms", ok.stream().mapToInt(i -> intOf(nested(summary(i), "http", "p95Ms"))).max().orElse(0));
        s.put("errorRatePercent", ok.stream().mapToDouble(i -> doubleOf(nested(summary(i), "http", "errorRatePercent"))).max().orElse(0));
        s.put("httpRecording", ok.stream().anyMatch(i -> Boolean.TRUE.equals(nested(summary(i), "http", "recording"))));
        s.put("modules", first == null ? List.of() : first.get("modules"));
        s.put("instances", instances);
        return s;
    }

    private Map<String, Object> fetch(Target t) {
        try {
            HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(t.baseUrl() + "/api/v1/fleet/summary"))
                    .timeout(fleet().getTimeout()).header("Accept", "application/json").GET();
            trustHeaders(b, "securetest-fleet", "VIEWER");
            HttpResponse<String> r = http.send(b.build(), HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            int code = r.statusCode();
            if (code == 200) {
                Map<String, Object> summary = json.readValue(r.body(), new TypeReference<Map<String, Object>>() { });
                return entry(t, "OK", null, summary);
            }
            if (code == 401 || code == 403) {
                return entry(t, "UNAUTHORIZED", token() == null
                        ? "This service needs the fleet token. Give every service the same SECURETEST_FLEET_TOKEN (for example from your config server)."
                        : "This service rejected the fleet token. Every service needs the same SECURETEST_FLEET_TOKEN.", null);
            }
            if (code == 404) return entry(t, "NOT_INSTALLED", "SecureTest is not added to this service (or it uses a different dashboard path).", null);
            return entry(t, "ERROR", "HTTP " + code, null);
        } catch (IOException e) {
            return entry(t, "UNREACHABLE", "Cannot reach " + t.baseUrl() + ": " + e.getClass().getSimpleName(), null);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return entry(t, "UNREACHABLE", "Interrupted", null);
        } catch (RuntimeException e) {
            return entry(t, "ERROR", e.getClass().getSimpleName() + ": " + e.getMessage(), null);
        }
    }

    private Map<String, Object> entry(Target t, String state, String message, Map<String, Object> summary) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("key", t.key());
        m.put("service", t.service());
        m.put("instanceId", t.instanceId());
        m.put("url", t.self() ? null : display(t.baseUrl()));
        m.put("self", t.self());
        m.put("status", state);
        m.put("message", message);
        m.put("summary", summary);
        return m;
    }

    // ------------------------------------------------------------------ drill-down proxy

    /** Forwards a request for {@code /fleet/{key}/...} to that service's own SecureTest dashboard, as the signed-in user. */
    public Forwarded forward(String key, String method, String rest, String query, Map<String, String> requestHeaders, byte[] body,
                             SecureTestPrincipal user) {
        Target t = find(key);
        if (t == null) throw ApiException.notFound("Service " + key);
        if (t.self()) throw ApiException.badRequest("This is the service you are on; open its dashboard directly.");
        String path = rest == null || rest.isEmpty() ? "/" : rest;
        URI uri = URI.create(t.baseUrl() + path + (query == null || query.isEmpty() ? "" : "?" + query));
        HttpRequest.Builder b = HttpRequest.newBuilder(uri).timeout(Duration.ofSeconds(60))
                .method(method, body == null || body.length == 0 ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofByteArray(body));
        requestHeaders.forEach((k, v) -> {
            if (v != null && FORWARDED_REQUEST_HEADERS.contains(k.toLowerCase(Locale.ROOT))) b.header(k, v);
        });
        trustHeaders(b, user.name(), user.roles().stream().map(Enum::name).sorted().collect(Collectors.joining(",")));
        try {
            HttpResponse<byte[]> r = http.send(b.build(), HttpResponse.BodyHandlers.ofByteArray());
            Map<String, String> headers = new LinkedHashMap<>();
            r.headers().map().forEach((k, v) -> {
                String lk = k.toLowerCase(Locale.ROOT);
                if (!v.isEmpty() && FORWARDED_RESPONSE_HEADERS.contains(lk)) headers.put(lk, v.get(0));
            });
            if (headers.containsKey("location")) headers.put("location", rewriteLocation(headers.get("location"), t));
            if (r.statusCode() == 401) {
                headers.put("content-type", "application/json");
                String msg = "{\"status\":401,\"error\":\"unauthenticated\",\"message\":\"" + t.service()
                        + " did not accept this dashboard. Give every service the same SECURETEST_FLEET_TOKEN.\"}";
                return new Forwarded(401, headers, msg.getBytes(StandardCharsets.UTF_8));
            }
            return new Forwarded(r.statusCode(), headers, r.body());
        } catch (IOException e) {
            throw new ApiException(502, "bad_gateway", "Cannot reach " + t.service() + " at " + display(t.baseUrl()));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new ApiException(502, "bad_gateway", "Interrupted");
        }
    }

    private String rewriteLocation(String location, Target t) {
        URI base = URI.create(t.baseUrl());
        String path = location;
        if (location.startsWith("http://") || location.startsWith("https://")) {
            URI l = URI.create(location);
            if (!(l.getHost() + ":" + l.getPort()).equals(base.getHost() + ":" + base.getPort())) return location;
            path = l.getRawPath() + (l.getRawQuery() == null ? "" : "?" + l.getRawQuery());
        }
        String memberPrefix = base.getRawPath();
        if (memberPrefix != null && path.startsWith(memberPrefix)) {
            return app.contextPath() + props.normalizedPath() + "/fleet/" + t.key() + path.substring(memberPrefix.length());
        }
        return location;
    }

    private void trustHeaders(HttpRequest.Builder b, String user, String roles) {
        String token = token();
        if (token != null) {
            b.header(TOKEN_HEADER, token);
            b.header(USER_HEADER, user);
            b.header(ROLES_HEADER, roles);
            b.header(VIA_HEADER, app.name());
        }
    }

    private String token() {
        String t = secrets.resolve(fleet().getTokenRef());
        return t == null || t.isBlank() ? null : t.trim();
    }

    // ------------------------------------------------------------------ targets

    private Target find(String key) {
        for (Target t : targets(false)) if (t.key().equals(key)) return t;
        for (Target t : targets(true)) if (t.key().equals(key)) return t;
        return null;
    }

    private List<String> sources() {
        List<String> s = new ArrayList<>();
        if (!fleet().getMembers().isEmpty()) s.add("securetest.fleet.members");
        if (fleet().isDiscovery()) discovery.forEach(d -> s.add(d.description()));
        return s;
    }

    synchronized List<Target> targets(boolean refresh) {
        long now = System.currentTimeMillis();
        if (!refresh && targetsAt > 0 && now - targetsAt < fleet().getCacheTtl().toMillis()) return targets;
        record Raw(String service, String instanceId, String baseUrl, boolean self) { }
        List<Raw> raw = new ArrayList<>();
        raw.add(new Raw(app.name(), selfInstanceId(), null, true));
        Set<String> seen = new HashSet<>();
        for (SecureTestProperties.Member m : fleet().getMembers()) {
            if (m.getUrl() == null || m.getUrl().isBlank()) continue;
            String base = stripSlash(m.getUrl()) + props.normalizedPath();
            String name = m.getName() == null || m.getName().isBlank() ? URI.create(m.getUrl()).getHost() : m.getName();
            if (seen.add(base)) raw.add(new Raw(name, display(m.getUrl()), base, false));
        }
        if (fleet().isDiscovery()) {
            for (FleetDiscovery d : discovery) {
                for (FleetDiscovery.Instance i : d.instances()) {
                    if (isSelf(i)) continue;
                    String path = i.metadata().getOrDefault("securetest-path", i.metadata().getOrDefault("securetest.path", props.normalizedPath()));
                    String base = stripSlash(i.baseUri().toString()) + path;
                    if (seen.add(base)) raw.add(new Raw(i.service().toLowerCase(Locale.ROOT), i.instanceId(), base, false));
                }
            }
        }
        int max = Math.max(1, fleet().getMaxInstances());
        if (raw.size() > max) raw = new ArrayList<>(raw.subList(0, max));
        Map<String, Long> perService = raw.stream().collect(Collectors.groupingBy(r -> sanitize(r.service()), Collectors.counting()));
        List<Target> out = new ArrayList<>();
        Set<String> keys = new HashSet<>();
        for (Raw r : raw) {
            String k = sanitize(r.service());
            if (perService.get(k) > 1) k = k + "~" + (r.self() ? "this" : sanitize(r.instanceId()));
            String unique = k;
            for (int n = 2; !keys.add(unique); n++) unique = k + "-" + n;
            out.add(new Target(unique, r.service(), r.instanceId(), r.baseUrl(), r.self()));
        }
        targets = Collections.unmodifiableList(out);
        targetsAt = now;
        return targets;
    }

    private boolean isSelf(FleetDiscovery.Instance i) {
        if (!i.service().equalsIgnoreCase(app.name())) return false;
        Integer port = app.port();
        if (port == null || i.baseUri().getPort() != port) return false;
        String host = i.baseUri().getHost();
        return host != null && localHosts.contains(host.toLowerCase(Locale.ROOT));
    }

    private String selfInstanceId() {
        String host = "localhost";
        try {
            host = InetAddress.getLocalHost().getHostName();
        } catch (IOException e) {
            // keep localhost
        }
        return host + ":" + app.port();
    }

    private static Set<String> localHosts() {
        Set<String> s = new HashSet<>(Set.of("localhost", "127.0.0.1", "::1", "0:0:0:0:0:0:0:1"));
        try {
            InetAddress me = InetAddress.getLocalHost();
            s.add(me.getHostName().toLowerCase(Locale.ROOT));
            s.add(me.getCanonicalHostName().toLowerCase(Locale.ROOT));
            s.add(me.getHostAddress());
            var nics = NetworkInterface.getNetworkInterfaces();
            while (nics != null && nics.hasMoreElements()) {
                var addrs = nics.nextElement().getInetAddresses();
                while (addrs.hasMoreElements()) {
                    String a = addrs.nextElement().getHostAddress();
                    int pct = a.indexOf('%');
                    s.add((pct > 0 ? a.substring(0, pct) : a).toLowerCase(Locale.ROOT));
                }
            }
        } catch (IOException | RuntimeException e) {
            log.debug("SecureTest: cannot list local addresses", e);
        }
        return s;
    }

    // ------------------------------------------------------------------ helpers

    @SuppressWarnings("unchecked")
    private static Map<String, Object> summary(Map<String, Object> instance) {
        Object s = instance.get("summary");
        return s instanceof Map<?, ?> m ? (Map<String, Object>) m : Map.of();
    }

    private static String health(Map<String, Object> instance) {
        return String.valueOf(summary(instance).get("health"));
    }

    /** Spring Boot's failing health states (custom states such as UNKNOWN are not counted as down). */
    private static boolean isDown(String health) {
        return "DOWN".equals(health) || "OUT_OF_SERVICE".equals(health);
    }

    private static Object nested(Map<String, Object> m, String a, String b) {
        Object x = m.get(a);
        return x instanceof Map<?, ?> mm ? mm.get(b) : null;
    }

    private static int intOf(Object o) {
        return o instanceof Number n ? n.intValue() : 0;
    }

    private static double doubleOf(Object o) {
        return o instanceof Number n ? n.doubleValue() : 0;
    }

    private static String stripSlash(String s) {
        String t = s.trim();
        while (t.endsWith("/")) t = t.substring(0, t.length() - 1);
        return t;
    }

    private static String display(String url) {
        try {
            URI u = URI.create(url);
            return u.getHost() + (u.getPort() > 0 ? ":" + u.getPort() : "");
        } catch (RuntimeException e) {
            return url;
        }
    }

    static String sanitize(String s) {
        String t = (s == null ? "service" : s).toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9._-]+", "-").replaceAll("^-+|-+$", "");
        if (t.isEmpty()) t = "service";
        return t.length() > 80 ? t.substring(0, 80) : t;
    }

    public void shutdown() {
        pool.shutdownNow();
    }
}
