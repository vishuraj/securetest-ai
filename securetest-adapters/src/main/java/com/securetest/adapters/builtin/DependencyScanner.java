package com.securetest.adapters.builtin;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.securetest.adapters.support.ScanSupport;
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
import com.securetest.core.util.Cvss3;
import com.securetest.core.util.MavenVersion;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;
import java.util.UUID;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarInputStream;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/**
 * Software composition analysis of the running application's classpath (SRS 5.6):
 * inventory, CycloneDX SBOM, restricted licenses, unsupported framework lines and
 * vulnerabilities from OSV (online, opt-in) or an offline OSV feed directory.
 */
public class DependencyScanner implements Scanner {

    public static final String ID = "builtin-dependencies";
    private static final String OSV = "https://api.osv.dev";
    private static final Pattern LICENSE = Pattern.compile("<license>\\s*<name>([^<]+)</name>", Pattern.DOTALL);
    private static final Pattern FILE_NAME = Pattern.compile("^(.+?)-(\\d[\\w.\\-]*)\\.jar$");

    public record Component(String group, String artifact, String version, String license, String source) {
        public String purl() { return "pkg:maven/" + group + "/" + artifact + "@" + version; }
        public String name() { return group + ":" + artifact; }
    }

    @Override
    public ScannerDescriptor descriptor() {
        return ScannerDescriptor.builder(ID, ModuleCatalog.VULNERABILITY, "Dependency inventory, SBOM and vulnerabilities")
                .purpose("Builds an inventory of every library on the application's runtime classpath, produces a CycloneDX SBOM, "
                        + "flags restricted licenses and matches components against OSV vulnerability data.")
                .access("Reads JAR metadata from the classpath. With online lookup enabled, package names and versions (no source code) are sent to api.osv.dev.")
                .duration("Seconds (offline) to ~1 minute (online lookup)")
                .field(FieldSpec.flag("onlineLookup", "Query OSV.dev for vulnerabilities", false,
                        "Sends package coordinates to https://api.osv.dev. Requires securetest.security.allow-external-intelligence=true."))
                .field(FieldSpec.optional("offlineFeed", "Offline OSV feed directory", FieldType.PATH, "",
                        "Directory containing OSV JSON advisories (e.g. an extracted Maven ecosystem export) for air-gapped use."))
                .field(FieldSpec.optional("restrictedLicenses", "Restricted licenses", FieldType.LIST, "AGPL,GPL-2.0,GPL-3.0,SSPL,Commons Clause",
                        "Comma-separated license names/fragments to flag."))
                .build();
    }

    @Override
    public List<PreflightCheck> preflight(ScanContext ctx) {
        List<PreflightCheck> out = new ArrayList<>();
        if (ctx.boolOption("onlineLookup", false)) {
            out.add(ctx.boolOption("_allowExternalIntelligence", false)
                    ? PreflightCheck.ok("External intelligence", "Online OSV lookups are permitted by policy.")
                    : PreflightCheck.error("External intelligence", "Online lookups are disabled by policy (securetest.security.allow-external-intelligence=false)."));
        }
        String feed = ctx.option("offlineFeed", "");
        if (!feed.isBlank()) {
            out.add(Files.isDirectory(Path.of(feed)) ? PreflightCheck.ok("Offline feed", feed) : PreflightCheck.error("Offline feed", "Directory not found: " + feed));
        }
        if (!ctx.boolOption("onlineLookup", false) && feed.isBlank()) {
            out.add(PreflightCheck.warn("Vulnerability data", "Neither online lookup nor an offline feed is configured: only inventory, SBOM and license checks will run."));
        }
        return out;
    }

    @Override
    public void scan(ScanContext ctx) throws Exception {
        ctx.progress(5, "Reading classpath");
        List<Component> components = inventory();
        ctx.log("Found " + components.size() + " components on the classpath");
        ctx.putResult("inventory", components.stream().map(c -> Map.of("name", c.name(), "version", c.version(),
                "license", c.license() == null ? "" : c.license(), "purl", c.purl())).toList());
        byte[] sbom = cycloneDx(components, ctx);
        ctx.attachArtifact("sbom.cdx.json", "application/vnd.cyclonedx+json", sbom);
        ctx.progress(20, "SBOM generated (" + components.size() + " components)");

        licenses(ctx, components);
        frameworkSupport(ctx, components);

        Map<String, List<JsonNode>> vulns = new HashMap<>();
        String feed = ctx.option("offlineFeed", "");
        if (!feed.isBlank()) {
            ctx.progress(30, "Matching offline OSV feed");
            offline(ctx, Path.of(feed), components, vulns);
        }
        if (ctx.boolOption("onlineLookup", false)) {
            if (!ctx.boolOption("_allowExternalIntelligence", false)) {
                ctx.log("Online lookup skipped: disabled by policy");
            } else {
                ctx.progress(40, "Querying OSV.dev");
                online(ctx, components, vulns);
            }
        }
        int count = 0;
        for (Component c : components) {
            for (JsonNode v : vulns.getOrDefault(c.name() + "@" + c.version(), List.of())) {
                ctx.report(toFinding(c, v));
                count++;
            }
        }
        ctx.putResult("vulnerableComponents", vulns.size());
        ctx.log("Vulnerability findings: " + count);
    }

    // ------------------------------------------------------------------ inventory

    public static List<Component> inventory() {
        Map<String, Component> out = new LinkedHashMap<>();
        String cp = System.getProperty("java.class.path", "");
        java.util.Deque<Path> queue = new java.util.ArrayDeque<>();
        java.util.Set<Path> seen = new java.util.HashSet<>();
        for (String entry : cp.split(File.pathSeparator)) if (!entry.isBlank()) queue.add(Path.of(entry));
        while (!queue.isEmpty()) {
            Path p = queue.poll();
            if (!seen.add(p.toAbsolutePath().normalize())) continue;
            if (!Files.isRegularFile(p) || !p.toString().toLowerCase(Locale.ROOT).endsWith(".jar")) continue;
            try (JarFile jar = new JarFile(p.toFile())) {
                // manifest-only launcher jars (surefire, IDEs) reference the real classpath via Class-Path
                if (jar.getManifest() != null) {
                    String classPath = jar.getManifest().getMainAttributes().getValue("Class-Path");
                    if (classPath != null) {
                        for (String ref : classPath.trim().split("\\s+")) {
                            try {
                                URI u = p.toUri().resolve(ref);
                                if ("file".equals(u.getScheme())) queue.add(Path.of(u));
                            } catch (RuntimeException ignored) {
                                // malformed entry
                            }
                        }
                    }
                }
                boolean boot = jar.getEntry("BOOT-INF/lib/") != null || jar.stream().anyMatch(e -> e.getName().startsWith("BOOT-INF/lib/"));
                if (boot) {
                    for (JarEntry e : jar.stream().filter(e -> e.getName().startsWith("BOOT-INF/lib/") && e.getName().endsWith(".jar")).toList()) {
                        try (InputStream in = jar.getInputStream(e)) {
                            readNested(new JarInputStream(in), e.getName().substring("BOOT-INF/lib/".length()), out);
                        }
                    }
                } else {
                    readJar(jar, p.getFileName().toString(), out);
                }
            } catch (IOException ignored) {
                // unreadable entry
            }
        }
        return new ArrayList<>(out.values());
    }

    private static void readJar(JarFile jar, String fileName, Map<String, Component> out) throws IOException {
        Map<String, Properties> poms = new HashMap<>();
        Map<String, String> licenses = new HashMap<>();
        for (JarEntry e : jar.stream().filter(x -> x.getName().startsWith("META-INF/maven/")).toList()) {
            if (e.getName().endsWith("pom.properties")) {
                Properties pr = new Properties();
                try (InputStream in = jar.getInputStream(e)) { pr.load(in); }
                poms.put(e.getName().replace("pom.properties", ""), pr);
            } else if (e.getName().endsWith("pom.xml")) {
                try (InputStream in = jar.getInputStream(e)) {
                    licenses.put(e.getName().replace("pom.xml", ""), license(new String(in.readNBytes(256 * 1024), StandardCharsets.UTF_8)));
                }
            }
        }
        add(poms, licenses, fileName, out);
    }

    private static void readNested(JarInputStream jin, String fileName, Map<String, Component> out) throws IOException {
        Map<String, Properties> poms = new HashMap<>();
        Map<String, String> licenses = new HashMap<>();
        JarEntry e;
        while ((e = jin.getNextJarEntry()) != null) {
            String n = e.getName();
            if (!n.startsWith("META-INF/maven/")) continue;
            byte[] data = jin.readNBytes(256 * 1024);
            if (n.endsWith("pom.properties")) {
                Properties pr = new Properties();
                pr.load(new ByteArrayInputStream(data));
                poms.put(n.replace("pom.properties", ""), pr);
            } else if (n.endsWith("pom.xml")) {
                licenses.put(n.replace("pom.xml", ""), license(new String(data, StandardCharsets.UTF_8)));
            }
        }
        add(poms, licenses, fileName, out);
    }

    private static void add(Map<String, Properties> poms, Map<String, String> licenses, String fileName, Map<String, Component> out) {
        if (poms.isEmpty()) {
            // Gradle-built jars (Spring, Micrometer...) carry no pom.properties: infer the group from the file name
            Matcher m = FILE_NAME.matcher(fileName);
            if (m.matches()) {
                String group = inferGroup(m.group(1));
                out.putIfAbsent(group + ":" + m.group(1), new Component(group, m.group(1), m.group(2), null, fileName));
            }
            return;
        }
        poms.forEach((dir, pr) -> {
            String g = pr.getProperty("groupId");
            String a = pr.getProperty("artifactId");
            String v = pr.getProperty("version");
            if (g != null && a != null && v != null) out.putIfAbsent(g + ":" + a, new Component(g, a, v, licenses.get(dir), fileName));
        });
    }

    private static final String[][] GROUPS = {
            {"spring-boot", "org.springframework.boot"}, {"spring-security-", "org.springframework.security"},
            {"spring-data-", "org.springframework.data"}, {"spring-cloud-", "org.springframework.cloud"},
            {"spring-kafka", "org.springframework.kafka"}, {"spring-amqp", "org.springframework.amqp"}, {"spring-rabbit", "org.springframework.amqp"},
            {"spring-session-", "org.springframework.session"}, {"spring-ws-", "org.springframework.ws"}, {"spring-batch-", "org.springframework.batch"},
            {"spring-", "org.springframework"}, {"micrometer-", "io.micrometer"}, {"tomcat-embed-", "org.apache.tomcat.embed"},
            {"jackson-datatype-", "com.fasterxml.jackson.datatype"}, {"jackson-module-", "com.fasterxml.jackson.module"},
            {"jackson-dataformat-", "com.fasterxml.jackson.dataformat"}, {"jackson-", "com.fasterxml.jackson.core"},
            {"logback-", "ch.qos.logback"}, {"slf4j-", "org.slf4j"}, {"jul-to-slf4j", "org.slf4j"}, {"log4j-", "org.apache.logging.log4j"},
            {"snakeyaml", "org.yaml"}, {"hibernate-", "org.hibernate.orm"}, {"HdrHistogram", "org.hdrhistogram"}, {"LatencyUtils", "org.latencyutils"},
            {"jakarta.", null}, {"netty-", "io.netty"}, {"reactor-core", "io.projectreactor"}, {"h2", "com.h2database"},
            {"postgresql", "org.postgresql"}, {"HikariCP", "com.zaxxer"}, {"guava", "com.google.guava"}, {"commons-", "commons-"}};

    static String inferGroup(String artifact) {
        for (String[] g : GROUPS) {
            if (!artifact.startsWith(g[0])) continue;
            if (g[1] == null) return artifact.replaceAll("-api$", "");         // jakarta.annotation-api -> jakarta.annotation
            if (g[1].equals("commons-")) return artifact;                       // commons-io:commons-io
            return g[1];
        }
        return "unknown";
    }

    private static String license(String pom) {
        Matcher m = LICENSE.matcher(pom);
        return m.find() ? m.group(1).trim() : null;
    }

    // ------------------------------------------------------------------ SBOM

    private static byte[] cycloneDx(List<Component> components, ScanContext ctx) throws IOException {
        ObjectNode root = ScanSupport.JSON.createObjectNode();
        root.put("bomFormat", "CycloneDX");
        root.put("specVersion", "1.5");
        root.put("serialNumber", "urn:uuid:" + UUID.randomUUID());
        root.put("version", 1);
        ObjectNode meta = root.putObject("metadata");
        meta.put("timestamp", Instant.now().toString());
        meta.putArray("tools").addObject().put("vendor", "SecureTest").put("name", "securetest-adapters").put("version", "1.0.2");
        ObjectNode app = meta.putObject("component");
        app.put("type", "application");
        app.put("name", ctx.application().name());
        if (ctx.application().version() != null) app.put("version", ctx.application().version());
        ArrayNode comps = root.putArray("components");
        for (Component c : components) {
            ObjectNode n = comps.addObject();
            n.put("type", "library");
            n.put("bom-ref", c.purl());
            n.put("group", c.group());
            n.put("name", c.artifact());
            n.put("version", c.version());
            n.put("purl", c.purl());
            if (c.license() != null) n.putArray("licenses").addObject().putObject("license").put("name", c.license());
        }
        return ScanSupport.JSON.writerWithDefaultPrettyPrinter().writeValueAsBytes(root);
    }

    // ------------------------------------------------------------------ policy checks

    private static void licenses(ScanContext ctx, List<Component> components) {
        List<String> restricted = Arrays.stream(ctx.option("restrictedLicenses", "AGPL,GPL-2.0,GPL-3.0,SSPL").split(","))
                .map(String::trim).filter(s -> !s.isEmpty()).toList();
        for (Component c : components) {
            if (c.license() == null) continue;
            String lic = c.license().toUpperCase(Locale.ROOT);
            boolean linkingException = lic.contains("CLASSPATH EXCEPTION") || lic.contains("LGPL") || lic.contains("LESSER");
            for (String r : restricted) {
                if (lic.contains(r.toUpperCase(Locale.ROOT)) && !linkingException) {
                    Finding f = Finding.of(ModuleCatalog.VULNERABILITY, ID, "LICENSE-RESTRICTED", "Restricted license: " + c.name() + " (" + c.license() + ")", Severity.MEDIUM)
                            .description("The component's license matches the restricted list (" + r + "). Distribution or SaaS use may impose obligations.")
                            .remediation("Review with legal/OSPO; replace the component or obtain a commercial license.")
                            .category("License").confidence(Confidence.MEDIUM).asset(c.purl()).tags("ISO27001-A.5.32");
                    f.dependency = new Finding.DependencyInfo(c.name(), c.version());
                    f.dependency.license = c.license();
                    f.dependency.advisoryId = "LICENSE";
                    ctx.report(f);
                    break;
                }
            }
        }
    }

    private static void frameworkSupport(ScanContext ctx, List<Component> components) {
        components.stream().filter(c -> c.name().equals("org.springframework.boot:spring-boot")).findFirst().ifPresent(c -> {
            int major = MavenVersion.major(c.version());
            int minor = MavenVersion.minor(c.version());
            boolean unsupported = major < 3 || (major == 3 && minor < 4);
            if (unsupported) {
                Finding f = Finding.of(ModuleCatalog.VULNERABILITY, ID, "EOL-SPRING-BOOT", "Spring Boot " + c.version() + " is out of open-source support", Severity.MEDIUM)
                        .description("Releases outside the OSS support window no longer receive public security fixes.")
                        .remediation("Upgrade to a supported Spring Boot line. The Migration module can assess and plan the upgrade.")
                        .category("Outdated").confidence(Confidence.HIGH).asset(c.purl()).tags("OWASP-A06", "PCI-6.3.3");
                f.dependency = new Finding.DependencyInfo(c.name(), c.version());
                f.dependency.advisoryId = "EOL";
                ctx.report(f);
            }
        });
        int feature = Runtime.version().feature();
        if (feature != 17 && feature != 21 && feature != 25 && feature < 26) {
            ctx.report(Finding.of(ModuleCatalog.VULNERABILITY, ID, "EOL-JAVA", "Non-LTS Java runtime " + feature, Severity.LOW)
                    .description("Non-LTS Java releases receive updates for six months only.")
                    .remediation("Run on a Java LTS release (17, 21 or 25).").category("Outdated").confidence(Confidence.HIGH)
                    .asset("java-runtime").tags("OWASP-A06"));
        }
    }

    // ------------------------------------------------------------------ vulnerability data

    private static void offline(ScanContext ctx, Path dir, List<Component> components, Map<String, List<JsonNode>> out) throws IOException {
        Map<String, Component> byName = new HashMap<>();
        components.forEach(c -> byName.put(c.name(), c));
        int files = 0;
        try (Stream<Path> s = Files.walk(dir)) {
            for (Path f : s.filter(p -> p.toString().endsWith(".json")).limit(500_000).toList()) {
                if (ctx.cancelled()) return;
                files++;
                JsonNode v;
                try { v = ScanSupport.JSON.readTree(f.toFile()); } catch (IOException e) { continue; }
                for (JsonNode aff : v.path("affected")) {
                    String name = aff.path("package").path("name").asText();
                    Component c = byName.get(name);
                    if (c != null && affects(aff, c.version())) out.computeIfAbsent(c.name() + "@" + c.version(), k -> new ArrayList<>()).add(v);
                }
            }
        }
        ctx.log("Offline feed: " + files + " advisories read");
    }

    static boolean affects(JsonNode affected, String version) {
        for (JsonNode v : affected.path("versions")) if (v.asText().equals(version)) return true;
        for (JsonNode range : affected.path("ranges")) {
            if (!"ECOSYSTEM".equals(range.path("type").asText())) continue;
            String introduced = null;
            for (JsonNode ev : range.path("events")) {
                if (ev.has("introduced")) introduced = ev.get("introduced").asText();
                String end = ev.has("fixed") ? ev.get("fixed").asText() : ev.has("last_affected") ? ev.get("last_affected").asText() : null;
                if (end != null && introduced != null) {
                    boolean afterStart = introduced.equals("0") || MavenVersion.compare(version, introduced) >= 0;
                    boolean beforeEnd = ev.has("fixed") ? MavenVersion.compare(version, end) < 0 : MavenVersion.compare(version, end) <= 0;
                    if (afterStart && beforeEnd) return true;
                    introduced = null;
                }
            }
            if (introduced != null && (introduced.equals("0") || MavenVersion.compare(version, introduced) >= 0)) return true;
        }
        return false;
    }

    private static void online(ScanContext ctx, List<Component> components, Map<String, List<JsonNode>> out) throws Exception {
        HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build();
        List<Component> known = components.stream().filter(c -> !c.group().equals("unknown")).toList();
        Map<String, JsonNode> details = new HashMap<>();
        for (int i = 0; i < known.size(); i += 500) {
            ctx.checkCancelled();
            List<Component> batch = known.subList(i, Math.min(known.size(), i + 500));
            ObjectNode body = ScanSupport.JSON.createObjectNode();
            ArrayNode queries = body.putArray("queries");
            for (Component c : batch) {
                ObjectNode q = queries.addObject();
                q.putObject("package").put("ecosystem", "Maven").put("name", c.name());
                q.put("version", c.version());
            }
            HttpResponse<String> resp = http.send(HttpRequest.newBuilder(URI.create(OSV + "/v1/querybatch"))
                    .timeout(Duration.ofSeconds(60)).header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(ScanSupport.JSON.writeValueAsString(body))).build(), HttpResponse.BodyHandlers.ofString());
            if (resp.statusCode() != 200) throw new IOException("OSV querybatch returned HTTP " + resp.statusCode());
            JsonNode results = ScanSupport.JSON.readTree(resp.body()).path("results");
            for (int k = 0; k < batch.size() && k < results.size(); k++) {
                Component c = batch.get(k);
                for (JsonNode v : results.get(k).path("vulns")) {
                    String id = v.path("id").asText();
                    if (details.size() >= 300 && !details.containsKey(id)) continue;
                    JsonNode d = details.get(id);
                    if (d == null) {
                        ctx.checkCancelled();
                        HttpResponse<String> dr = http.send(HttpRequest.newBuilder(URI.create(OSV + "/v1/vulns/" + id))
                                .timeout(Duration.ofSeconds(30)).GET().build(), HttpResponse.BodyHandlers.ofString());
                        if (dr.statusCode() != 200) continue;
                        d = ScanSupport.JSON.readTree(dr.body());
                        details.put(id, d);
                    }
                    out.computeIfAbsent(c.name() + "@" + c.version(), x -> new ArrayList<>()).add(d);
                }
            }
            ctx.progress(40 + (int) (50.0 * Math.min(known.size(), i + 500) / Math.max(1, known.size())), "Checked " + Math.min(known.size(), i + 500) + " components");
        }
    }

    static Finding toFinding(Component c, JsonNode v) {
        String id = v.path("id").asText();
        List<String> aliases = new ArrayList<>();
        v.path("aliases").forEach(a -> aliases.add(a.asText()));
        String cve = aliases.stream().filter(a -> a.startsWith("CVE-")).findFirst().orElse(id);
        String dbSeverity = v.path("database_specific").path("severity").asText(null);
        String vector = null;
        for (JsonNode s : v.path("severity")) {
            if (s.path("type").asText().startsWith("CVSS_V3")) vector = s.path("score").asText();
        }
        double score = Cvss3.baseScore(vector);
        Severity sev = dbSeverity != null ? Severity.parse(dbSeverity) : score >= 0 ? Severity.fromCvss(score) : Severity.MEDIUM;
        String summary = v.path("summary").asText(null);
        Finding f = Finding.of(ModuleCatalog.VULNERABILITY, ID, id, cve + " in " + c.name() + " " + c.version()
                        + (summary != null ? ": " + summary : ""), sev)
                .rawSeverity(dbSeverity != null ? dbSeverity : score >= 0 ? "CVSS " + score : "UNKNOWN")
                .description(ScanSupport.truncate(v.path("details").asText(summary == null ? "" : summary), 4000))
                .category("Vulnerable dependency").confidence(Confidence.HIGH).asset(c.purl())
                .tags("OWASP-A06", "PCI-6.3.3", "ISO27001-A.8.8", "SOC2-CC7.1");
        f.dependency = new Finding.DependencyInfo(c.name(), c.version());
        f.dependency.advisoryId = id;
        f.dependency.aliases = aliases.isEmpty() ? new ArrayList<>(List.of(id)) : aliases;
        f.dependency.cvssVector = vector;
        f.dependency.cvssScore = score >= 0 ? score : null;
        f.dependency.license = c.license();
        f.dependency.dependencyPath = new ArrayList<>(List.of(c.source(), c.name() + ":" + c.version()));
        f.dependency.fixedVersion = fixedVersion(v, c);
        f.remediation(f.dependency.fixedVersion != null
                ? "Upgrade " + c.name() + " to " + f.dependency.fixedVersion + " or later (or bump the Spring Boot / BOM version that manages it)."
                : "No fixed version is published yet. Assess exploitability, apply vendor mitigations or replace the component.");
        if (f.dependency.fixedVersion != null) f.fix("dependency-upgrade");
        for (JsonNode r : v.path("references")) {
            if (f.references.size() < 6) f.references.add(r.path("url").asText());
        }
        return f;
    }

    private static String fixedVersion(JsonNode v, Component c) {
        String best = null;
        for (JsonNode aff : v.path("affected")) {
            if (!aff.path("package").path("name").asText().equals(c.name())) continue;
            for (JsonNode range : aff.path("ranges")) {
                for (JsonNode ev : range.path("events")) {
                    if (!ev.has("fixed")) continue;
                    String fixed = ev.get("fixed").asText();
                    if (MavenVersion.compare(fixed, c.version()) > 0 && (best == null || MavenVersion.compare(fixed, best) < 0)) best = fixed;
                }
            }
        }
        return best;
    }
}
