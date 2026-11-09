package com.securetest.migration;

import com.securetest.core.util.MavenVersion;
import com.securetest.core.util.SourceFiles;
import com.securetest.migration.MigrationModels.Assessment;
import com.securetest.migration.MigrationModels.BuildModule;
import com.securetest.migration.MigrationModels.Inventory;
import com.securetest.migration.MigrationModels.Item;
import com.securetest.migration.MigrationModels.Plan;
import com.securetest.migration.MigrationModels.PlanStep;
import com.securetest.migration.MigrationModels.Target;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.regex.MatchResult;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Analysis-only by construction (FR-MIG-001): {@link #discover}, {@link #assess}, {@link #plan} and
 * {@link #transform} never write files. Writing happens exclusively through {@link ChangeSetEngine}.
 */
public class MigrationEngine {

    public static final String CAT_BUILD = "BUILD";
    public static final String CAT_DEPENDENCIES = "DEPENDENCIES";
    public static final String CAT_JAKARTA = "JAKARTA";
    public static final String CAT_SECURITY = "SPRING_SECURITY";
    public static final String CAT_JDK = "JDK_API";
    public static final String CAT_CONFIG = "CONFIGURATION";
    public static final String CAT_CONTAINER = "CONTAINER";
    public static final String CAT_BOOT4 = "SPRING_BOOT_4";
    public static final List<String> CATEGORIES = List.of(CAT_BUILD, CAT_DEPENDENCIES, CAT_JAKARTA, CAT_SECURITY, CAT_JDK, CAT_CONFIG, CAT_CONTAINER, CAT_BOOT4);

    private static final int MAX_FILES = 20_000;

    private final GitWorkspace git;

    public MigrationEngine(GitWorkspace git) {
        this.git = git;
    }

    // =====================================================================================  discover

    public Inventory discover(Path root) throws IOException {
        Inventory inv = new Inventory();
        inv.root = root.toAbsolutePath().normalize().toString();
        List<Path> buildFiles = SourceFiles.walk(root, p -> {
            String n = p.getFileName().toString();
            return n.equals("pom.xml") || n.equals("build.gradle") || n.equals("build.gradle.kts");
        }, 500);
        for (Path bf : buildFiles) {
            BuildModule m = new BuildModule();
            Path dir = bf.getParent();
            m.path = SourceFiles.relative(root, dir);
            m.buildFile = SourceFiles.relative(root, bf);
            String text = SourceFiles.read(bf);
            if (bf.getFileName().toString().equals("pom.xml")) {
                m.buildTool = "maven";
                m.springBootVersion = first(text, "<artifactId>spring-boot-starter-parent</artifactId>\\s*<version>([^<]+)</version>",
                        "<artifactId>spring-boot-dependencies</artifactId>\\s*<version>([^<]+)</version>",
                        "<spring-boot\\.version>([^<]+)</spring-boot\\.version>");
                m.javaVersion = first(text, "<java\\.version>([^<]+)</java\\.version>", "<maven\\.compiler\\.release>([^<]+)<",
                        "<maven\\.compiler\\.source>([^<]+)<", "<release>(\\d+)</release>", "<source>([0-9.]+)</source>");
                m.wrapperVersion = wrapper(dir.resolve(".mvn/wrapper/maven-wrapper.properties"), "apache-maven-([0-9.]+)-");
            } else {
                m.buildTool = "gradle";
                m.springBootVersion = first(text, "org\\.springframework\\.boot['\"]\\s*\\)?\\s*version\\s*['\"]([^'\"]+)['\"]");
                m.javaVersion = first(text, "JavaLanguageVersion\\.of\\((\\d+)\\)", "sourceCompatibility\\s*=\\s*['\"]?(?:JavaVersion\\.VERSION_)?([0-9._]+)");
                if (m.javaVersion != null) m.javaVersion = m.javaVersion.replace('_', '.');
                m.wrapperVersion = wrapper(dir.resolve("gradle/wrapper/gradle-wrapper.properties"), "gradle-([0-9.]+)-");
            }
            List<Path> javaFiles = SourceFiles.walk(dir, p -> p.toString().endsWith(".java"), MAX_FILES);
            for (Path jf : javaFiles) {
                // count only files that belong to this module (not a nested module)
                if (!owningModule(jf, buildFiles).equals(bf)) continue;
                m.javaFiles++;
                String rel = jf.toString().replace('\\', '/');
                if (rel.contains("/src/test/")) m.testFiles++;
                String src = SourceFiles.read(jf);
                Matcher jm = JAKARTA_PATTERN.matcher(src);
                while (jm.find()) m.javaxReferences++;
            }
            inv.modules.add(m);
        }
        inv.totalJavaFiles = inv.modules.stream().mapToInt(m -> m.javaFiles).sum();
        inv.totalTestFiles = inv.modules.stream().mapToInt(m -> m.testFiles).sum();
        inv.detectedJava = inv.modules.stream().map(m -> m.javaVersion).filter(v -> v != null).findFirst().orElse(null);
        inv.detectedSpringBoot = inv.modules.stream().map(m -> m.springBootVersion).filter(v -> v != null).findFirst().orElse(null);
        int javax = inv.modules.stream().mapToInt(m -> m.javaxReferences).sum();
        inv.servletNamespace = javax > 0 ? "javax" : (inv.detectedSpringBoot != null && MavenVersion.major(inv.detectedSpringBoot) >= 3 ? "jakarta" : "none detected");
        if (inv.totalJavaFiles > 0) inv.languages.add("Java");
        if (!SourceFiles.walk(root, p -> p.toString().endsWith(".kt"), 1).isEmpty()) inv.languages.add("Kotlin");
        for (Path df : SourceFiles.walk(root, p -> p.getFileName().toString().startsWith("Dockerfile"), 200)) {
            String from = first(SourceFiles.read(df), "(?m)^\\s*FROM\\s+(\\S+)");
            if (from != null) inv.containerImages.put(SourceFiles.relative(root, df), from);
        }
        inv.gitRepository = git.isRepository(root);
        if (inv.gitRepository) {
            inv.gitBranch = git.branch(root).orElse(null);
            inv.gitHead = git.head(root).orElse(null);
            inv.dirtyFiles = new ArrayList<>(git.dirtyFiles(root));
        }
        return inv;
    }

    private static Path owningModule(Path file, List<Path> buildFiles) {
        Path best = null;
        for (Path bf : buildFiles) {
            Path dir = bf.getParent();
            if (file.startsWith(dir) && (best == null || dir.getNameCount() > best.getParent().getNameCount())) best = bf;
        }
        return best;
    }

    private static String wrapper(Path props, String regex) throws IOException {
        return Files.exists(props) ? first(SourceFiles.read(props), regex) : null;
    }

    private static String first(String text, String... regexes) {
        for (String r : regexes) {
            Matcher m = Pattern.compile(r, Pattern.DOTALL).matcher(text);
            if (m.find()) return m.group(1).trim();
        }
        return null;
    }

    // =====================================================================================  rules

    /** javax packages that moved to jakarta (JDK-owned javax.* packages such as javax.sql or javax.crypto are excluded). */
    static final Pattern JAKARTA_PATTERN = Pattern.compile(
            "\\bjavax\\.(servlet|persistence|validation|transaction(?!\\.xa)|ws\\.rs|inject|ejb|faces|jms|json|mail|websocket|xml\\.bind|xml\\.ws|xml\\.soap|activation|enterprise|interceptor|batch|el|decorator|security\\.enterprise|annotation\\.(?:PostConstruct|PreDestroy|Resource|Resources|Generated|Priority|ManagedBean|security))\\b");

    private record Rule(String id, String category, String severity, Predicate<Path> files, Pattern pattern,
                        Function<MatchResult, String> replacement, Function<MatchResult, String> message, String guidance) {
        boolean auto() { return replacement != null; }
    }

    private static Predicate<Path> named(String... names) {
        Set<String> set = Set.of(names);
        return p -> set.contains(p.getFileName().toString());
    }

    private static Predicate<Path> ext(String e) { return p -> p.getFileName().toString().endsWith(e); }

    private static final Predicate<Path> APP_PROPERTIES = p -> p.getFileName().toString().matches("application.*\\.properties") || p.getFileName().toString().matches("bootstrap.*\\.properties");
    private static final Predicate<Path> APP_YAML = p -> p.getFileName().toString().matches("(application|bootstrap).*\\.ya?ml");
    private static final Predicate<Path> DOCKERFILE = p -> p.getFileName().toString().startsWith("Dockerfile");

    private static final String[][] JAVAX_ARTIFACTS = {
            {"javax.servlet", "javax.servlet-api", "jakarta.servlet", "jakarta.servlet-api"},
            {"javax.persistence", "javax.persistence-api", "jakarta.persistence", "jakarta.persistence-api"},
            {"javax.validation", "validation-api", "jakarta.validation", "jakarta.validation-api"},
            {"javax.xml.bind", "jaxb-api", "jakarta.xml.bind", "jakarta.xml.bind-api"},
            {"javax.annotation", "javax.annotation-api", "jakarta.annotation", "jakarta.annotation-api"},
            {"javax.transaction", "javax.transaction-api", "jakarta.transaction", "jakarta.transaction-api"},
            {"javax.inject", "javax.inject", "jakarta.inject", "jakarta.inject-api"},
            {"javax.ws.rs", "javax.ws.rs-api", "jakarta.ws.rs", "jakarta.ws.rs-api"},
    };

    private static final String[][] PROPERTY_RENAMES = {
            {"spring.redis.", "spring.data.redis."},
            {"spring.data.cassandra.", "spring.cassandra."},
            {"server.max-http-header-size", "server.max-http-request-header-size"},
            {"management.metrics.export.prometheus.", "management.prometheus.metrics.export."},
            {"management.metrics.export.datadog.", "management.datadog.metrics.export."},
            {"management.metrics.export.influx.", "management.influx.metrics.export."},
            {"management.metrics.export.otlp.", "management.otlp.metrics.export."},
            {"spring.security.saml2.relyingparty.registration.", "spring.security.saml2.relyingparty.registration."},
    };

    private List<Rule> rules(Target t, Inventory inv) {
        List<Rule> r = new ArrayList<>();
        String tj = String.valueOf(t.javaVersion());
        String tb = t.springBootVersion();
        boolean toBoot3Plus = MavenVersion.major(tb) >= 3;
        boolean fromBoot2 = inv.detectedSpringBoot == null || MavenVersion.major(inv.detectedSpringBoot) < 3;

        // ---------------- build
        Function<MatchResult, String> bootVersion = m -> MavenVersion.isLower(m.group(2).trim(), tb) ? m.group(1) + tb + m.group(3) : m.group();
        r.add(new Rule("MIG-BUILD-001", CAT_BUILD, "MAJOR", named("pom.xml"),
                Pattern.compile("(<artifactId>spring-boot-starter-parent</artifactId>\\s*<version>)([^<]+)(</version>)"),
                bootVersion, m -> "Spring Boot parent " + m.group(2) + " → " + tb, "Review the Spring Boot release notes / migration guide for every skipped minor line."));
        r.add(new Rule("MIG-BUILD-002", CAT_BUILD, "MAJOR", named("pom.xml"),
                Pattern.compile("(<artifactId>spring-boot-dependencies</artifactId>\\s*<version>)([^<]+)(</version>)"),
                bootVersion, m -> "Spring Boot BOM " + m.group(2) + " → " + tb, "Imported BOM version must match the plugin version."));
        r.add(new Rule("MIG-BUILD-003", CAT_BUILD, "MAJOR", named("pom.xml"),
                Pattern.compile("(<spring-boot\\.version>)([^<]+)(</spring-boot\\.version>)"),
                bootVersion, m -> "spring-boot.version property " + m.group(2) + " → " + tb, ""));
        r.add(new Rule("MIG-BUILD-004", CAT_BUILD, "MAJOR", named("pom.xml"),
                Pattern.compile("(<(java\\.version|maven\\.compiler\\.(?:source|target|release))>)([^<]+)(</\\2>)"),
                m -> CompatibilityMatrix.javaMajor(m.group(3)) > 0 && CompatibilityMatrix.javaMajor(m.group(3)) < t.javaVersion() ? m.group(1) + tj + m.group(4) : m.group(),
                m -> "<" + m.group(2) + "> " + m.group(3) + " → " + tj, "Update CI images and the local JDK to Java " + tj + "."));
        r.add(new Rule("MIG-BUILD-005", CAT_BUILD, "MAJOR", named("build.gradle", "build.gradle.kts"),
                Pattern.compile("(id\\s*\\(?\\s*['\"]org\\.springframework\\.boot['\"]\\s*\\)?\\s*version\\s*['\"])([^'\"]+)(['\"])"),
                bootVersion, m -> "Spring Boot Gradle plugin " + m.group(2) + " → " + tb, ""));
        r.add(new Rule("MIG-BUILD-006", CAT_BUILD, "MAJOR", named("build.gradle", "build.gradle.kts"),
                Pattern.compile("((?:source|target)Compatibility\\s*=\\s*)(['\"]?(?:JavaVersion\\.VERSION_)?([0-9]+(?:[._][0-9]+)?)['\"]?)"),
                m -> CompatibilityMatrix.javaMajor(m.group(3).replace('_', '.')) < t.javaVersion() ? m.group(1) + "JavaVersion.VERSION_" + tj : m.group(),
                m -> "Gradle " + m.group(1).trim() + " " + m.group(3) + " → " + tj, ""));
        r.add(new Rule("MIG-BUILD-007", CAT_BUILD, "MAJOR", named("build.gradle", "build.gradle.kts"),
                Pattern.compile("(JavaLanguageVersion\\.of\\()(\\d+)(\\))"),
                m -> Integer.parseInt(m.group(2)) < t.javaVersion() ? m.group(1) + tj + m.group(3) : m.group(),
                m -> "Gradle toolchain Java " + m.group(2) + " → " + tj, ""));
        String gradleTarget = t.javaVersion() >= 25 ? "9.1.0" : "8.14.3";
        String gradleMin = t.javaVersion() >= 25 ? "9.1" : (t.javaVersion() >= 21 ? "8.5" : (MavenVersion.major(tb) >= 4 ? "8.14" : "7.6.4"));
        r.add(new Rule("MIG-BUILD-008", CAT_BUILD, "MAJOR", named("gradle-wrapper.properties"),
                Pattern.compile("(distributionUrl=.*?gradle-)([0-9.]+)(-(?:bin|all)\\.zip)"),
                m -> MavenVersion.isLower(m.group(2), gradleMin) ? m.group(1) + gradleTarget + m.group(3) : m.group(),
                m -> "Gradle wrapper " + m.group(2) + " (needs ≥ " + gradleMin + ") → " + gradleTarget, "Run ./gradlew wrapper afterwards to refresh the wrapper jar."));
        r.add(new Rule("MIG-BUILD-009", CAT_BUILD, "MINOR", named("maven-wrapper.properties"),
                Pattern.compile("(distributionUrl=.*?apache-maven/)([0-9.]+)(/apache-maven-)([0-9.]+)(-bin\\.zip)"),
                m -> MavenVersion.isLower(m.group(2), "3.6.3") ? m.group(1) + "3.9.11" + m.group(3) + "3.9.11" + m.group(5) : m.group(),
                m -> "Maven wrapper " + m.group(2) + " (Spring Boot 3+ needs ≥ 3.6.3)", ""));
        r.add(new Rule("MIG-BUILD-010", CAT_BUILD, "MINOR", named("build.gradle", "build.gradle.kts"),
                Pattern.compile("(id\\s*\\(?\\s*['\"]io\\.spring\\.dependency-management['\"]\\s*\\)?\\s*version\\s*['\"])(1\\.0\\.[^'\"]+)(['\"])"),
                m -> m.group(1) + "1.1.7" + m.group(3), m -> "dependency-management plugin " + m.group(2) + " → 1.1.7", ""));

        // ---------------- dependencies (javax → jakarta coordinates)
        if (toBoot3Plus) {
            for (String[] a : JAVAX_ARTIFACTS) {
                r.add(new Rule("MIG-DEP-" + a[3], CAT_DEPENDENCIES, "BLOCKER", named("pom.xml"),
                        Pattern.compile("<groupId>\\s*" + Pattern.quote(a[0]) + "\\s*</groupId>(\\s*)<artifactId>\\s*" + Pattern.quote(a[1]) + "\\s*</artifactId>"),
                        m -> "<groupId>" + a[2] + "</groupId>" + m.group(1) + "<artifactId>" + a[3] + "</artifactId>",
                        m -> a[0] + ":" + a[1] + " → " + a[2] + ":" + a[3],
                        "Remove any explicit <version> so Spring Boot dependency management selects the Jakarta EE version."));
                r.add(new Rule("MIG-DEP-G-" + a[3], CAT_DEPENDENCIES, "BLOCKER", named("build.gradle", "build.gradle.kts"),
                        Pattern.compile("(['\"])" + Pattern.quote(a[0] + ":" + a[1]) + "(:[^'\"]*)?(['\"])"),
                        m -> m.group(1) + a[2] + ":" + a[3] + m.group(3),
                        m -> a[0] + ":" + a[1] + " → " + a[2] + ":" + a[3] + " (explicit version removed)", ""));
            }
            r.add(new Rule("MIG-DEP-SPRINGFOX", CAT_DEPENDENCIES, "BLOCKER", named("pom.xml", "build.gradle", "build.gradle.kts"),
                    Pattern.compile("io\\.springfox"), null, m -> "Springfox is incompatible with Spring Boot 3+",
                    "Replace springfox with springdoc-openapi-starter-webmvc-ui and migrate @Api* annotations to @Operation/@Tag."));
        }

        // ---------------- javax → jakarta source namespace
        if (toBoot3Plus) {
            r.add(new Rule("MIG-JAKARTA-001", CAT_JAKARTA, "BLOCKER", ext(".java"), JAKARTA_PATTERN,
                    m -> "jakarta." + m.group(1), m -> "javax." + m.group(1) + " → jakarta." + m.group(1),
                    "Jakarta EE 9+ renamed the javax.* enterprise packages."));
            r.add(new Rule("MIG-JAKARTA-002", CAT_JAKARTA, "MAJOR", ext(".java"),
                    Pattern.compile("import\\s+javax\\.annotation\\.\\*;"), null, m -> "Wildcard import javax.annotation.* is ambiguous",
                    "Replace with explicit jakarta.annotation imports (javax.annotation.Nonnull etc. from JSR-305 stay unchanged)."));
            r.add(new Rule("MIG-JAKARTA-003", CAT_JAKARTA, "MAJOR", p -> p.getFileName().toString().endsWith(".xml") && p.toString().replace('\\', '/').contains("META-INF"),
                    Pattern.compile("http://xmlns\\.jcp\\.org/xml/ns/persistence|http://java\\.sun\\.com/xml/ns/persistence"), null,
                    m -> "persistence.xml uses the javax schema namespace", "Update to https://jakarta.ee/xml/ns/persistence and version 3.0+."));
        }

        // ---------------- Spring Security 6
        if (toBoot3Plus && fromBoot2) {
            r.add(new Rule("MIG-SEC-001", CAT_SECURITY, "MAJOR", ext(".java"), Pattern.compile("\\.(antMatchers|mvcMatchers|regexMatchers)\\("),
                    m -> ".requestMatchers(", m -> m.group(1) + "() was removed in Spring Security 6 → requestMatchers()",
                    "requestMatchers picks MVC or Ant matching automatically; review path patterns with trailing slashes."));
            r.add(new Rule("MIG-SEC-002", CAT_SECURITY, "MAJOR", ext(".java"), Pattern.compile("\\.authorizeRequests\\("),
                    m -> ".authorizeHttpRequests(", m -> "authorizeRequests() → authorizeHttpRequests()",
                    "authorizeHttpRequests applies to all dispatcher types by default; verify error and forward dispatches."));
            r.add(new Rule("MIG-SEC-003", CAT_SECURITY, "BLOCKER", ext(".java"), Pattern.compile("extends\\s+WebSecurityConfigurerAdapter"),
                    null, m -> "WebSecurityConfigurerAdapter was removed",
                    "Replace with a @Bean SecurityFilterChain filterChain(HttpSecurity http) and expose AuthenticationManager / UserDetailsService as beans."));
            r.add(new Rule("MIG-SEC-004", CAT_SECURITY, "MINOR", ext(".java"), Pattern.compile("EnableGlobalMethodSecurity"),
                    m -> "EnableMethodSecurity", m -> "@EnableGlobalMethodSecurity → @EnableMethodSecurity",
                    "prePostEnabled is true by default in @EnableMethodSecurity; remove the attribute if present."));
        }

        // ---------------- JDK APIs
        r.add(new Rule("MIG-JDK-001", CAT_JDK, "MINOR", ext(".java"),
                Pattern.compile("new\\s+(Integer|Long|Short|Byte|Double|Float|Boolean|Character)\\s*\\("),
                m -> m.group(1) + ".valueOf(", m -> "Boxed-primitive constructor new " + m.group(1) + "() is deprecated for removal",
                "valueOf() uses caches and is the supported factory."));
        r.add(new Rule("MIG-JDK-002", CAT_JDK, "MAJOR", ext(".java"), Pattern.compile("\\bsun\\.misc\\.|\\bcom\\.sun\\.image\\.|\\bsun\\.security\\."),
                null, m -> "Use of internal JDK API " + m.group(), "Internal APIs are strongly encapsulated since Java 17; use supported replacements."));
        r.add(new Rule("MIG-JDK-003", CAT_JDK, "MAJOR", ext(".java"), Pattern.compile("SecurityManager|System\\.getSecurityManager"),
                null, m -> "SecurityManager is deprecated for removal (JEP 411) and disabled in Java 24+", "Remove SecurityManager usage."));
        r.add(new Rule("MIG-JDK-004", CAT_JDK, "MINOR", ext(".java"), Pattern.compile("protected\\s+void\\s+finalize\\s*\\(\\)"),
                null, m -> "finalize() is deprecated for removal (JEP 421)", "Use try-with-resources or java.lang.ref.Cleaner."));
        r.add(new Rule("MIG-JDK-005", CAT_JDK, "MINOR", ext(".java"), Pattern.compile("Thread\\.currentThread\\(\\)\\.stop\\(|\\bthread\\.stop\\(\\)"),
                null, m -> "Thread.stop() throws UnsupportedOperationException since Java 20", "Use interruption."));

        // ---------------- configuration properties
        if (toBoot3Plus && fromBoot2) {
            for (String[] p : PROPERTY_RENAMES) {
                if (p[0].equals(p[1])) continue;
                r.add(new Rule("MIG-CFG-" + p[1], CAT_CONFIG, "MAJOR", APP_PROPERTIES,
                        Pattern.compile("(?m)^(\\s*)" + Pattern.quote(p[0])), m -> m.group(1) + p[1],
                        m -> "Property " + p[0] + "* renamed to " + p[1] + "*", "Add spring-boot-properties-migrator temporarily to find remaining renames at runtime."));
            }
            r.add(new Rule("MIG-CFG-SAML", CAT_CONFIG, "MAJOR", APP_PROPERTIES.or(APP_YAML), Pattern.compile("identityprovider"),
                    null, m -> "SAML 'identityprovider' properties were renamed to 'assertingparty'", ""));
            r.add(new Rule("MIG-CFG-YAML-REDIS", CAT_CONFIG, "MAJOR", APP_YAML, Pattern.compile("(?m)^\\s{2}redis:"),
                    null, m -> "spring.redis.* moved to spring.data.redis.* (YAML key needs manual nesting change)", ""));
            r.add(new Rule("MIG-CFG-SUFFIX", CAT_CONFIG, "MINOR", APP_PROPERTIES.or(APP_YAML), Pattern.compile("use-suffix-pattern|use-registered-suffix-pattern"),
                    null, m -> "Suffix pattern matching was removed in Spring Framework 6", ""));
            r.add(new Rule("MIG-CFG-SLASH", CAT_CONFIG, "INFO", ext(".java"), Pattern.compile("@(Get|Post|Put|Delete|Request)Mapping\\(\\s*\"[^\"]*/\"\\s*\\)"),
                    null, m -> "Trailing-slash matching is disabled by default in Spring Framework 6", "Map both paths explicitly or add a redirect filter."));
        }

        // ---------------- container
        r.add(new Rule("MIG-CNT-001", CAT_CONTAINER, "MAJOR", DOCKERFILE,
                Pattern.compile("(?m)^(\\s*FROM\\s+)((?:openjdk|adoptopenjdk|amazoncorretto|eclipse-temurin|adoptopenjdk/openjdk\\d+)(?::|/[\\w-]+:)(?:1\\.)?(\\d+)[^\\s]*)(.*)$"),
                m -> Integer.parseInt(m.group(3)) < t.javaVersion() ? m.group(1) + "eclipse-temurin:" + tj + "-jre" + m.group(4) : m.group(),
                m -> "Base image " + m.group(2) + " → eclipse-temurin:" + tj + "-jre", "openjdk images are deprecated; Temurin provides maintained JRE images."));
        r.add(new Rule("MIG-CNT-002", CAT_CONTAINER, "MAJOR", DOCKERFILE,
                Pattern.compile("(?m)^(\\s*FROM\\s+)(maven:[\\w.]*?-(?:jdk|openjdk|eclipse-temurin)-?(\\d+)[^\\s]*)(.*)$"),
                m -> Integer.parseInt(m.group(3)) < t.javaVersion() ? m.group(1) + "maven:3.9-eclipse-temurin-" + tj + m.group(4) : m.group(),
                m -> "Build image " + m.group(2) + " → maven:3.9-eclipse-temurin-" + tj, ""));

        // ---------------- Spring Boot 4 specifics (manual review)
        if (MavenVersion.major(tb) >= 4) {
            r.add(new Rule("MIG-B4-001", CAT_BOOT4, "MAJOR", ext(".java"), Pattern.compile("com\\.fasterxml\\.jackson\\.databind"),
                    null, m -> "Spring Boot 4 defaults to Jackson 3 (package tools.jackson.databind)",
                    "Migrate ObjectMapper customizations to Jackson 3 or keep Jackson 2 via the compatibility module."));
            r.add(new Rule("MIG-B4-002", CAT_BOOT4, "MAJOR", named("pom.xml", "build.gradle", "build.gradle.kts"), Pattern.compile("spring-boot-starter-undertow"),
                    null, m -> "Undertow support was removed in Spring Boot 4", "Switch to Tomcat or Jetty."));
            r.add(new Rule("MIG-B4-003", CAT_BOOT4, "INFO", named("pom.xml", "build.gradle", "build.gradle.kts"), Pattern.compile("spring-boot-starter-web(?![-\\w])"),
                    null, m -> "Spring Boot 4 modularized starters (spring-boot-starter-webmvc)", "Review the Spring Boot 4 migration guide for starter renames."));
        }
        return r;
    }

    private static boolean scannable(Path p) {
        String n = p.getFileName().toString();
        return n.endsWith(".java") || n.equals("pom.xml") || n.startsWith("build.gradle") || n.endsWith(".properties")
                || n.matches(".*\\.ya?ml") || n.startsWith("Dockerfile") || n.endsWith(".xml");
    }

    // =====================================================================================  assess

    public Assessment assess(Path root, Target target, Inventory inv) throws IOException {
        Assessment a = new Assessment();
        a.target = target;
        a.inventory = inv;
        List<List<String>> compat = CompatibilityMatrix.check(inv.detectedJava, inv.detectedSpringBoot, target.javaVersion(), target.springBootVersion());
        a.compatibilityErrors = compat.get(0);
        a.compatibilityWarnings = compat.get(1);
        List<Rule> rules = rules(target, inv);
        for (Path file : SourceFiles.walk(root, MigrationEngine::scannable, MAX_FILES)) {
            String content = SourceFiles.read(file);
            String rel = SourceFiles.relative(root, file);
            for (Rule rule : rules) {
                if (!rule.files().test(file)) continue;
                Matcher m = rule.pattern().matcher(content);
                while (m.find()) {
                    MatchResult mr = m.toMatchResult();
                    // version rules that are already at/above target produce no item
                    if (rule.auto() && rule.replacement().apply(mr).equals(mr.group())) continue;
                    a.items.add(new Item(rule.id(), rule.category(), rule.severity(), rel, lineOf(content, m.start()),
                            rule.message().apply(mr), rule.auto(), rule.guidance()));
                }
            }
        }
        if (inv.totalTestFiles == 0) {
            a.items.add(new Item("MIG-TEST-001", "VALIDATION", "MAJOR", null, null, "No automated tests detected",
                    false, "Add smoke and integration tests before migrating; validation will only prove that the build compiles."));
        }
        for (Item i : a.items) a.countsByCategory.merge(i.category(), 1, Integer::sum);
        a.autoFixableCount = (int) a.items.stream().filter(Item::autoFixable).count();
        a.manualCount = a.items.size() - a.autoFixableCount;
        risk(a, inv, target);
        return a;
    }

    private static void risk(Assessment a, Inventory inv, Target t) {
        double score = 0;
        int jakarta = a.countsByCategory.getOrDefault(CAT_JAKARTA, 0);
        if (jakarta > 0) { score += Math.min(25, jakarta * 0.5 + 5); a.riskFactors.add(jakarta + " javax→jakarta reference(s)"); }
        long security = a.items.stream().filter(i -> i.category().equals(CAT_SECURITY)).count();
        if (security > 0) { score += Math.min(20, security * 5); a.riskFactors.add(security + " Spring Security API change(s) — security-sensitive, needs approval"); }
        long blockersManual = a.items.stream().filter(i -> !i.autoFixable() && i.severity().equals("BLOCKER")).count();
        if (blockersManual > 0) { score += Math.min(25, blockersManual * 8); a.riskFactors.add(blockersManual + " blocker(s) requiring manual work"); }
        long manual = a.manualCount - blockersManual;
        if (manual > 0) { score += Math.min(15, manual * 2); a.riskFactors.add(manual + " other manual item(s)"); }
        int srcBoot = inv.detectedSpringBoot == null ? 0 : MavenVersion.major(inv.detectedSpringBoot);
        int jump = MavenVersion.major(t.springBootVersion()) - srcBoot;
        if (srcBoot > 0 && jump > 0) { score += 15 * jump; a.riskFactors.add("Spring Boot major version jump " + srcBoot + " → " + MavenVersion.major(t.springBootVersion())); }
        int srcJava = CompatibilityMatrix.javaMajor(inv.detectedJava);
        if (srcJava > 0 && t.javaVersion() - srcJava >= 8) { score += 10; a.riskFactors.add("Large Java jump " + srcJava + " → " + t.javaVersion()); }
        if (inv.totalTestFiles == 0) { score += 15; a.riskFactors.add("No automated tests to validate behaviour"); }
        if (!a.compatibilityErrors.isEmpty()) { score += 20; a.riskFactors.add("Unsupported target combination"); }
        a.riskScore = (int) Math.min(100, Math.round(score));
        a.riskLevel = a.riskScore < 25 ? "LOW" : a.riskScore < 55 ? "MEDIUM" : a.riskScore < 80 ? "HIGH" : "VERY HIGH";
    }

    private static int lineOf(String content, int offset) {
        int line = 1;
        for (int i = 0; i < offset && i < content.length(); i++) if (content.charAt(i) == '\n') line++;
        return line;
    }

    // =====================================================================================  plan

    public Plan plan(Assessment a) {
        Plan p = new Plan();
        p.migrationId = a.migrationId;
        int order = 1;
        p.steps.add(new PlanStep(order++, "Capture baseline", "BASELINE",
                "Record git branch/commit, working-tree status, current build/test result and dependency snapshot.",
                List.of("Clean working tree (or approved snapshot)"), List.of(), "Low",
                "Nothing changes in this step.", true));
        for (String cat : CATEGORIES) {
            List<Item> items = a.items.stream().filter(i -> i.category().equals(cat)).toList();
            if (items.isEmpty()) continue;
            Set<String> files = new LinkedHashSet<>();
            items.forEach(i -> { if (i.file() != null) files.add(i.file()); });
            long auto = items.stream().filter(Item::autoFixable).count();
            String complexity = items.size() > 40 || items.stream().anyMatch(i -> !i.autoFixable() && i.severity().equals("BLOCKER")) ? "High"
                    : items.size() > 10 ? "Medium" : "Low";
            p.steps.add(new PlanStep(order++, title(cat), cat,
                    items.size() + " item(s): " + auto + " automated, " + (items.size() - auto) + " manual. " + describe(cat),
                    prerequisites(cat), new ArrayList<>(files), complexity,
                    "Revert the generated commit, or restore the per-file backup captured before apply.", auto > 0));
        }
        p.steps.add(new PlanStep(order++, "Validate", "VALIDATION",
                "Run the configured build and test command in the workspace (e.g. mvn -B verify) and the configured static/security checks.",
                List.of("Validation command allowlisted in securetest.execution.allowed-commands"), List.of(), "Medium",
                "If validation fails, undo restores the rollback point.", true));
        p.steps.add(new PlanStep(order, "Review and commit", "REVIEW",
                "Review pass/fail, new warnings and unresolved manual items; commit only after approval.",
                List.of("Approver with APPROVE permission"), List.of(), "Low",
                "Undo reverts the generated commit; conflicts with later edits stop the undo and are reported.", false));
        p.rollbackStrategy = "Changes are applied on a dedicated branch (securetest/<change-set>) with per-file backups. "
                + "Undo uses git revert for committed changes or restores backups after verifying no later edits; conflicts stop the process.";
        return p;
    }

    private static String title(String cat) {
        return switch (cat) {
            case CAT_BUILD -> "Upgrade build configuration";
            case CAT_DEPENDENCIES -> "Replace incompatible dependencies";
            case CAT_JAKARTA -> "Migrate javax.* to jakarta.*";
            case CAT_SECURITY -> "Update Spring Security configuration";
            case CAT_JDK -> "Replace removed / deprecated JDK APIs";
            case CAT_CONFIG -> "Rename configuration properties";
            case CAT_CONTAINER -> "Update container images";
            case CAT_BOOT4 -> "Spring Boot 4 specific changes";
            default -> cat;
        };
    }

    private static String describe(String cat) {
        return switch (cat) {
            case CAT_BUILD -> "Bumps Spring Boot, Java level and wrapper versions.";
            case CAT_DEPENDENCIES -> "Swaps javax artifacts for Jakarta EE coordinates and flags incompatible libraries.";
            case CAT_JAKARTA -> "Coordinated namespace change across imports and fully-qualified references.";
            case CAT_SECURITY -> "Security-sensitive: requires human approval before apply.";
            case CAT_JDK -> "Removes reliance on APIs deprecated for removal.";
            case CAT_CONFIG -> "Renames properties in application*.properties; YAML items need manual nesting changes.";
            case CAT_CONTAINER -> "Moves to maintained Temurin images matching the target Java version.";
            default -> "";
        };
    }

    private static List<String> prerequisites(String cat) {
        return switch (cat) {
            case CAT_JAKARTA, CAT_DEPENDENCIES -> List.of("Build configuration upgraded");
            case CAT_SECURITY -> List.of("Jakarta migration", "Security owner approval");
            default -> List.of();
        };
    }

    // =====================================================================================  transform (in memory)

    /** Computes proposed file contents for the selected categories. Never writes. */
    public Map<String, String> transform(Path root, Target target, Inventory inv, Set<String> categories,
                                         Map<String, String> explanations) throws IOException {
        Map<String, String> out = new LinkedHashMap<>();
        List<Rule> rules = rules(target, inv).stream().filter(Rule::auto).filter(r -> categories.contains(r.category())).toList();
        for (Path file : SourceFiles.walk(root, MigrationEngine::scannable, MAX_FILES)) {
            String original = SourceFiles.read(file);
            String content = original;
            List<String> why = new ArrayList<>();
            for (Rule rule : rules) {
                if (!rule.files().test(file)) continue;
                Matcher m = rule.pattern().matcher(content);
                StringBuilder sb = new StringBuilder();
                boolean changed = false;
                while (m.find()) {
                    String rep = rule.replacement().apply(m.toMatchResult());
                    if (!rep.equals(m.group())) {
                        changed = true;
                        String msg = rule.message().apply(m.toMatchResult());
                        if (!why.contains(msg)) why.add(msg);
                    }
                    m.appendReplacement(sb, Matcher.quoteReplacement(rep));
                }
                m.appendTail(sb);
                if (changed) content = sb.toString();
            }
            if (!content.equals(original)) {
                String rel = SourceFiles.relative(root, file);
                out.put(rel, content);
                explanations.put(rel, String.join("; ", why.size() > 6 ? why.subList(0, 6) : why) + (why.size() > 6 ? "; …" : ""));
            }
        }
        return out;
    }

    public static String normalizeCategory(String c) {
        return c == null ? null : c.trim().toUpperCase(Locale.ROOT);
    }
}
