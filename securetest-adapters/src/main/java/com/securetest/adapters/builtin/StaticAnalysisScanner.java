package com.securetest.adapters.builtin;

import com.securetest.adapters.support.PatternRule;
import com.securetest.adapters.support.ScanSupport;
import com.securetest.core.model.Enums.Confidence;
import com.securetest.core.model.Finding;
import com.securetest.core.model.ModuleCatalog;
import com.securetest.core.model.Severity;
import com.securetest.core.spi.FieldSpec;
import com.securetest.core.spi.PreflightCheck;
import com.securetest.core.spi.ScanContext;
import com.securetest.core.spi.Scanner;
import com.securetest.core.spi.ScannerDescriptor;
import com.securetest.core.util.SourceFiles;
import com.securetest.core.util.UnifiedDiff;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static com.securetest.adapters.support.PatternRule.rule;

/**
 * Lightweight built-in static analysis for Java sources: security anti-patterns, reliability
 * smells and maintainability metrics (complexity, size, duplication). It is not a replacement
 * for SonarQube/SpotBugs/Semgrep, which are supported through adapters (SRS 5.5).
 */
public class StaticAnalysisScanner implements Scanner {

    public static final String ID = "builtin-static-analysis";
    private static final java.util.function.Predicate<Path> JAVA = ScanSupport.extensions("java");
    private static final java.util.function.Predicate<Path> MAIN_JAVA = p -> JAVA.test(p) && !p.toString().replace('\\', '/').contains("/src/test/");

    static final List<PatternRule> RULES = List.of(
            rule("JAVA-SEC-001", "Weak hash algorithm (MD5/SHA-1)", Severity.HIGH).files(MAIN_JAVA).confidence(Confidence.HIGH)
                    .regex("MessageDigest\\.getInstance\\(\\s*\"(MD5|MD2|SHA-?1)\"")
                    .description("MD5 and SHA-1 are broken for collision resistance and must not protect integrity or passwords.")
                    .remediation("Use SHA-256 or stronger for integrity; use BCrypt/SCrypt/Argon2 (e.g. Spring Security PasswordEncoder) for passwords.")
                    .tags("OWASP-A02", "ASVS-6.2", "PCI-3.6", "CWE-328").category("Cryptography")
                    .fix("\"(MD5|MD2|SHA-?1)\"", "\"SHA-256\"").build(),
            rule("JAVA-SEC-002", "Predictable random number generator", Severity.MEDIUM).files(MAIN_JAVA).confidence(Confidence.LOW)
                    .regex("new\\s+Random\\s*\\(")
                    .description("java.util.Random is predictable. If the value is used for tokens, IDs, passwords or keys it can be guessed.")
                    .remediation("Use java.security.SecureRandom for any security-relevant randomness.")
                    .tags("OWASP-A02", "ASVS-6.3", "CWE-330").category("Cryptography")
                    .fix("new\\s+Random\\s*\\(", "new java.security.SecureRandom(").build(),
            rule("JAVA-SEC-003", "SQL built by string concatenation", Severity.HIGH).files(MAIN_JAVA).confidence(Confidence.MEDIUM)
                    .regex("(createQuery|createNativeQuery|executeQuery|executeUpdate|prepareStatement|queryForObject|queryForList|queryForMap|\\.query|\\.update|\\.execute)\\s*\\(\\s*\"[^\"]*\"\\s*\\+")
                    .description("Concatenating input into SQL/JPQL enables injection attacks.")
                    .remediation("Use bind parameters (PreparedStatement '?', JPA :named parameters, JdbcTemplate args) instead of string concatenation.")
                    .tags("OWASP-A03", "ASVS-5.3", "PCI-6.2.4", "CWE-89").category("Injection").build(),
            rule("JAVA-SEC-004", "Hard-coded credential", Severity.HIGH).files(MAIN_JAVA).confidence(Confidence.MEDIUM)
                    .regexIgnoreCase("(password|passwd|pwd|secret|api_?key|token)\\w*\\s*=\\s*\"[^\"$]{4,}\"")
                    .description("Credentials in source code leak through repositories, builds and logs and cannot be rotated safely.")
                    .remediation("Load secrets from environment variables or a secret manager (Spring Cloud Vault, AWS Secrets Manager, Azure Key Vault).")
                    .tags("OWASP-A07", "ASVS-2.10", "CIS-SECRETS", "CWE-798").category("Secrets").build(),
            rule("JAVA-SEC-005", "CSRF protection disabled", Severity.MEDIUM).files(MAIN_JAVA).confidence(Confidence.HIGH)
                    .regex("csrf\\(\\)\\s*\\.disable\\(\\)|csrf\\(\\s*(AbstractHttpConfigurer::disable|\\w+\\s*->\\s*\\w+\\.disable\\(\\))")
                    .description("Disabling CSRF is only safe for purely stateless APIs that never use cookies for authentication.")
                    .remediation("Keep CSRF enabled for browser sessions; if the API is stateless with bearer tokens, document why it is disabled.")
                    .tags("OWASP-A01", "ASVS-4.2", "CWE-352").category("Access control").build(),
            rule("JAVA-SEC-006", "Permissive CORS configuration", Severity.MEDIUM).files(MAIN_JAVA).confidence(Confidence.HIGH)
                    .regex("@CrossOrigin\\s*(\\(\\s*\\)|$|\\(\\s*(origins\\s*=\\s*)?\"\\*\")|allowedOrigins\\(\\s*\"\\*\"\\s*\\)|addAllowedOrigin\\(\\s*\"\\*\"\\s*\\)")
                    .description("Allowing every origin lets any website call the API from a victim's browser.")
                    .remediation("Restrict CORS to an explicit list of trusted origins.")
                    .tags("OWASP-A05", "ASVS-14.5", "CWE-942").category("Configuration").build(),
            rule("JAVA-SEC-007", "TLS certificate or hostname verification disabled", Severity.HIGH).files(MAIN_JAVA).confidence(Confidence.HIGH)
                    .regex("NoopHostnameVerifier|ALLOW_ALL_HOSTNAME_VERIFIER|setHostnameVerifier\\(\\s*\\([^)]*\\)\\s*->\\s*true|InsecureTrustManagerFactory|TrustAllStrategy|checkServerTrusted\\([^)]*\\)\\s*(throws[^{]*)?\\{\\s*\\}")
                    .description("Disabling certificate validation allows man-in-the-middle interception of TLS traffic.")
                    .remediation("Use the default TrustManager and HostnameVerifier; add private CAs to a truststore instead.")
                    .tags("OWASP-A02", "ASVS-9.2", "PCI-4.2", "CWE-295").category("Cryptography").build(),
            rule("JAVA-SEC-008", "Unsafe Java deserialization", Severity.MEDIUM).files(MAIN_JAVA).confidence(Confidence.LOW)
                    .regex("new\\s+ObjectInputStream\\s*\\(|enableDefaultTyping\\(|activateDefaultTyping\\(|XMLDecoder\\s*\\(")
                    .description("Deserializing untrusted data can lead to remote code execution through gadget chains.")
                    .remediation("Avoid native serialization for untrusted input; use JSON with explicit types and an ObjectInputFilter allowlist.")
                    .tags("OWASP-A08", "ASVS-5.5", "CWE-502").category("Injection").build(),
            rule("JAVA-SEC-009", "Weak cipher or ECB mode", Severity.HIGH).files(MAIN_JAVA).confidence(Confidence.HIGH)
                    .regex("Cipher\\.getInstance\\(\\s*\"(DES|DESede|RC4|Blowfish|AES)(/ECB[^\"]*)?\"\\s*\\)")
                    .description("DES/3DES/RC4 are weak; AES without a mode defaults to ECB, which leaks plaintext patterns.")
                    .remediation("Use AES/GCM/NoPadding with a random 12-byte IV per message.")
                    .tags("OWASP-A02", "ASVS-6.2", "PCI-3.6", "CWE-327").category("Cryptography").build(),
            rule("JAVA-SEC-010", "XML parser may allow XXE", Severity.MEDIUM).files(MAIN_JAVA).confidence(Confidence.LOW)
                    .regex("(DocumentBuilderFactory|SAXParserFactory|XMLInputFactory)\\.newInstance\\(\\)")
                    .description("Default XML parser settings can resolve external entities (XXE), exposing files or enabling SSRF.")
                    .remediation("Set FEATURE_SECURE_PROCESSING and disallow-doctype-decl, or disable external entities explicitly.")
                    .tags("OWASP-A05", "ASVS-5.5", "CWE-611").category("Injection").build(),
            rule("JAVA-SEC-011", "Sensitive data written to logs", Severity.MEDIUM).files(MAIN_JAVA).confidence(Confidence.LOW)
                    .regexIgnoreCase("\\b(log|logger)\\.(trace|debug|info|warn|error)\\([^;]*(password|passwd|secret|token|creditcard|ssn)")
                    .description("Logging credentials or personal data exposes them to everyone with log access.")
                    .remediation("Remove the value from the log statement or mask it.")
                    .tags("OWASP-A09", "ASVS-7.1", "GDPR-32", "PCI-3.3", "CWE-532").category("Logging").build(),
            rule("JAVA-SEC-012", "File path built from request parameter", Severity.HIGH).files(MAIN_JAVA).confidence(Confidence.LOW)
                    .regex("new\\s+File(InputStream|Reader)?\\s*\\([^;]*getParameter\\(|Paths?\\.(get|of)\\([^;]*getParameter\\(")
                    .description("Building file paths from user input enables path traversal (../) to read arbitrary files.")
                    .remediation("Resolve against a fixed base directory, normalize, and verify the result stays inside it.")
                    .tags("OWASP-A01", "ASVS-12.3", "CWE-22").category("Injection").build(),
            rule("JAVA-REL-001", "Empty catch block", Severity.MEDIUM).files(JAVA).confidence(Confidence.HIGH)
                    .multiline("catch\\s*\\([^)]*\\)\\s*\\{\\s*\\}")
                    .description("Swallowed exceptions hide failures and make incidents hard to diagnose.")
                    .remediation("Log the exception with context, rethrow, or document why ignoring it is safe.")
                    .tags("ASVS-7.4", "CWE-390").category("Reliability").build(),
            rule("JAVA-REL-002", "printStackTrace() used for error handling", Severity.LOW).files(MAIN_JAVA).confidence(Confidence.HIGH)
                    .regex("\\.printStackTrace\\(\\s*\\)")
                    .description("Stack traces printed to stderr bypass the logging framework and can leak internals.")
                    .remediation("Use the application logger: log.error(\"context\", e).")
                    .tags("OWASP-A09", "CWE-209").category("Reliability").build(),
            rule("JAVA-REL-003", "Catching Throwable", Severity.LOW).files(MAIN_JAVA).confidence(Confidence.HIGH)
                    .regex("catch\\s*\\(\\s*(final\\s+)?Throwable\\b")
                    .description("Catching Throwable also catches Errors such as OutOfMemoryError that should not be handled.")
                    .remediation("Catch specific exceptions or Exception.").category("Reliability").build(),
            rule("JAVA-MNT-001", "Console output instead of logger", Severity.LOW).files(MAIN_JAVA).confidence(Confidence.HIGH)
                    .regex("System\\.(out|err)\\.print")
                    .description("System.out/err cannot be filtered, correlated or shipped by the logging pipeline.")
                    .remediation("Use SLF4J: private static final Logger log = LoggerFactory.getLogger(...).").category("Maintainability").build(),
            rule("JAVA-MNT-002", "TODO / FIXME left in code", Severity.INFO).files(JAVA).confidence(Confidence.HIGH)
                    .regex("//\\s*(TODO|FIXME|XXX)\\b")
                    .description("Unresolved work items.")
                    .remediation("Track the work in the issue tracker and remove the marker.").category("Maintainability").build()
    );

    @Override
    public ScannerDescriptor descriptor() {
        return ScannerDescriptor.builder(ID, ModuleCatalog.CODE_QUALITY, "Built-in static analysis")
                .purpose("Reads Java source files in the workspace and flags security anti-patterns, reliability smells, complexity and duplication. "
                        + "Read-only: no files are changed and nothing leaves this machine.")
                .access("Read access to the configured source workspace.")
                .requiresSourceRoot()
                .duration("Seconds to a few minutes depending on repository size")
                .resources("Low CPU, single background thread")
                .field(FieldSpec.number("maxFiles", "Maximum files to analyze", 5000, 1, 50000, "Stops after this many files."))
                .field(FieldSpec.number("complexityThreshold", "Method complexity threshold", 15, 5, 100,
                        "Methods with more decision points than this are reported."))
                .field(FieldSpec.flag("includeTests", "Include test sources in metrics", false, "Security rules ignore src/test regardless."))
                .build();
    }

    @Override
    public List<PreflightCheck> preflight(ScanContext ctx) {
        List<PreflightCheck> out = new ArrayList<>();
        out.add(ctx.sourceRoot().isPresent()
                ? PreflightCheck.ok("Source workspace", ctx.sourceRoot().get().toString())
                : PreflightCheck.error("Source workspace", "No source workspace configured (securetest.workspace.source-root)."));
        return out;
    }

    @Override
    public void scan(ScanContext ctx) throws Exception {
        Path root = ScanSupport.requireSource(ctx);
        boolean includeTests = ctx.boolOption("includeTests", false);
        List<Path> files = SourceFiles.walk(root, JAVA, ctx.intOption("maxFiles", 5000, 1, 50000));
        ctx.log("Analyzing " + files.size() + " Java files under " + root);
        ctx.progress(5, "Found " + files.size() + " Java files");
        int count = ScanSupport.runRules(ctx, root, files, RULES, ModuleCatalog.CODE_QUALITY, ID);
        metrics(ctx, root, includeTests ? files : files.stream().filter(MAIN_JAVA).toList());
        ctx.log("Rule findings: " + count);
    }

    private static final Pattern METHOD = Pattern.compile(
            "(?m)^\\s*(public|protected|private|static|final|synchronized|abstract|default|\\s)*[\\w<>\\[\\],.? ]+\\s+(\\w+)\\s*\\([^;{)]*\\)\\s*(throws[^{]+)?\\{");
    private static final Pattern DECISION = Pattern.compile("\\b(if|for|while|case|catch)\\b|&&|\\|\\||\\?[^:]+:");

    private void metrics(ScanContext ctx, Path root, List<Path> files) throws Exception {
        int threshold = ctx.intOption("complexityThreshold", 15, 5, 100);
        long loc = 0;
        long comments = 0;
        long methods = 0;
        long complexitySum = 0;
        Map<String, List<String>> windows = new HashMap<>();
        for (Path file : files) {
            ctx.checkCancelled();
            String content = SourceFiles.read(file);
            List<String> lines = UnifiedDiff.lines(content);
            String rel = SourceFiles.relative(root, file);
            for (String l : lines) {
                String t = l.trim();
                if (t.isEmpty()) continue;
                if (t.startsWith("//") || t.startsWith("*") || t.startsWith("/*")) comments++;
                else loc++;
            }
            if (lines.size() > 1000) {
                Finding f = Finding.of(ModuleCatalog.CODE_QUALITY, ID, "JAVA-MNT-003", "Very large source file (" + lines.size() + " lines)", Severity.LOW)
                        .description("Large classes usually have too many responsibilities and are harder to test.")
                        .remediation("Split the class by responsibility.").category("Maintainability").confidence(Confidence.HIGH);
                ctx.report(SourceFiles.locate(f, root, file, lines, 1, 1, null));
            }
            // method complexity
            Matcher m = METHOD.matcher(content);
            while (m.find()) {
                String name = m.group(2);
                if (List.of("if", "for", "while", "switch", "catch", "synchronized", "return", "new").contains(name)) continue;
                int bodyStart = m.end();
                int depth = 1;
                int i = bodyStart;
                while (i < content.length() && depth > 0) {
                    char c = content.charAt(i++);
                    if (c == '{') depth++;
                    else if (c == '}') depth--;
                }
                String body = content.substring(bodyStart, Math.min(i, content.length()));
                Matcher d = DECISION.matcher(body);
                int cc = 1;
                while (d.find()) cc++;
                methods++;
                complexitySum += cc;
                if (cc > threshold) {
                    int line = ScanSupport.lineOf(content, m.start());
                    Finding f = Finding.of(ModuleCatalog.CODE_QUALITY, ID, "JAVA-MNT-004", "High cyclomatic complexity in " + name + "() (" + cc + ")", cc > threshold * 2 ? Severity.MEDIUM : Severity.LOW)
                            .description("Complex methods are error-prone and hard to test. Threshold: " + threshold + ".")
                            .remediation("Extract smaller methods, replace conditionals with polymorphism or lookup tables.")
                            .category("Maintainability").confidence(Confidence.HIGH).attr("complexity", String.valueOf(cc));
                    ctx.report(SourceFiles.locate(f, root, file, lines, line, line, null));
                }
            }
            // duplication: normalized 6-line windows
            List<String> norm = new ArrayList<>();
            List<Integer> lineNos = new ArrayList<>();
            for (int k = 0; k < lines.size(); k++) {
                String t = lines.get(k).trim();
                if (t.isEmpty() || t.startsWith("import ") || t.startsWith("//") || t.startsWith("*") || t.equals("}") || t.equals("{")) continue;
                norm.add(t.replaceAll("\\s+", " "));
                lineNos.add(k + 1);
            }
            for (int k = 0; k + 6 <= norm.size(); k++) {
                String key = String.join("\n", norm.subList(k, k + 6));
                windows.computeIfAbsent(key, x -> new ArrayList<>()).add(rel + ":" + lineNos.get(k));
            }
        }
        java.util.Set<String> duplicatedLines = new java.util.HashSet<>();
        int blocks = 0;
        for (Map.Entry<String, List<String>> e : windows.entrySet()) {
            if (e.getValue().size() > 1) {
                blocks++;
                for (String loc0 : e.getValue()) {
                    String[] parts = loc0.split(":");
                    int start = Integer.parseInt(parts[parts.length - 1]);
                    for (int k = 0; k < 6; k++) duplicatedLines.add(parts[0] + ":" + (start + k));
                }
            }
        }
        double dupPct = loc == 0 ? 0 : Math.min(100.0, 100.0 * duplicatedLines.size() / loc);
        Map<String, Object> metrics = new LinkedHashMap<>();
        metrics.put("files", files.size());
        metrics.put("linesOfCode", loc);
        metrics.put("commentLines", comments);
        metrics.put("methods", methods);
        metrics.put("averageComplexity", methods == 0 ? 0 : Math.round(10.0 * complexitySum / methods) / 10.0);
        metrics.put("duplicatedBlocks", blocks);
        metrics.put("duplicationPercent", Math.round(dupPct * 10) / 10.0);
        ctx.putResult("metrics", metrics);
        if (dupPct > 5) {
            Finding f = Finding.of(ModuleCatalog.CODE_QUALITY, ID, "JAVA-MNT-005",
                    String.format("Code duplication %.1f%% exceeds 5%%", dupPct), Severity.LOW)
                    .description(blocks + " duplicated 6-line blocks were found across the workspace.")
                    .remediation("Extract shared logic into reusable methods or classes.").category("Maintainability").confidence(Confidence.MEDIUM)
                    .asset(root.getFileName() == null ? root.toString() : root.getFileName().toString());
            ctx.report(f);
        }
    }
}
