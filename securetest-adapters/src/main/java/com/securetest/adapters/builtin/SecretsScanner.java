package com.securetest.adapters.builtin;

import com.securetest.adapters.support.PatternRule;
import com.securetest.adapters.support.ScanSupport;
import com.securetest.core.model.Enums.Confidence;
import com.securetest.core.model.ModuleCatalog;
import com.securetest.core.model.Severity;
import com.securetest.core.spi.FieldSpec;
import com.securetest.core.spi.PreflightCheck;
import com.securetest.core.spi.ScanContext;
import com.securetest.core.spi.Scanner;
import com.securetest.core.spi.ScannerDescriptor;
import com.securetest.core.util.SourceFiles;

import java.nio.file.Path;
import java.util.List;
import java.util.Set;
import java.util.function.Predicate;

import static com.securetest.adapters.support.PatternRule.rule;

/** Detects committed secrets. Matched values are always redacted in snippets, evidence and reports. */
public class SecretsScanner implements Scanner {

    public static final String ID = "builtin-secrets";

    private static final Set<String> TEXT_EXT = Set.of("java", "kt", "groovy", "scala", "js", "ts", "py", "go", "rb", "php", "cs",
            "properties", "yml", "yaml", "json", "xml", "env", "conf", "cfg", "ini", "toml", "tf", "tfvars", "sh", "ps1", "bat",
            "gradle", "sql", "md", "txt", "pem", "key", "npmrc", "dockerfile", "");

    private static final Predicate<Path> TEXT = p -> {
        String n = p.getFileName().toString().toLowerCase();
        return TEXT_EXT.contains(SourceFiles.extension(p)) || n.startsWith("dockerfile") || n.startsWith(".env");
    };
    private static final Predicate<Path> CONFIG = p -> {
        String e = SourceFiles.extension(p);
        return e.equals("properties") || e.equals("yml") || e.equals("yaml") || e.equals("env") || p.getFileName().toString().startsWith(".env");
    };

    static final List<PatternRule> RULES = List.of(
            rule("SECRET-001", "AWS access key ID", Severity.HIGH).files(TEXT).confidence(Confidence.HIGH)
                    .regex("\\b(AKIA|ASIA)[0-9A-Z]{16}\\b")
                    .description("An AWS access key ID is committed. Combined with its secret it grants API access to the AWS account.")
                    .remediation("Deactivate and rotate the key in IAM, remove it from the repository history, and use IAM roles or a secret manager.")
                    .tags("OWASP-A07", "CIS-SECRETS", "ISO27001-A.8.24", "SOC2-CC6.1", "PCI-8.3").category("Secrets").build(),
            rule("SECRET-002", "AWS secret access key", Severity.CRITICAL).files(TEXT).confidence(Confidence.HIGH)
                    .regexIgnoreCase("aws_?secret_?access_?key\\s*[:=]\\s*['\"]?[A-Za-z0-9/+=]{40}")
                    .description("An AWS secret access key is committed.")
                    .remediation("Rotate immediately, purge from history (git filter-repo) and check CloudTrail for misuse.")
                    .tags("OWASP-A07", "CIS-SECRETS", "SOC2-CC6.1", "PCI-8.3").category("Secrets").build(),
            rule("SECRET-003", "Private key", Severity.CRITICAL).files(TEXT).confidence(Confidence.HIGH)
                    .regex("-----BEGIN (RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----")
                    .description("A private key is stored in the repository.")
                    .remediation("Revoke/replace the key pair and keep keys in a keystore or secret manager.")
                    .tags("OWASP-A02", "CIS-SECRETS", "PCI-3.6", "ISO27001-A.8.24").category("Secrets").build(),
            rule("SECRET-004", "GitHub token", Severity.HIGH).files(TEXT).confidence(Confidence.HIGH)
                    .regex("\\bgh[pousr]_[A-Za-z0-9]{36,}\\b")
                    .description("A GitHub personal access or app token is committed.")
                    .remediation("Revoke the token in GitHub settings and use repository/organization secrets.")
                    .tags("OWASP-A07", "CIS-SECRETS").category("Secrets").build(),
            rule("SECRET-005", "Slack token or webhook", Severity.MEDIUM).files(TEXT).confidence(Confidence.HIGH)
                    .regex("xox[baprs]-[A-Za-z0-9-]{10,}|hooks\\.slack\\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+")
                    .description("A Slack token or incoming webhook URL is committed.")
                    .remediation("Regenerate the token/webhook and load it from configuration.")
                    .tags("CIS-SECRETS").category("Secrets").build(),
            rule("SECRET-006", "Stripe live secret key", Severity.CRITICAL).files(TEXT).confidence(Confidence.HIGH)
                    .regex("\\b(sk|rk)_live_[0-9a-zA-Z]{20,}")
                    .description("A live Stripe key grants access to payment operations.")
                    .remediation("Roll the key in the Stripe dashboard immediately.")
                    .tags("PCI-3.6", "PCI-8.3", "CIS-SECRETS").category("Secrets").build(),
            rule("SECRET-007", "Google API key", Severity.MEDIUM).files(TEXT).confidence(Confidence.HIGH)
                    .regex("\\bAIza[0-9A-Za-z_-]{35}\\b")
                    .description("A Google API key is committed.")
                    .remediation("Restrict or regenerate the key in Google Cloud console.").tags("CIS-SECRETS").category("Secrets").build(),
            rule("SECRET-008", "Password in configuration file", Severity.HIGH).files(CONFIG).confidence(Confidence.MEDIUM)
                    .regexIgnoreCase("^\\s*[\\w.-]*(password|passwd|secret|client-secret|api-key|apikey|token)[\\w.-]*\\s*[:=]\\s*(?!\\$\\{)(?!\\s*$)(?![\"']?\\s*[\"']?\\s*$)[\"']?[^\\s\"'#$]{4,}")
                    .description("A credential value is set in plain text in configuration.")
                    .remediation("Reference an environment variable (${DB_PASSWORD}) or a secret manager instead of a literal value.")
                    .tags("OWASP-A07", "ASVS-2.10", "CIS-SECRETS", "PCI-8.3", "SOC2-CC6.1").category("Secrets").build(),
            rule("SECRET-009", "Credentials embedded in connection URL", Severity.HIGH).files(TEXT).confidence(Confidence.HIGH)
                    .regex("\\b(jdbc:[a-z]+|mongodb(\\+srv)?|redis|amqps?|postgres(ql)?|mysql)://[^/\\s:@'\"]+:[^@\\s'\"$]{3,}@")
                    .description("A connection string contains a username and password.")
                    .remediation("Move credentials to separate properties resolved from a secret store.")
                    .tags("OWASP-A07", "CIS-SECRETS", "PCI-8.3").category("Secrets").build(),
            rule("SECRET-010", "JSON Web Token", Severity.MEDIUM).files(TEXT).confidence(Confidence.MEDIUM)
                    .regex("\\beyJ[A-Za-z0-9_-]{10,}\\.eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}")
                    .description("A signed token is committed and may still be valid.")
                    .remediation("Remove the token; rotate the signing key if it was a long-lived credential.").tags("CIS-SECRETS").category("Secrets").build()
    );

    @Override
    public ScannerDescriptor descriptor() {
        return ScannerDescriptor.builder(ID, ModuleCatalog.VULNERABILITY, "Secrets detection")
                .purpose("Searches the source workspace for committed credentials: cloud keys, private keys, tokens and plain-text passwords. "
                        + "Values are redacted everywhere they are displayed.")
                .access("Read access to text files in the source workspace (build output and VCS folders are skipped).")
                .requiresSourceRoot()
                .field(FieldSpec.number("maxFiles", "Maximum files to scan", 20000, 1, 100000, ""))
                .build();
    }

    @Override
    public List<PreflightCheck> preflight(ScanContext ctx) {
        return List.of(ctx.sourceRoot().isPresent()
                ? PreflightCheck.ok("Source workspace", ctx.sourceRoot().get().toString())
                : PreflightCheck.error("Source workspace", "No source workspace configured."));
    }

    @Override
    public void scan(ScanContext ctx) throws Exception {
        Path root = ScanSupport.requireSource(ctx);
        List<Path> files = SourceFiles.walk(root, TEXT, ctx.intOption("maxFiles", 20000, 1, 100000));
        ctx.progress(5, "Scanning " + files.size() + " files");
        int n = ScanSupport.runRules(ctx, root, files, RULES, ModuleCatalog.VULNERABILITY, ID);
        ctx.log("Potential secrets: " + n);
    }
}
