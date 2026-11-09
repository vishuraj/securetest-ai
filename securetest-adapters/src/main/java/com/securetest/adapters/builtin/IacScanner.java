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
import com.securetest.core.util.Hashing;
import com.securetest.core.util.SourceFiles;
import com.securetest.core.util.UnifiedDiff;

import java.nio.file.Path;
import java.util.List;
import java.util.Locale;
import java.util.function.Predicate;

import static com.securetest.adapters.support.PatternRule.rule;

/** Dockerfile, Kubernetes/Helm, Docker Compose and Terraform misconfiguration checks (SRS 5.11). */
public class IacScanner implements Scanner {

    public static final String ID = "builtin-iac";

    private static final Predicate<Path> DOCKERFILE = p -> p.getFileName().toString().toLowerCase(Locale.ROOT).startsWith("dockerfile")
            || p.getFileName().toString().toLowerCase(Locale.ROOT).endsWith(".dockerfile");
    private static final Predicate<Path> YAML = ScanSupport.extensions("yml", "yaml");
    private static final Predicate<Path> COMPOSE = p -> p.getFileName().toString().toLowerCase(Locale.ROOT).matches("(docker-)?compose.*\\.ya?ml");
    private static final Predicate<Path> K8S = YAML.and(COMPOSE.negate()).and(p -> !p.getFileName().toString().startsWith("application"));
    private static final Predicate<Path> TF = ScanSupport.extensions("tf");

    static final List<PatternRule> RULES = List.of(
            // ---- Dockerfile
            rule("IAC-DOCKER-001", "Base image uses 'latest' or no tag", Severity.MEDIUM).files(DOCKERFILE).confidence(Confidence.HIGH)
                    .regex("(?i)^\\s*FROM\\s+(?!scratch)([\\w./-]+)(:latest)?(\\s+AS\\s+\\w+)?\\s*$")
                    .description("Untagged/latest images are not reproducible and can silently pull vulnerable versions.")
                    .remediation("Pin an explicit version tag, ideally with a digest (image:1.2.3@sha256:...).")
                    .tags("CIS-DOCKER-4.2", "OWASP-A06").category("Container").build(),
            rule("IAC-DOCKER-002", "Container runs as root", Severity.HIGH).files(DOCKERFILE).confidence(Confidence.HIGH)
                    .regex("(?i)^\\s*USER\\s+(root|0)(\\s|:|$)")
                    .description("Processes running as root inside a container make container escapes far more damaging.")
                    .remediation("Create an unprivileged user and switch to it: RUN useradd -r app && USER app")
                    .tags("CIS-DOCKER-4.1", "CIS-K8S-5.2.6").category("Container").fix("(?i)USER\\s+(root|0)", "USER 10001").build(),
            rule("IAC-DOCKER-003", "ADD with remote URL", Severity.MEDIUM).files(DOCKERFILE).confidence(Confidence.HIGH)
                    .regex("(?i)^\\s*ADD\\s+https?://")
                    .description("ADD downloads remote content without integrity verification.")
                    .remediation("Use RUN curl with checksum verification, or COPY a verified artifact.")
                    .tags("CIS-DOCKER-4.9").category("Container").build(),
            rule("IAC-DOCKER-004", "Secret passed through ENV/ARG", Severity.HIGH).files(DOCKERFILE).confidence(Confidence.MEDIUM)
                    .regex("(?i)^\\s*(ENV|ARG)\\s+\\w*(PASSWORD|SECRET|TOKEN|API_?KEY|ACCESS_?KEY)\\w*[ =]\\s*\\S+")
                    .description("ENV/ARG values are stored in image layers and visible via docker history.")
                    .remediation("Use BuildKit secrets (RUN --mount=type=secret) or runtime secret injection.")
                    .tags("CIS-DOCKER-4.10", "CIS-SECRETS", "OWASP-A07").category("Container").build(),
            rule("IAC-DOCKER-005", "Piping remote script into a shell", Severity.MEDIUM).files(DOCKERFILE).confidence(Confidence.HIGH)
                    .regex("(curl|wget)[^|\\n]*\\|\\s*(ba|z)?sh")
                    .description("Executing downloaded scripts without verification is a supply-chain risk.")
                    .remediation("Download, verify a checksum/signature, then execute.").tags("CIS-DOCKER-4.9", "OWASP-A08").category("Container").build(),
            // ---- Kubernetes / Helm
            rule("IAC-K8S-001", "Privileged container", Severity.HIGH).files(K8S).confidence(Confidence.HIGH)
                    .regex("^\\s*privileged:\\s*true")
                    .description("Privileged containers have full access to the host kernel and devices.")
                    .remediation("Remove privileged: true; grant only the specific capabilities required.")
                    .tags("CIS-K8S-5.2.1", "NSA-K8S").category("Kubernetes").fix("privileged:\\s*true", "privileged: false").build(),
            rule("IAC-K8S-002", "Privilege escalation allowed", Severity.HIGH).files(K8S).confidence(Confidence.HIGH)
                    .regex("^\\s*allowPrivilegeEscalation:\\s*true")
                    .description("Allows setuid binaries to gain more privileges than the parent process.")
                    .remediation("Set allowPrivilegeEscalation: false.")
                    .tags("CIS-K8S-5.2.5").category("Kubernetes").fix("allowPrivilegeEscalation:\\s*true", "allowPrivilegeEscalation: false").build(),
            rule("IAC-K8S-003", "Host namespace shared", Severity.HIGH).files(K8S).confidence(Confidence.HIGH)
                    .regex("^\\s*(hostNetwork|hostPID|hostIPC):\\s*true")
                    .description("Sharing host namespaces breaks pod isolation.")
                    .remediation("Remove hostNetwork/hostPID/hostIPC unless strictly required (e.g. node agents).")
                    .tags("CIS-K8S-5.2.2", "CIS-K8S-5.2.3", "CIS-K8S-5.2.4").category("Kubernetes").build(),
            rule("IAC-K8S-004", "Container runs as root user", Severity.HIGH).files(K8S).confidence(Confidence.HIGH)
                    .regex("^\\s*(runAsUser:\\s*0\\b|runAsNonRoot:\\s*false)")
                    .description("The pod explicitly runs as root.")
                    .remediation("Set runAsNonRoot: true and a non-zero runAsUser.")
                    .tags("CIS-K8S-5.2.6").category("Kubernetes").build(),
            rule("IAC-K8S-005", "Image without pinned tag", Severity.MEDIUM).files(K8S).confidence(Confidence.HIGH)
                    .regex("^\\s*-?\\s*image:\\s*[\"']?[\\w./-]+(:latest)?[\"']?\\s*$")
                    .description("Untagged or latest images make deployments non-reproducible.")
                    .remediation("Pin image versions (and preferably digests).").tags("CIS-K8S-5.5.1").category("Kubernetes").build(),
            rule("IAC-K8S-006", "Dangerous Linux capability added", Severity.HIGH).files(K8S).confidence(Confidence.HIGH)
                    .regex("^\\s*-\\s*[\"']?(SYS_ADMIN|NET_ADMIN|ALL|SYS_PTRACE|SYS_MODULE)[\"']?\\s*$")
                    .description("These capabilities effectively grant host-level control.")
                    .remediation("Drop ALL capabilities and add back only what is needed.").tags("CIS-K8S-5.2.8").category("Kubernetes").build(),
            rule("IAC-K8S-007", "hostPath volume", Severity.MEDIUM).files(K8S).confidence(Confidence.HIGH)
                    .regex("^\\s*hostPath:")
                    .description("hostPath mounts expose the node file system to the pod.")
                    .remediation("Use persistent volumes or emptyDir instead.").tags("CIS-K8S-5.2.12").category("Kubernetes").build(),
            rule("IAC-K8S-008", "Kubernetes Secret stored in repository", Severity.MEDIUM).files(K8S).confidence(Confidence.MEDIUM)
                    .multiline("kind:\\s*Secret\\b.*?\\n(data|stringData):")
                    .description("Secret manifests contain base64-encoded (not encrypted) credentials.")
                    .remediation("Use Sealed Secrets, External Secrets Operator or SOPS-encrypted manifests.")
                    .tags("CIS-K8S-5.4.1", "CIS-SECRETS").category("Kubernetes").build(),
            // ---- Compose
            rule("IAC-COMPOSE-001", "Privileged service in Compose", Severity.HIGH).files(COMPOSE).confidence(Confidence.HIGH)
                    .regex("^\\s*privileged:\\s*true").description("Privileged containers have full host access.")
                    .remediation("Remove privileged: true.").tags("CIS-DOCKER-5.4").category("Container").fix("privileged:\\s*true", "privileged: false").build(),
            rule("IAC-COMPOSE-002", "Host network mode", Severity.MEDIUM).files(COMPOSE).confidence(Confidence.HIGH)
                    .regex("^\\s*network_mode:\\s*[\"']?host").description("Host networking removes network isolation.")
                    .remediation("Use bridge networks and publish only required ports.").tags("CIS-DOCKER-5.9").category("Container").build(),
            rule("IAC-COMPOSE-003", "Docker socket mounted", Severity.CRITICAL).files(COMPOSE.or(K8S)).confidence(Confidence.HIGH)
                    .regex("/var/run/docker\\.sock").description("Mounting the Docker socket grants root on the host.")
                    .remediation("Avoid mounting the socket; use rootless alternatives (Kaniko, BuildKit).").tags("CIS-DOCKER-5.31").category("Container").build(),
            // ---- Terraform
            rule("IAC-TF-001", "Public storage bucket ACL", Severity.HIGH).files(TF).confidence(Confidence.HIGH)
                    .regex("acl\\s*=\\s*\"public-read(-write)?\"").description("Bucket objects are readable by anyone on the internet.")
                    .remediation("Use private ACLs and S3 Block Public Access.").tags("CIS-AWS-2.1.5", "GDPR-32", "PCI-1.3").category("Cloud storage").build(),
            rule("IAC-TF-002", "Ingress open to the internet", Severity.MEDIUM).files(TF).confidence(Confidence.MEDIUM)
                    .regex("cidr_blocks\\s*=\\s*\\[[^\\]]*\"0\\.0\\.0\\.0/0\"").description("A security group rule allows traffic from any address.")
                    .remediation("Restrict sources to known CIDRs; never expose SSH/RDP/databases publicly.").tags("CIS-AWS-5.2", "PCI-1.3").category("Cloud network").build(),
            rule("IAC-TF-003", "Encryption disabled", Severity.HIGH).files(TF).confidence(Confidence.HIGH)
                    .regex("(encrypted|storage_encrypted|enable_encryption)\\s*=\\s*false").description("Data at rest is not encrypted.")
                    .remediation("Enable encryption with a managed KMS key.").tags("CIS-AWS-2.2.1", "PCI-3.5", "GDPR-32", "ISO27001-A.8.24").category("Cloud storage")
                    .fix("=\\s*false", "= true").build(),
            rule("IAC-TF-004", "Database publicly accessible", Severity.HIGH).files(TF).confidence(Confidence.HIGH)
                    .regex("publicly_accessible\\s*=\\s*true").description("The managed database has a public endpoint.")
                    .remediation("Set publicly_accessible = false and use private subnets.").tags("CIS-AWS-2.3.3", "PCI-1.3").category("Cloud database")
                    .fix("publicly_accessible\\s*=\\s*true", "publicly_accessible = false").build()
    );

    @Override
    public ScannerDescriptor descriptor() {
        return ScannerDescriptor.builder(ID, ModuleCatalog.CLOUD_SECURITY, "Container & IaC configuration")
                .purpose("Checks Dockerfiles, Kubernetes manifests / Helm templates, Docker Compose files and Terraform for insecure "
                        + "settings (root users, privileged pods, public buckets, open security groups, missing encryption…).")
                .access("Read access to the source workspace. No cloud credentials are used.")
                .requiresSourceRoot()
                .field(FieldSpec.number("maxFiles", "Maximum files", 5000, 1, 50000, ""))
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
        List<Path> files = SourceFiles.walk(root, DOCKERFILE.or(YAML).or(TF), ctx.intOption("maxFiles", 5000, 1, 50000));
        // only consider YAML that looks like Kubernetes or Compose
        List<Path> relevant = new java.util.ArrayList<>();
        for (Path f : files) {
            if (DOCKERFILE.test(f) || TF.test(f) || COMPOSE.test(f)) { relevant.add(f); continue; }
            String c = SourceFiles.read(f);
            if (c.contains("apiVersion:") && c.contains("kind:")) relevant.add(f);
        }
        ctx.progress(5, relevant.size() + " infrastructure files");
        ScanSupport.runRules(ctx, root, relevant, RULES, ModuleCatalog.CLOUD_SECURITY, ID);
        // file-level checks
        for (Path f : relevant) {
            String c = SourceFiles.read(f);
            List<String> lines = UnifiedDiff.lines(c);
            if (DOCKERFILE.test(f)) {
                if (!java.util.regex.Pattern.compile("(?im)^\\s*USER\\s+\\S+").matcher(c).find()) {
                    report(ctx, root, f, lines, "IAC-DOCKER-006", "Dockerfile never switches to a non-root user", Severity.HIGH,
                            "Without a USER instruction the container runs as root.", "Add 'USER 10001' (or a named user) before CMD/ENTRYPOINT.", "CIS-DOCKER-4.1");
                }
                if (!c.toUpperCase(Locale.ROOT).contains("HEALTHCHECK")) {
                    report(ctx, root, f, lines, "IAC-DOCKER-007", "Dockerfile has no HEALTHCHECK", Severity.LOW,
                            "Orchestrators cannot detect a hung container.", "Add HEALTHCHECK or rely on Kubernetes probes.", "CIS-DOCKER-4.6");
                }
            } else if (!COMPOSE.test(f) && !TF.test(f) && c.contains("containers:")) {
                if (!c.contains("runAsNonRoot: true")) {
                    report(ctx, root, f, lines, "IAC-K8S-009", "Pod does not enforce runAsNonRoot", Severity.MEDIUM,
                            "Containers may run as root if the image does not set a user.", "Add securityContext.runAsNonRoot: true.", "CIS-K8S-5.2.6");
                }
                if (!c.contains("limits:")) {
                    report(ctx, root, f, lines, "IAC-K8S-010", "No resource limits defined", Severity.LOW,
                            "A runaway container can starve other workloads on the node.", "Set resources.requests and resources.limits for CPU and memory.", "CIS-K8S-5.7");
                }
                if (!c.contains("readOnlyRootFilesystem: true")) {
                    report(ctx, root, f, lines, "IAC-K8S-011", "Root filesystem is writable", Severity.LOW,
                            "A writable root filesystem lets attackers persist tools.", "Set securityContext.readOnlyRootFilesystem: true.", "NSA-K8S");
                }
            }
        }
    }

    private static void report(ScanContext ctx, Path root, Path file, List<String> lines, String rule, String title, Severity s,
                               String desc, String fix, String tag) throws Exception {
        Finding f = Finding.of(ModuleCatalog.CLOUD_SECURITY, ID, rule, title, s).description(desc).remediation(fix)
                .category("Configuration").confidence(Confidence.MEDIUM).tags(tag);
        SourceFiles.locate(f, root, file, lines, 1, 1, Hashing.sha256(file));
        f.asset = f.filePath;
        ctx.report(f);
    }
}
