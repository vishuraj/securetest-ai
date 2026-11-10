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

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Predicate;
import java.util.regex.Pattern;

import static com.securetest.adapters.support.PatternRule.rule;

/**
 * Static checks for applications that use large language models, mapped to the OWASP Top 10 for LLM Applications (2025):
 * an inventory of LLM SDKs in use, hard-coded model API keys, user input in system prompts, model output reaching
 * dangerous sinks, risky tool functions, prompts and completions in logs, and missing token limits.
 */
public class LlmCodeScanner implements Scanner {

    public static final String ID = "llm-code";

    private static final Set<String> CODE = Set.of("java", "kt", "kts", "groovy", "scala", "js", "mjs", "ts", "tsx", "jsx", "py");
    private static final Set<String> CONFIG = Set.of("properties", "yml", "yaml", "env", "json");
    private static final Predicate<Path> CODE_FILES = p -> CODE.contains(SourceFiles.extension(p));
    private static final Predicate<Path> CONFIG_FILES = p -> CONFIG.contains(SourceFiles.extension(p)) || p.getFileName().toString().startsWith(".env");
    private static final Predicate<Path> ALL = CODE_FILES.or(CONFIG_FILES);

    /** SDK import / dependency markers, for the inventory and to decide whether LLM rules apply to a file. */
    private static final Map<String, Pattern> SDKS = new LinkedHashMap<>();
    static {
        SDKS.put("Spring AI", Pattern.compile("org\\.springframework\\.ai\\b"));
        SDKS.put("LangChain4j", Pattern.compile("dev\\.langchain4j\\b"));
        SDKS.put("Anthropic SDK", Pattern.compile("com\\.anthropic\\b|@anthropic-ai/sdk|\\bimport anthropic\\b|from anthropic import"));
        SDKS.put("OpenAI SDK", Pattern.compile("com\\.openai\\b|\\bfrom openai import|\\bimport openai\\b|from ['\"]openai['\"]"));
        SDKS.put("Azure OpenAI", Pattern.compile("com\\.azure\\.ai\\.openai\\b"));
        SDKS.put("Google Vertex AI / Gemini", Pattern.compile("com\\.google\\.cloud\\.vertexai\\b|com\\.google\\.genai\\b"));
        SDKS.put("LangChain", Pattern.compile("from langchain|['\"]langchain['\"]|@langchain/"));
        SDKS.put("Ollama", Pattern.compile("ollama", Pattern.CASE_INSENSITIVE));
    }
    private static final Pattern ANY_SDK = Pattern.compile(String.join("|", SDKS.values().stream().map(Pattern::pattern).toList()), Pattern.CASE_INSENSITIVE);

    private static final String LLM = "OWASP-LLM";

    static final List<PatternRule> RULES = List.of(
            rule("LLM-HARDCODED-KEY", "Model provider API key in source or configuration", Severity.CRITICAL)
                    .files(ALL).regex("(sk-ant-[A-Za-z0-9_-]{20,}|sk-proj-[A-Za-z0-9_-]{20,}|\\bsk-[A-Za-z0-9]{32,})")
                    .confidence(Confidence.HIGH).category("LLM02: Sensitive information disclosure").tags(LLM + "-LLM02", "OWASP-A07")
                    .description("A key for an LLM provider is committed. Anyone with the code can use (and bill) the account.")
                    .remediation("Revoke the key at the provider, then read it from the environment or a secret manager (e.g. ${ANTHROPIC_API_KEY}).").build(),
            rule("LLM-PROMPT-INJECTION", "User input concatenated into a system prompt or instructions", Severity.HIGH)
                    .files(CODE_FILES)
                    .regexIgnoreCase("(system|instruction|preamble)[A-Za-z_]*\\s*(\\(|=|\\+=|:)\\s*[^;]*(\\+|\\$\\{|%s|f\")\\s*[^;]*(request|input|query|param|body|user|message|prompt)")
                    .category("LLM01: Prompt injection").tags(LLM + "-LLM01")
                    .description("Text from the user is mixed into the system prompt, so a user can rewrite the model's instructions.")
                    .remediation("Keep the system prompt constant. Pass user text only as a user message, and treat it as data, not instructions.").build(),
            rule("LLM-OUTPUT-TO-SINK", "Model output reaches a command, query or HTML sink", Severity.HIGH)
                    .files(CODE_FILES)
                    .regexIgnoreCase("(exec\\s*\\(|ProcessBuilder\\s*\\(|createNativeQuery\\s*\\(|jdbcTemplate\\.(execute|update|query)\\s*\\(|\\beval\\s*\\(|innerHTML\\s*=|dangerouslySetInnerHTML|subprocess\\.|os\\.system\\s*\\()[^;]*(completion|response|answer|reply|content|output|generation|chatResponse|llm)")
                    .category("LLM05: Improper output handling").tags(LLM + "-LLM05", "OWASP-A03")
                    .description("Model output is untrusted input. Running it as a command or query, or inserting it as HTML, lets a prompt injection reach your system or users.")
                    .remediation("Never execute or render model output directly. Parse it into a fixed structure, validate it, use parameterized queries and escape HTML.").build(),
            rule("LLM-RISKY-TOOL", "Model-callable tool performs a destructive or financial action", Severity.MEDIUM)
                    .files(CODE_FILES)
                    .multiline("@Tool\\b[^\\n]*\\n(\\s*@[^\\n]*\\n)*\\s*(public\\s+|private\\s+|protected\\s+)?[\\w<>\\[\\], ]+\\s+(delete|remove|drop|purge|exec|execute|run|transfer|pay|refund|send|email|grant|revoke|update)\\w*\\s*\\(")
                    .category("LLM06: Excessive agency").tags(LLM + "-LLM06")
                    .description("The model can call this function on its own. A prompt injection could make it delete data, move money or send messages.")
                    .remediation("Give tools the least privilege they need, require human confirmation for destructive or financial actions, and check the caller's own permissions inside the tool.").build(),
            rule("LLM-PROMPT-LOGGED", "Prompts or model responses written to logs", Severity.MEDIUM)
                    .files(CODE_FILES)
                    .regexIgnoreCase("(log|logger|console)\\.(info|debug|warn|log|trace)\\s*\\([^;]*(prompt|completion|chatResponse|messages|llmResponse)")
                    .confidence(Confidence.LOW).category("LLM02: Sensitive information disclosure").tags(LLM + "-LLM02", "GDPR")
                    .description("Prompts and answers often contain personal data, secrets and the system prompt; logging them copies that data into log storage.")
                    .remediation("Log metadata (model, token counts, latency, request id) instead, or redact before logging.").build(),
            rule("LLM-SYSTEM-PROMPT-SECRET", "Secret or internal detail placed in a system prompt", Severity.HIGH)
                    .files(ALL).regexIgnoreCase("(system|instruction)[A-Za-z_]*\\s*[=:(][^\\n]*(password|api[_ -]?key|secret|token|connection string)\\s*(is|=|:)")
                    .category("LLM07: System prompt leakage").tags(LLM + "-LLM07")
                    .description("System prompts can be extracted by users. Anything in them should be treated as public.")
                    .remediation("Keep credentials and internal rules out of prompts; enforce access control in code, not in the prompt.").build()
    );

    @Override
    public ScannerDescriptor descriptor() {
        return ScannerDescriptor.builder(ID, ModuleCatalog.AI_SECURITY, "LLM application code check")
                .purpose("Lists the LLM SDKs your code uses and checks for the OWASP Top 10 for LLM Applications risks that are visible in code: "
                        + "hard-coded model keys, user input in system prompts, model output reaching commands/queries/HTML, risky tools, "
                        + "prompts in logs, secrets in prompts and missing token limits.")
                .access("Reads files in the source workspace. Nothing is sent anywhere.")
                .requiresSourceRoot()
                .duration("Seconds to a minute")
                .field(FieldSpec.number("maxFiles", "Maximum files", 20000, 100, 100000, ""))
                .build();
    }

    @Override
    public List<PreflightCheck> preflight(ScanContext ctx) {
        return List.of(ctx.sourceRoot().isPresent() ? PreflightCheck.ok("Workspace", ctx.sourceRoot().get().toString())
                : PreflightCheck.error("Workspace", "Set securetest.workspace.source-root"));
    }

    @Override
    public void scan(ScanContext ctx) throws Exception {
        Path root = ScanSupport.requireSource(ctx);
        List<Path> files = SourceFiles.walk(root, ALL, ctx.intOption("maxFiles", 20000, 100, 100000));
        ctx.progress(5, files.size() + " files");
        // only files that use an LLM SDK (plus config and build files) are checked by the prompt rules
        List<Path> llmFiles = new ArrayList<>();
        Map<String, List<String>> inventory = new LinkedHashMap<>();
        boolean maxTokens = false;
        boolean modelConfigured = false;
        for (Path f : files) {
            ctx.checkCancelled();
            String content;
            try {
                content = SourceFiles.read(f);
            } catch (java.io.IOException e) {
                continue;
            }
            boolean uses = false;
            for (Map.Entry<String, Pattern> e : SDKS.entrySet()) {
                if (e.getValue().matcher(content).find() && !(e.getKey().equals("Ollama") && !CODE_FILES.test(f) && !content.contains("spring.ai"))) {
                    inventory.computeIfAbsent(e.getKey(), k -> new ArrayList<>()).add(SourceFiles.relative(root, f));
                    uses = true;
                }
            }
            if (CONFIG_FILES.test(f)) {
                if (content.matches("(?s).*spring\\.ai\\.[\\w.-]*(chat\\.options\\.model|model)\\s*[:=].*") || content.matches("(?s).*\\bmodel:\\s*\\S+.*spring.*ai.*")) modelConfigured = true;
                if (content.matches("(?is).*max[-_]?(completion[-_])?tokens.*")) maxTokens = true;
            } else if (content.matches("(?is).*max[_]?tokens.*|.*maxTokens.*")) {
                maxTokens = true;
            }
            if (uses || CONFIG_FILES.test(f)) llmFiles.add(f);
        }
        ctx.putResult("sdks", inventory);
        for (Map.Entry<String, List<String>> e : inventory.entrySet()) {
            ctx.report(Finding.of(ModuleCatalog.AI_SECURITY, ID, "LLM-SDK", "Uses " + e.getKey(), Severity.INFO)
                    .category("LLM03: Supply chain").asset(e.getKey()).confidence(Confidence.HIGH)
                    .description("Found in " + e.getValue().size() + " file(s), e.g. " + String.join(", ", e.getValue().stream().limit(5).toList()) + ".")
                    .remediation("Keep an inventory of models and SDK versions; review the provider's data-retention terms.")
                    .tags(LLM + "-LLM03"));
        }
        if (inventory.isEmpty()) {
            ctx.log("No LLM SDK found; only hard-coded model keys are checked.");
            ScanSupport.runRules(ctx, root, files, RULES.subList(0, 1), ModuleCatalog.AI_SECURITY, ID);
            ctx.progress(100, "No LLM usage found");
            return;
        }
        int n = ScanSupport.runRules(ctx, root, llmFiles, RULES, ModuleCatalog.AI_SECURITY, ID);
        if (!maxTokens) {
            ctx.report(Finding.of(ModuleCatalog.AI_SECURITY, ID, "LLM-NO-TOKEN-LIMIT", "No output token limit found for model calls", Severity.MEDIUM)
                    .category("LLM10: Unbounded consumption").confidence(Confidence.LOW).tags(LLM + "-LLM10")
                    .description("No max-tokens setting was found" + (modelConfigured ? " although a model is configured" : "")
                            + ". Without limits (and per-user rate limits) a user can drive up cost or exhaust capacity.")
                    .remediation("Set max tokens per call (e.g. spring.ai.anthropic.chat.options.max-tokens) and rate-limit model use per user."));
            n++;
        }
        ctx.progress(100, n + " finding(s)");
    }
}
