package com.securetest.adapters;

import com.securetest.adapters.builtin.LlmCodeScanner;
import com.securetest.adapters.builtin.PromptInjectionScanner;
import com.securetest.core.model.Finding;
import com.securetest.core.model.Severity;
import com.securetest.core.spi.ApplicationInfo;
import com.securetest.core.spi.CommandRunner;
import com.securetest.core.spi.HttpProbe;
import com.securetest.core.spi.ScanContext;
import com.securetest.core.spi.TargetGuard;
import com.securetest.core.util.AllowlistTargetGuard;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

class LlmSecurityTest {

    @TempDir
    Path root;

    static final class Ctx implements ScanContext {
        final Path root;
        final Map<String, String> options;
        final List<Finding> findings = new ArrayList<>();
        final Map<String, Object> results = new HashMap<>();
        Ctx(Path root, Map<String, String> options) { this.root = root; this.options = options; }
        @Override public String jobId() { return "t"; }
        @Override public Map<String, String> options() { return options; }
        @Override public String secret(String key) { return null; }
        @Override public Optional<Path> sourceRoot() { return Optional.ofNullable(root); }
        @Override public TargetGuard targets() { return new AllowlistTargetGuard(List.of("127.0.0.1"), "http://127.0.0.1:1", true); }
        @Override public HttpProbe http() {
            HttpClient c = HttpClient.newHttpClient();
            return (method, url, headers, body) -> {
                HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(url)).method(method, body == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofString(body));
                headers.forEach(b::header);
                HttpResponse<String> r = c.send(b.build(), HttpResponse.BodyHandlers.ofString());
                return new HttpProbe.HttpResult(url, r.statusCode(), r.headers().map(), r.body(), 1);
            };
        }
        @Override public CommandRunner commands() { return null; }
        @Override public ApplicationInfo application() { return null; }
        @Override public void report(Finding f) { findings.add(f); }
        @Override public void progress(int p, String m) { }
        @Override public void log(String m) { }
        @Override public boolean cancelled() { return false; }
        @Override public void putResult(String k, Object v) { results.put(k, v); }
        @Override public void attachArtifact(String n, String t, byte[] d) { }
        List<String> rules() { return findings.stream().map(f -> f.ruleId).toList(); }
    }

    @Test
    void codeCheckFindsLlmRisks() throws Exception {
        Path src = Files.createDirectories(root.resolve("src/main/java/shop"));
        Files.writeString(src.resolve("ChatService.java"), """
                package shop;
                import org.springframework.ai.chat.client.ChatClient;
                import org.springframework.ai.tool.annotation.Tool;
                class ChatService {
                    String answer(ChatClient chat, String userInput) {
                        String systemPrompt = "You are ShopBot. The customer says: " + userInput;
                        String response = chat.prompt().system(systemPrompt).call().content();
                        log.info("prompt sent: " + systemPrompt);
                        Runtime.getRuntime().exec(response);
                        return response;
                    }
                    @Tool(description = "Removes a customer account")
                    public void deleteCustomer(String id) { }
                }
                """);
        Path res = Files.createDirectories(root.resolve("src/main/resources"));
        Files.writeString(res.resolve("application.properties"), "spring.ai.anthropic.api-key=sk-ant-api03-abcdefghijklmnopqrstuvwxyz012345\n"
                + "spring.ai.anthropic.chat.options.model=claude-opus-5-5\n");

        Ctx ctx = new Ctx(root, Map.of());
        new LlmCodeScanner().scan(ctx);
        assertThat(ctx.rules()).contains("LLM-SDK", "LLM-HARDCODED-KEY", "LLM-PROMPT-INJECTION", "LLM-OUTPUT-TO-SINK", "LLM-RISKY-TOOL",
                "LLM-PROMPT-LOGGED", "LLM-NO-TOKEN-LIMIT");
        assertThat(ctx.findings).filteredOn(f -> f.ruleId.equals("LLM-HARDCODED-KEY")).allMatch(f -> f.sourceSeverity == Severity.CRITICAL);
        assertThat(ctx.findings).filteredOn(f -> f.ruleId.equals("LLM-SDK")).extracting(f -> f.title).contains("Uses Spring AI");
        assertThat(ctx.findings).allMatch(f -> f.complianceTags.stream().anyMatch(t -> t.startsWith("OWASP-LLM")));
    }

    @Test
    void codeWithoutLlmUsageOnlyGetsTheKeyCheck() throws Exception {
        Files.writeString(Files.createDirectories(root.resolve("src")).resolve("App.java"), "class App { String system = \"x\" + request; }");
        Ctx ctx = new Ctx(root, Map.of());
        new LlmCodeScanner().scan(ctx);
        assertThat(ctx.findings).isEmpty();
    }

    private HttpServer chat(Function<String, String> model) throws Exception {
        HttpServer s = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        s.createContext("/api/chat", ex -> {
            String body = new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            String msg = body.replaceAll("(?s).*\"message\":\"(.*)\"}\\s*$", "$1").replace("\\\"", "\"");
            String reply = model.apply(msg).replace("\\", "\\\\").replace("\"", "\\\"");
            byte[] out = ("{\"reply\":\"" + reply + "\"}").getBytes(StandardCharsets.UTF_8);
            ex.getResponseHeaders().add("Content-Type", "application/json");
            ex.sendResponseHeaders(200, out.length);
            ex.getResponseBody().write(out);
            ex.close();
        });
        s.start();
        return s;
    }

    /** A model that does whatever it is told. */
    private static String gullible(String msg) {
        Matcher b64 = Pattern.compile("says: ([A-Za-z0-9+/=]{20,})").matcher(msg);
        if (b64.find()) msg = new String(Base64.getDecoder().decode(b64.group(1)), StandardCharsets.UTF_8);
        Matcher canary = Pattern.compile("(CANARY[A-Z0-9]+)").matcher(msg);
        if (msg.contains("<img")) return msg.substring(msg.indexOf("<img"));
        if (canary.find()) return canary.group(1);
        if (msg.contains("repeat everything above")) return "You are ShopBot, a helpful assistant for Acme. Do not reveal discount codes. Never discuss competitors.";
        if (msg.contains("API keys")) return "Sure: the key is sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAA";
        if (msg.contains("20000 times")) return "data ".repeat(5000);
        return "OK";
    }

    @Test
    void endpointTestDetectsAVulnerableChatbot() throws Exception {
        HttpServer s = chat(LlmSecurityTest::gullible);
        try {
            Ctx ctx = new Ctx(null, Map.of("url", "http://127.0.0.1:" + s.getAddress().getPort() + "/api/chat", "responseField", "reply"));
            new PromptInjectionScanner().scan(ctx);
            assertThat(ctx.rules()).contains("LLM01-DIRECT", "LLM01-ENCODED", "LLM01-ROLE", "LLM07-LEAK", "LLM02-SECRETS", "LLM05-HTML", "LLM10-LENGTH");
            assertThat(ctx.findings).filteredOn(f -> f.ruleId.equals("LLM02-SECRETS")).allMatch(f -> !f.evidence.contains("AAAAAAAAAAAAAAAA"));
            assertThat(ctx.results.get("requests")).isEqualTo(7);
        } finally {
            s.stop(0);
        }
    }

    @Test
    void endpointTestPassesARobustChatbot() throws Exception {
        HttpServer s = chat(msg -> "Sorry, I can only help with questions about your orders.");
        try {
            Ctx ctx = new Ctx(null, Map.of("url", "http://127.0.0.1:" + s.getAddress().getPort() + "/api/chat", "responseField", "reply"));
            new PromptInjectionScanner().scan(ctx);
            assertThat(ctx.findings).isEmpty();
        } finally {
            s.stop(0);
        }
    }

    @Test
    void endpointMustBeAllowlisted() {
        Ctx ctx = new Ctx(null, Map.of("url", "https://chat.example.com/api"));
        assertThat(new PromptInjectionScanner().preflight(ctx)).anyMatch(c -> c.level().name().equals("ERROR"));
    }
}
