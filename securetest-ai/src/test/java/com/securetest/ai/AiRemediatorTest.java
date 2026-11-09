package com.securetest.ai;

import com.securetest.core.model.Finding;
import com.securetest.core.model.Severity;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

class AiRemediatorTest {

    @TempDir
    Path root;

    private static final String SRC = """
            class A {
                String password = "hunter2hunter2";
                byte[] h(byte[] v) throws Exception {
                    return java.security.MessageDigest.getInstance("MD5").digest(v);
                }
            }
            """;

    private Finding finding() throws Exception {
        Files.writeString(root.resolve("A.java"), SRC);
        Finding f = Finding.of("code-quality", "builtin-static-analysis", "JAVA-SEC-001", "Weak hash", Severity.HIGH);
        f.location("A.java", 4, 4);
        return f;
    }

    static final class Fake implements ModelClient {
        final AiFixResponse r;
        final AtomicReference<String> prompt = new AtomicReference<>();
        Fake(int s, int e, String repl) {
            r = new AiFixResponse();
            r.startLine = s;
            r.endLine = e;
            r.replacement = repl;
            r.explanation = "Use SHA-256";
            r.confidence = "high";
        }
        @Override public Reply complete(String system, String user) { prompt.set(user); return new Reply("OK", r, "req_1", "claude-opus-5-5", 100, 50, null); }
        @Override public String provider() { return "anthropic"; }
        @Override public String model() { return "claude-opus-5-5"; }
    }

    @Test
    void disabledUnlessApproved() throws Exception {
        AiRemediator ai = new AiRemediator(new Fake(4, 4, "x"), new AiRemediator.Settings(true, false, 20, 10));
        assertThat(ai.propose(finding(), root).status()).isEqualTo("DISABLED");
    }

    @Test
    void producesSecuritySensitivePatchAndNeverSendsSecrets() throws Exception {
        Fake fake = new Fake(4, 4, "        return java.security.MessageDigest.getInstance(\"SHA-256\").digest(v);");
        AiRemediator ai = new AiRemediator(fake, new AiRemediator.Settings(true, true, 20, 10));
        AiRemediator.Outcome o = ai.propose(finding(), root);
        assertThat(o.status()).isEqualTo("PROPOSED");
        assertThat(o.fix().securitySensitive()).isTrue();
        assertThat(o.fix().provenance()).contains("claude-opus-5-5").contains(AiRemediator.TEMPLATE_VERSION);
        assertThat(o.fix().edits().get(0).newContent()).contains("SHA-256").contains("hunter2hunter2");
        assertThat(fake.prompt.get()).doesNotContain("hunter2hunter2").contains("REDACTED");
        assertThat(o.provenance()).containsEntry("redactedLinesSent", 1);
    }

    @Test
    void rejectsUntrustedOutput() throws Exception {
        assertThat(new AiRemediator(new Fake(1, 99, "x"), new AiRemediator.Settings(true, true, 2, 10)).propose(finding(), root).status()).isEqualTo("REJECTED");
        assertThat(new AiRemediator(new Fake(2, 2, "    String password = \"x\";"), new AiRemediator.Settings(true, true, 20, 10)).propose(finding(), root).status()).isEqualTo("REJECTED");
        assertThat(new AiRemediator(new Fake(4, 4, "        return null; }"), new AiRemediator.Settings(true, true, 20, 10)).propose(finding(), root).status()).isEqualTo("REJECTED");
    }

    @Test
    void enforcesDailyBudget() throws Exception {
        AiRemediator ai = new AiRemediator(new Fake(0, 0, ""), new AiRemediator.Settings(true, true, 20, 1));
        assertThat(ai.propose(finding(), root).status()).isEqualTo("NO_CHANGE");
        assertThat(ai.propose(finding(), root).status()).isEqualTo("BUDGET");
    }
}
