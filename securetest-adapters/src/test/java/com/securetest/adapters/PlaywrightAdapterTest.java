package com.securetest.adapters;

import com.securetest.adapters.external.PlaywrightAdapter;
import com.securetest.adapters.support.ScanSupport;
import com.securetest.core.model.Finding;
import com.securetest.core.model.Severity;
import com.securetest.core.spi.ApplicationInfo;
import com.securetest.core.spi.CommandRunner;
import com.securetest.core.spi.HttpProbe;
import com.securetest.core.spi.ScanContext;
import com.securetest.core.spi.TargetGuard;
import com.securetest.core.util.AllowlistTargetGuard;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

class PlaywrightAdapterTest {

    @TempDir
    Path root;

    static final class Ctx implements ScanContext {
        final Path root;
        final List<Finding> findings = new ArrayList<>();
        final Map<String, Object> results = new HashMap<>();
        final Map<String, byte[]> artifacts = new HashMap<>();
        Ctx(Path root) { this.root = root; }
        @Override public String jobId() { return "t"; }
        @Override public Map<String, String> options() { return Map.of(); }
        @Override public String secret(String key) { return null; }
        @Override public Optional<Path> sourceRoot() { return Optional.of(root); }
        @Override public TargetGuard targets() { return new AllowlistTargetGuard(List.of("self"), "http://localhost:8080", true); }
        @Override public HttpProbe http() { return null; }
        @Override public CommandRunner commands() { return null; }
        @Override public ApplicationInfo application() { return null; }
        @Override public void report(Finding f) { findings.add(f); }
        @Override public void progress(int p, String m) { }
        @Override public void log(String m) { }
        @Override public boolean cancelled() { return false; }
        @Override public void putResult(String k, Object v) { results.put(k, v); }
        @Override public void attachArtifact(String n, String t, byte[] d) { artifacts.put(n, d); }
    }

    @Test
    @SuppressWarnings("unchecked")
    void importsMatrixFailuresFlakesAndScreenshots() throws Exception {
        Path tests = Files.createDirectories(root.resolve("e2e/tests"));
        Files.writeString(tests.resolve("login.spec.ts"), "import { test } from '@playwright/test';\ntest('login', async () => {});\n");
        Path shot = root.resolve("e2e/test-results/shot.png");
        Files.createDirectories(shot.getParent());
        Files.write(shot, new byte[] {(byte) 0x89, 'P', 'N', 'G'});
        String json = """
                {"stats":{"expected":2,"unexpected":1,"flaky":1,"skipped":0,"duration":4200},
                 "suites":[{"title":"login.spec.ts","specs":[],"suites":[{"title":"auth","suites":[],"specs":[
                   {"title":"login works","file":"tests/login.spec.ts","line":2,"tests":[
                     {"projectName":"chromium","status":"expected","results":[{"status":"passed","duration":800}]},
                     {"projectName":"firefox","status":"unexpected","results":[{"status":"failed","duration":900,
                        "error":{"message":"\\u001b[31mExpected: visible\\u001b[39m password=hunter22","stack":"at login.spec.ts:2"},
                        "attachments":[{"name":"screenshot","contentType":"image/png","path":"test-results/shot.png"}]}]},
                     {"projectName":"webkit","status":"flaky","results":[{"status":"failed","duration":700,"error":{"message":"timeout"}},{"status":"passed","duration":650}]}
                   ]}]}]}]}
                """;
        Ctx ctx = new Ctx(root);
        Method m = PlaywrightAdapter.class.getDeclaredMethod("importReport", ScanContext.class, com.fasterxml.jackson.databind.JsonNode.class, Path.class, Path.class);
        m.setAccessible(true);
        m.invoke(null, ctx, ScanSupport.JSON.readTree(json), root.resolve("e2e"), root);

        assertThat(ctx.findings).hasSize(2);
        Finding failed = ctx.findings.stream().filter(f -> f.ruleId.equals("PW-FAILED")).findFirst().orElseThrow();
        assertThat(failed.sourceSeverity).isEqualTo(Severity.HIGH);
        assertThat(failed.title).contains("[firefox]");
        assertThat(failed.description).doesNotContain("\u001b").doesNotContain("hunter22");
        assertThat(failed.filePath).isEqualTo("e2e/tests/login.spec.ts");
        assertThat(failed.attributes).containsKey("screenshot");
        assertThat(ctx.artifacts).hasSize(1);
        assertThat(ctx.findings).anyMatch(f -> f.ruleId.equals("PW-FLAKY") && f.sourceSeverity == Severity.MEDIUM);
        List<Map<String, Object>> matrix = (List<Map<String, Object>>) ctx.results.get("browserMatrix");
        assertThat(matrix).extracting(r -> r.get("project")).containsExactly("chromium", "firefox", "webkit");
    }
}
