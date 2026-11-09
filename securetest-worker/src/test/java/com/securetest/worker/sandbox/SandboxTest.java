package com.securetest.worker.sandbox;

import com.securetest.adapters.builtin.HttpSecurityScanner;
import com.securetest.adapters.builtin.SecretsScanner;
import com.securetest.worker.WorkerProperties;
import com.securetest.worker.WorkerScanners;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class SandboxTest {

    @Test
    void catalogServesOnlyTargetBasedScanners() {
        var catalog = new WorkerScanners.Catalog(List.of(new HttpSecurityScanner(), new SecretsScanner()), List.of());
        assertThat(catalog.scanners()).containsOnlyKeys(HttpSecurityScanner.ID);
        var restricted = new WorkerScanners.Catalog(List.of(new HttpSecurityScanner()), List.of("something-else"));
        assertThat(restricted.scanners()).isEmpty();
    }

    @Test
    void sandboxRefusesTargetsOutsideTheWorkerAllowlist(@TempDir Path dir) {
        var req = new SandboxProtocol.Request("job-1", HttpSecurityScanner.ID, HttpSecurityScanner.class.getName(),
                "http://not-allowed.example.com", Map.of(), List.of("localhost"), List.of(), 5,
                new SandboxProtocol.App("svc", "svc", "test"));
        SandboxProtocol.Result r = SandboxMain.run(req, dir.resolve(SandboxProtocol.PROGRESS));
        assertThat(r.status).isEqualTo("FAILED");
        assertThat(r.error).contains("allowlist");
        assertThat(r.findings).isEmpty();
    }

    @Test
    void sandboxRejectsClassesThatAreNotTheRequestedScanner(@TempDir Path dir) {
        var req = new SandboxProtocol.Request("job-2", "builtin-secrets", HttpSecurityScanner.class.getName(),
                "http://localhost", Map.of(), List.of("localhost"), List.of(), 5, null);
        assertThat(SandboxMain.run(req, dir.resolve(SandboxProtocol.PROGRESS)).error).contains("does not implement");
        var notAScanner = new SandboxProtocol.Request("job-3", "x", String.class.getName(), "http://localhost", Map.of(),
                List.of("localhost"), List.of(), 5, null);
        assertThat(SandboxMain.run(notAScanner, dir.resolve(SandboxProtocol.PROGRESS)).error).contains("not a Scanner");
    }

    @Test
    void containerSandboxIsLockedDown(@TempDir Path dir) {
        var cfg = new WorkerProperties().getSandbox();
        List<String> cmd = new ContainerSandbox(cfg).command(dir, "abc-123");
        assertThat(cmd).containsSubsequence("run", "--rm")
                .contains("--read-only", "no-new-privileges", "ALL", cfg.getImage(), "sandbox", "/job/request.json");
        assertThat(String.join(" ", cmd)).contains("--cap-drop ALL").contains("--pids-limit 256").contains("--memory 1g");
        assertThat(cmd.get(cmd.indexOf("--user") + 1)).doesNotStartWith("0:");
        cfg.setUser("1000:1000");
        assertThat(new ContainerSandbox(cfg).command(dir, "x")).containsSubsequence("--user", "1000:1000");
    }
}
