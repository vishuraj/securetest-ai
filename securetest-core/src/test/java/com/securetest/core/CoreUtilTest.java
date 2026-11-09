package com.securetest.core;

import com.securetest.core.model.Enums.Confidence;
import com.securetest.core.model.Finding;
import com.securetest.core.model.Severity;
import com.securetest.core.spi.ScanRejectedException;
import com.securetest.core.util.AllowlistCommandRunner;
import com.securetest.core.util.AllowlistTargetGuard;
import com.securetest.core.util.Cvss3;
import com.securetest.core.util.Fingerprints;
import com.securetest.core.util.MavenVersion;
import com.securetest.core.util.PriorityCalculator;
import com.securetest.core.util.Redactor;
import com.securetest.core.util.SourceFiles;
import com.securetest.core.util.UnifiedDiff;
import org.junit.jupiter.api.Test;

import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class CoreUtilTest {

    @Test
    void sourceCriticalIsNeverDowngraded() {
        Finding f = Finding.of("m", "s", "r", "t", Severity.CRITICAL).confidence(Confidence.LOW);
        f.reachable = false;
        PriorityCalculator.apply(f, new PriorityCalculator.Context(false, "low"));
        assertThat(f.priority).isEqualTo(Severity.CRITICAL);
        assertThat(f.sourceSeverity).isEqualTo(Severity.CRITICAL);
        assertThat(f.priorityRationale).anyMatch(s -> s.contains("never downgraded"));
    }

    @Test
    void contextRaisesAndLowersPriorityWithRationale() {
        Finding f = Finding.of("m", "s", "r", "t", Severity.MEDIUM).exposure("internet");
        PriorityCalculator.apply(f, new PriorityCalculator.Context(false, "medium"));
        assertThat(f.priority).isEqualTo(Severity.HIGH);
        Finding g = Finding.of("m", "s", "r", "t", Severity.MEDIUM).confidence(Confidence.LOW);
        PriorityCalculator.apply(g, null);
        assertThat(g.priority).isEqualTo(Severity.LOW);
        assertThat(g.priorityRationale).anyMatch(s -> s.contains("low detection confidence"));
    }

    @Test
    void fingerprintIgnoresLineShifts() {
        Finding a = Finding.of("m", "s", "R1", "t", Severity.LOW).location("A.java", 10, 10);
        a.snippet = List.of(new Finding.CodeLine(10, "  x = md5(y);", true));
        Finding b = Finding.of("m", "s", "R1", "t", Severity.LOW).location("A.java", 14, 14);
        b.snippet = List.of(new Finding.CodeLine(14, "x = md5(y);   ", true));
        assertThat(Fingerprints.of(a)).isEqualTo(Fingerprints.of(b));
    }

    @Test
    void redactsSecrets() {
        String s = Redactor.redact("password=hunter22 key=AKIAABCDEFGHIJKLMNOP\nAuthorization: Bearer abc.def\nurl=https://u:p4ss@host/x token=${TOKEN}");
        assertThat(s).doesNotContain("hunter22").doesNotContain("AKIAABCDEFGHIJKLMNOP").doesNotContain("p4ss").doesNotContain("abc.def");
        assertThat(s).contains("${TOKEN}");
        assertThat(Redactor.mask("raw-value")).isEqualTo("••••••••");
        assertThat(Redactor.mask("env://X")).isEqualTo("env://X");
    }

    @Test
    void mavenVersionOrdering() {
        assertThat(MavenVersion.compare("1.0", "1.0.0")).isZero();
        assertThat(MavenVersion.isLower("2.7.18", "3.5.16")).isTrue();
        assertThat(MavenVersion.isLower("1.0-rc1", "1.0")).isTrue();
        assertThat(MavenVersion.isLower("1.0", "1.0.1")).isTrue();
        assertThat(MavenVersion.isLower("2.15.0", "2.9.0")).isFalse();
        assertThat(MavenVersion.major("3.5.16")).isEqualTo(3);
    }

    @Test
    void cvssBaseScore() {
        assertThat(Cvss3.baseScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")).isEqualTo(9.8);
        assertThat(Cvss3.baseScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")).isEqualTo(10.0);
        assertThat(Cvss3.baseScore("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N")).isEqualTo(3.3);
        assertThat(Cvss3.baseScore("garbage")).isEqualTo(-1);
    }

    @Test
    void unifiedDiffIsApplicable() {
        String before = "a\nb\nc\nd\ne\nf\ng\n";
        String after = "a\nb\nC\nd\ne\nf\ng\nh\n";
        String d = UnifiedDiff.unified("x.txt", before, after, 1);
        assertThat(d).contains("--- a/x.txt").contains("-c").contains("+C").contains("+h");
        assertThat(UnifiedDiff.stats(before, after)).containsExactly(2, 1);
    }

    @Test
    void allowlistBlocksUnknownAndMetadataHosts() {
        AllowlistTargetGuard g = new AllowlistTargetGuard(List.of("self", "*.staging.example.com", "10.20.0.0/16"), "http://localhost:8080", true);
        assertThat(g.isAllowedHost("localhost")).isTrue();
        assertThat(g.isAllowedHost("api.staging.example.com")).isTrue();
        assertThat(g.isAllowedHost("10.20.3.4")).isTrue();
        assertThat(g.isAllowedHost("10.21.3.4")).isFalse();
        assertThat(g.isAllowedHost("169.254.169.254")).isFalse();
        assertThatThrownBy(() -> g.requireAllowedUrl("https://example.org/")).isInstanceOf(ScanRejectedException.class);
        assertThatThrownBy(() -> g.requireAllowedUrl("file:///etc/passwd")).isInstanceOf(ScanRejectedException.class);
        AllowlistTargetGuard open = new AllowlistTargetGuard(List.of(), null, false);
        assertThat(open.isAllowedHost("169.254.169.254")).isFalse();
    }

    @Test
    void commandRunnerRefusesNonAllowlisted() {
        AllowlistCommandRunner r = new AllowlistCommandRunner(Set.of("trivy"));
        assertThat(r.isAllowed("trivy.exe")).isTrue();
        assertThatThrownBy(() -> r.run(List.of("powershell", "-c", "x"), null, Duration.ofSeconds(1)))
                .isInstanceOf(ScanRejectedException.class).hasMessageContaining("not allowlisted");
    }

    @Test
    void pathTraversalIsRefused() {
        Path root = Path.of("build-root").toAbsolutePath();
        assertThatThrownBy(() -> SourceFiles.resolveInside(root, "../../etc/passwd")).isInstanceOf(SecurityException.class);
        assertThat(SourceFiles.resolveInside(root, "src/A.java")).isEqualTo(root.resolve("src").resolve("A.java"));
    }
}
