package com.securetest.migration;

import com.securetest.core.util.MavenVersion;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Validated compatibility matrix for migration targets (FR-MIG-002, SRS 14.1).
 * Ranges are the Java versions supported by each Spring Boot line.
 */
public final class CompatibilityMatrix {

    public record BootLine(String line, int minJava, int maxJava, String servletNamespace, String latestPatch, boolean ossSupported) { }

    public static final List<Integer> JAVA_TARGETS = List.of(17, 21, 25);

    public static final List<BootLine> BOOT_LINES = List.of(
            new BootLine("2.7", 8, 21, "javax", "2.7.18", false),
            new BootLine("3.0", 17, 21, "jakarta", "3.0.13", false),
            new BootLine("3.1", 17, 21, "jakarta", "3.1.12", false),
            new BootLine("3.2", 17, 23, "jakarta", "3.2.12", false),
            new BootLine("3.3", 17, 23, "jakarta", "3.3.13", false),
            new BootLine("3.4", 17, 25, "jakarta", "3.4.13", false),
            new BootLine("3.5", 17, 25, "jakarta", "3.5.16", true),
            new BootLine("4.0", 17, 25, "jakarta", "4.0.0", true),
            new BootLine("4.1", 17, 25, "jakarta", "4.1.2", true)
    );

    /** Targets offered in the UI. */
    public static final List<String> BOOT_TARGETS = List.of("3.5.16", "4.1.2");

    private CompatibilityMatrix() { }

    public static BootLine lineFor(String bootVersion) {
        if (bootVersion == null) return null;
        String key = MavenVersion.major(bootVersion) + "." + MavenVersion.minor(bootVersion);
        return BOOT_LINES.stream().filter(b -> b.line().equals(key)).findFirst().orElse(null);
    }

    public static int javaMajor(String v) {
        if (v == null || v.isBlank()) return -1;
        String s = v.trim();
        if (s.startsWith("1.")) s = s.substring(2);
        try {
            return Integer.parseInt(s.replaceAll("[^0-9].*$", ""));
        } catch (NumberFormatException e) {
            return -1;
        }
    }

    /** @return [errors, warnings] */
    public static List<List<String>> check(String sourceJava, String sourceBoot, int targetJava, String targetBoot) {
        List<String> errors = new ArrayList<>();
        List<String> warnings = new ArrayList<>();
        BootLine target = lineFor(targetBoot);
        if (target == null) {
            errors.add("Spring Boot " + targetBoot + " is not in the validated compatibility matrix.");
        } else {
            if (targetJava < target.minJava() || targetJava > target.maxJava()) {
                errors.add("Spring Boot " + target.line() + " supports Java " + target.minJava() + "–" + target.maxJava() + "; Java " + targetJava + " is unsupported.");
            }
            if (!target.ossSupported()) warnings.add("Spring Boot " + target.line() + " is out of open-source support.");
        }
        if (!JAVA_TARGETS.contains(targetJava)) errors.add("Java " + targetJava + " is not an LTS target. Choose one of " + JAVA_TARGETS + ".");
        int srcJava = javaMajor(sourceJava);
        if (srcJava > targetJava) errors.add("Target Java " + targetJava + " is older than the current Java " + srcJava + " (downgrades are not supported).");
        if (sourceBoot != null && targetBoot != null && MavenVersion.compare(sourceBoot, targetBoot) > 0) {
            errors.add("Target Spring Boot " + targetBoot + " is older than the current " + sourceBoot + ".");
        }
        if (sourceBoot != null && MavenVersion.major(sourceBoot) == 2 && MavenVersion.major(targetBoot) >= 4) {
            warnings.add("Upgrading 2.x directly to 4.x skips a major line. The plan migrates through 3.x semantics; validate thoroughly.");
        }
        if (sourceBoot != null && MavenVersion.major(sourceBoot) == 2 && MavenVersion.minor(sourceBoot) < 7) {
            warnings.add("Spring recommends upgrading to 2.7.x first and fixing deprecations before moving to 3.x.");
        }
        if (srcJava > 0 && srcJava < 11 && targetJava >= 17) {
            warnings.add("Java " + srcJava + " → " + targetJava + " crosses removal of Java EE modules (JAXB, JAX-WS), strong encapsulation of JDK internals and SecurityManager deprecation.");
        }
        return List.of(errors, warnings);
    }

    public static Map<String, Object> asTable() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("javaTargets", JAVA_TARGETS);
        m.put("bootTargets", BOOT_TARGETS);
        m.put("bootLines", BOOT_LINES);
        return m;
    }
}
