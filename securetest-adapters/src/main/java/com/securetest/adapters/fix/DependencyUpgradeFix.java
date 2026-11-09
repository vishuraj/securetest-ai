package com.securetest.adapters.fix;

import com.securetest.core.model.Finding;
import com.securetest.core.spi.FixProvider;
import com.securetest.core.util.SourceFiles;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Bumps a vulnerable dependency to its fixed version where the version is declared in the workspace:
 * an explicit {@code <version>} in pom.xml, a {@code ${property}} it references, or a Gradle coordinate string.
 * Managed/transitive versions are reported as "manual" (the BOM owner should upgrade).
 */
public class DependencyUpgradeFix implements FixProvider {

    @Override
    public boolean supports(Finding f) {
        return "dependency-upgrade".equals(f.fixId) && f.dependency != null && f.dependency.fixedVersion != null
                && f.dependency.packageName != null && f.dependency.packageName.contains(":");
    }

    @Override
    public Optional<ProposedFix> propose(Finding f, Path root) throws IOException {
        String[] ga = f.dependency.packageName.split(":");
        String group = ga[0];
        String artifact = ga[1];
        String from = f.dependency.installedVersion;
        String to = f.dependency.fixedVersion;
        List<FileEdit> edits = new ArrayList<>();
        for (Path build : SourceFiles.walk(root, p -> {
            String n = p.getFileName().toString();
            return n.equals("pom.xml") || n.equals("build.gradle") || n.equals("build.gradle.kts");
        }, 200)) {
            String content = SourceFiles.read(build);
            String updated = build.getFileName().toString().equals("pom.xml") ? pom(content, group, artifact, from, to) : gradle(content, group, artifact, from, to);
            if (!updated.equals(content)) edits.add(new FileEdit(SourceFiles.relative(root, build), updated));
        }
        if (edits.isEmpty()) return Optional.empty();
        return Optional.of(new ProposedFix("Upgrade " + f.dependency.packageName + " " + from + " → " + to,
                "Updates the declared version to the first release that fixes " + String.join(", ", f.dependency.aliases)
                        + ". Run the test suite: minor/major upgrades can include breaking changes.",
                edits, false, "rule-based: dependency-upgrade"));
    }

    static String pom(String content, String group, String artifact, String from, String to) {
        Pattern dep = Pattern.compile("(<groupId>\\s*" + Pattern.quote(group) + "\\s*</groupId>\\s*<artifactId>\\s*" + Pattern.quote(artifact)
                + "\\s*</artifactId>\\s*<version>\\s*)([^<\\s]+)(\\s*</version>)");
        Matcher m = dep.matcher(content);
        StringBuilder sb = new StringBuilder();
        String result = content;
        boolean found = false;
        while (m.find()) {
            String v = m.group(2);
            if (v.equals(from)) {
                m.appendReplacement(sb, Matcher.quoteReplacement(m.group(1) + to + m.group(3)));
                found = true;
            } else if (v.startsWith("${") && v.endsWith("}")) {
                String prop = v.substring(2, v.length() - 1);
                result = content.replaceAll("(<" + Pattern.quote(prop) + ">)\\s*" + Pattern.quote(from) + "\\s*(</" + Pattern.quote(prop) + ">)",
                        "$1" + Matcher.quoteReplacement(to) + "$2");
                return result;
            } else {
                m.appendReplacement(sb, Matcher.quoteReplacement(m.group()));
            }
        }
        if (!found) return content;
        m.appendTail(sb);
        return sb.toString();
    }

    static String gradle(String content, String group, String artifact, String from, String to) {
        return content.replace(group + ":" + artifact + ":" + from, group + ":" + artifact + ":" + to);
    }
}
