package com.securetest.migration;

import com.securetest.migration.MigrationModels.Assessment;
import com.securetest.migration.MigrationModels.Inventory;
import com.securetest.migration.MigrationModels.Target;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class MigrationEngineTest {

    @TempDir
    Path root;
    @TempDir
    Path storage;

    private void project() throws Exception {
        Files.writeString(root.resolve("pom.xml"), """
                <project><parent><groupId>org.springframework.boot</groupId>
                <artifactId>spring-boot-starter-parent</artifactId>
                <version>2.7.18</version></parent>
                <properties><java.version>1.8</java.version></properties>
                <dependencies><dependency><groupId>javax.servlet</groupId>
                <artifactId>javax.servlet-api</artifactId></dependency></dependencies></project>
                """);
        Path src = Files.createDirectories(root.resolve("src/main/java/x"));
        Files.writeString(src.resolve("A.java"), """
                package x;
                import javax.servlet.http.HttpServletRequest;
                import javax.sql.DataSource;
                import javax.annotation.Nullable;
                import javax.annotation.PostConstruct;
                class A extends WebSecurityConfigurerAdapter {
                  Integer i = new Integer(1);
                  void c(H http) { http.authorizeRequests().antMatchers("/x").permitAll(); }
                }
                """);
        Files.writeString(root.resolve("Dockerfile"), "FROM openjdk:8-jdk AS build\n");
    }

    @Test
    void assessesWithoutModifyingAndTransformsInMemory() throws Exception {
        project();
        String before = Files.readString(root.resolve("src/main/java/x/A.java"));
        MigrationEngine engine = new MigrationEngine(new GitWorkspace(false));
        Inventory inv = engine.discover(root);
        assertThat(inv.detectedSpringBoot).isEqualTo("2.7.18");
        assertThat(inv.detectedJava).isEqualTo("1.8");
        Assessment a = engine.assess(root, new Target(21, "3.5.16"), inv);
        assertThat(a.compatibilityErrors).isEmpty();
        assertThat(a.items).anyMatch(i -> i.id().equals("MIG-SEC-003") && !i.autoFixable());
        assertThat(a.countsByCategory).containsKeys("JAKARTA", "BUILD", "DEPENDENCIES", "SPRING_SECURITY", "JDK_API", "CONTAINER");
        assertThat(Files.readString(root.resolve("src/main/java/x/A.java"))).isEqualTo(before); // FR-MIG-001

        Map<String, String> why = new LinkedHashMap<>();
        Map<String, String> edits = engine.transform(root, new Target(21, "3.5.16"), inv, new HashSet<>(MigrationEngine.CATEGORIES), why);
        String a2 = edits.get("src/main/java/x/A.java");
        assertThat(a2).contains("import jakarta.servlet.http.HttpServletRequest;").contains("import javax.sql.DataSource;")
                .contains("import javax.annotation.Nullable;").contains("import jakarta.annotation.PostConstruct;")
                .contains("Integer.valueOf(1)").contains(".authorizeHttpRequests().requestMatchers(");
        assertThat(edits.get("pom.xml")).contains("<version>3.5.16</version>").contains("<java.version>21</java.version>")
                .contains("<artifactId>jakarta.servlet-api</artifactId>");
        assertThat(edits.get("Dockerfile")).contains("FROM eclipse-temurin:21-jre AS build");
    }

    @Test
    void unsupportedTargetIsReported() throws Exception {
        project();
        MigrationEngine engine = new MigrationEngine(new GitWorkspace(false));
        Assessment a = engine.assess(root, new Target(11, "3.5.16"), engine.discover(root));
        assertThat(a.compatibilityErrors).isNotEmpty();
    }

    @Test
    void applyCreatesRollbackPointAndUndoDetectsConflicts() throws Exception {
        project();
        ChangeSetEngine cse = new ChangeSetEngine(storage, new GitWorkspace(false));
        String original = Files.readString(root.resolve("Dockerfile"));
        ChangeSet cs = cse.create("MIGRATION", "t", "M-1", root, Map.of("Dockerfile", "FROM eclipse-temurin:21-jre\n"), Map.of(), "tester");
        assertThat(cs.files).hasSize(1);
        assertThat(cse.exportPatch(cs)).contains("-FROM openjdk:8-jdk AS build").contains("+FROM eclipse-temurin:21-jre");

        cse.apply(cs, root, new ChangeSetEngine.ApplyOptions(false, false), "tester");
        assertThat(cs.status).isEqualTo(ChangeSet.Status.APPLIED);
        assertThat(Files.readString(root.resolve("Dockerfile"))).isEqualTo("FROM eclipse-temurin:21-jre\n");

        // a later user edit must block undo (FR-MIG-008/009)
        Files.writeString(root.resolve("Dockerfile"), "FROM eclipse-temurin:21-jre\nUSER app\n");
        cse.undo(cs, root, "tester");
        assertThat(cs.status).isEqualTo(ChangeSet.Status.CONFLICT);
        assertThat(Files.readString(root.resolve("Dockerfile"))).contains("USER app");

        // restore the applied state and undo succeeds
        Files.writeString(root.resolve("Dockerfile"), "FROM eclipse-temurin:21-jre\n");
        cs.status = ChangeSet.Status.APPLIED;
        cse.undo(cs, root, "tester");
        assertThat(cs.status).isEqualTo(ChangeSet.Status.UNDONE);
        assertThat(Files.readString(root.resolve("Dockerfile"))).isEqualTo(original);
    }

    @Test
    void applyRefusesWhenFileChangedAfterPreview() throws Exception {
        project();
        ChangeSetEngine cse = new ChangeSetEngine(storage, new GitWorkspace(false));
        ChangeSet cs = cse.create("REMEDIATION", "t", "F-1", root, Map.of("Dockerfile", "FROM x:1\n"), Map.of(), "tester");
        Files.writeString(root.resolve("Dockerfile"), "FROM changed:2\n");
        cse.apply(cs, root, new ChangeSetEngine.ApplyOptions(false, false), "tester");
        assertThat(cs.status).isEqualTo(ChangeSet.Status.CONFLICT);
        assertThat(Files.readString(root.resolve("Dockerfile"))).isEqualTo("FROM changed:2\n");
    }
}
