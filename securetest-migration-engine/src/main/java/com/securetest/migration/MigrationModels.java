package com.securetest.migration;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Value types used by the migration workflow (SRS 7.4, 7.5). */
public final class MigrationModels {
    private MigrationModels() { }

    public static class BuildModule {
        public String path;          // relative directory ("" = root)
        public String buildFile;     // pom.xml / build.gradle(.kts)
        public String buildTool;     // maven / gradle
        public String javaVersion;
        public String springBootVersion;
        public String wrapperVersion;
        public int javaFiles;
        public int testFiles;
        public int javaxReferences;
    }

    public static class Inventory {
        public String root;
        public Instant discoveredAt = Instant.now();
        public List<BuildModule> modules = new ArrayList<>();
        public List<String> languages = new ArrayList<>();
        public Map<String, String> containerImages = new LinkedHashMap<>(); // file -> base image
        public boolean gitRepository;
        public String gitBranch;
        public String gitHead;
        public List<String> dirtyFiles = new ArrayList<>();
        public String detectedJava;
        public String detectedSpringBoot;
        public String servletNamespace;     // javax | jakarta | none
        public int totalJavaFiles;
        public int totalTestFiles;
    }

    public record Target(int javaVersion, String springBootVersion) { }

    public record Item(String id, String category, String severity, String file, Integer line, String message,
                       boolean autoFixable, String guidance) { }

    public static class Assessment {
        public String migrationId;
        public Target target;
        public Inventory inventory;
        public List<String> compatibilityErrors = new ArrayList<>();
        public List<String> compatibilityWarnings = new ArrayList<>();
        public List<Item> items = new ArrayList<>();
        public Map<String, Integer> countsByCategory = new LinkedHashMap<>();
        public int riskScore;
        public String riskLevel;
        public List<String> riskFactors = new ArrayList<>();
        public int autoFixableCount;
        public int manualCount;
        public Instant assessedAt = Instant.now();
    }

    public record PlanStep(int order, String title, String category, String description, List<String> prerequisites,
                           List<String> affectedFiles, String complexity, String rollback, boolean automated) { }

    public static class Plan {
        public String migrationId;
        public List<PlanStep> steps = new ArrayList<>();
        public String rollbackStrategy;
        public Instant createdAt = Instant.now();
    }

    /** A migration run tracked through Discover → Assess → Plan → Preview → Apply → Validate → Commit/Undo. */
    public static class MigrationRun {
        public String id;
        public String repoRef;
        public String status = "ASSESSED";
        public String requestedBy;
        public Instant createdAt = Instant.now();
        public Map<String, String> sourceVersions = new LinkedHashMap<>();
        public Map<String, String> targetVersions = new LinkedHashMap<>();
        public String baselineRef;
        public Assessment assessment;
        public Plan plan;
        public List<String> selectedCategories = new ArrayList<>();
        public String changeSetId;
        public List<String> history = new ArrayList<>();
    }
}
