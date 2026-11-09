package com.securetest.core.spi;

import com.securetest.core.model.Enums.ExecutionLocation;
import com.securetest.core.model.Enums.ScanMode;

import java.util.ArrayList;
import java.util.List;

/** Everything the dashboard needs to render the configuration modal for a scanner (SRS 6.2). */
public final class ScannerDescriptor {
    private final String id;
    private final String moduleId;
    private final String name;
    private final String purpose;
    private final String accessDescription;
    private final ScanMode mode;
    private final ExecutionLocation location;
    private final boolean requiresTarget;
    private final boolean requiresSourceRoot;
    private final String toolName;
    private final String toolVersion;
    private final String estimatedDuration;
    private final String resourceUse;
    private final List<String> permissions;
    private final List<String> prerequisites;
    private final List<FieldSpec> fields;

    private ScannerDescriptor(Builder b) {
        this.id = b.id;
        this.moduleId = b.moduleId;
        this.name = b.name;
        this.purpose = b.purpose;
        this.accessDescription = b.accessDescription;
        this.mode = b.mode;
        this.location = b.location;
        this.requiresTarget = b.requiresTarget;
        this.requiresSourceRoot = b.requiresSourceRoot;
        this.toolName = b.toolName;
        this.toolVersion = b.toolVersion;
        this.estimatedDuration = b.estimatedDuration;
        this.resourceUse = b.resourceUse;
        this.permissions = List.copyOf(b.permissions);
        this.prerequisites = List.copyOf(b.prerequisites);
        this.fields = List.copyOf(b.fields);
    }

    public static Builder builder(String id, String moduleId, String name) { return new Builder(id, moduleId, name); }

    public String getId() { return id; }
    public String getModuleId() { return moduleId; }
    public String getName() { return name; }
    public String getPurpose() { return purpose; }
    public String getAccessDescription() { return accessDescription; }
    public ScanMode getMode() { return mode; }
    public ExecutionLocation getLocation() { return location; }
    public boolean isRequiresTarget() { return requiresTarget; }
    public boolean isRequiresSourceRoot() { return requiresSourceRoot; }
    public String getToolName() { return toolName; }
    public String getToolVersion() { return toolVersion; }
    public String getEstimatedDuration() { return estimatedDuration; }
    public String getResourceUse() { return resourceUse; }
    public List<String> getPermissions() { return permissions; }
    public List<String> getPrerequisites() { return prerequisites; }
    public List<FieldSpec> getFields() { return fields; }

    /** Active and resource-intensive scans need explicit confirmation. */
    public boolean isRequiresConfirmation() { return mode != ScanMode.PASSIVE; }

    public static final class Builder {
        private final String id;
        private final String moduleId;
        private final String name;
        private String purpose = "";
        private String accessDescription = "";
        private ScanMode mode = ScanMode.PASSIVE;
        private ExecutionLocation location = ExecutionLocation.EMBEDDED;
        private boolean requiresTarget;
        private boolean requiresSourceRoot;
        private String toolName = "SecureTest built-in";
        private String toolVersion = "1.0.0";
        private String estimatedDuration = "< 1 minute";
        private String resourceUse = "Low";
        private final List<String> permissions = new ArrayList<>();
        private final List<String> prerequisites = new ArrayList<>();
        private final List<FieldSpec> fields = new ArrayList<>();

        private Builder(String id, String moduleId, String name) {
            this.id = id;
            this.moduleId = moduleId;
            this.name = name;
        }

        public Builder purpose(String v) { purpose = v; return this; }
        public Builder access(String v) { accessDescription = v; return this; }
        public Builder mode(ScanMode v) { mode = v; return this; }
        public Builder location(ExecutionLocation v) { location = v; return this; }
        public Builder requiresTarget() { requiresTarget = true; return this; }
        public Builder requiresSourceRoot() { requiresSourceRoot = true; return this; }
        public Builder tool(String name, String version) { toolName = name; toolVersion = version; return this; }
        public Builder duration(String v) { estimatedDuration = v; return this; }
        public Builder resources(String v) { resourceUse = v; return this; }
        public Builder permission(String v) { permissions.add(v); return this; }
        public Builder prerequisite(String v) { prerequisites.add(v); return this; }
        public Builder field(FieldSpec v) { fields.add(v); return this; }
        public ScannerDescriptor build() { return new ScannerDescriptor(this); }
    }
}
