package com.securetest.controlplane.security;

import java.util.EnumSet;
import java.util.Locale;
import java.util.Set;

/** Tenant roles. Mirrors the embedded starter's role model so the same OIDC groups work in both profiles. */
public enum Role {
    VIEWER(EnumSet.of(Permission.VIEW, Permission.AUDIT)),
    DEVELOPER(EnumSet.of(Permission.VIEW, Permission.EXECUTE)),
    QA(EnumSet.of(Permission.VIEW, Permission.EXECUTE)),
    DEVOPS(EnumSet.of(Permission.VIEW, Permission.EXECUTE)),
    SECURITY(EnumSet.of(Permission.VIEW, Permission.EXECUTE, Permission.APPROVE, Permission.REPORT, Permission.AUDIT)),
    OWNER(EnumSet.of(Permission.VIEW, Permission.EXECUTE, Permission.APPROVE, Permission.REPORT, Permission.AUDIT)),
    ADMIN(EnumSet.allOf(Permission.class));

    private final Set<Permission> permissions;

    Role(Set<Permission> permissions) { this.permissions = permissions; }

    public Set<Permission> permissions() { return permissions; }

    /** Lenient mapping of IdP group / role names; unknown names map to nothing. */
    public static Role parse(String raw) {
        if (raw == null) return null;
        String s = raw.trim().toUpperCase(Locale.ROOT).replace("ROLE_", "").replace("SECURETEST_", "").replace('-', '_');
        return switch (s) {
            case "VIEWER", "AUDITOR", "READ_ONLY", "READONLY" -> VIEWER;
            case "DEVELOPER", "DEV" -> DEVELOPER;
            case "QA", "TESTER" -> QA;
            case "DEVOPS", "SRE" -> DEVOPS;
            case "SECURITY", "SECURITY_LEAD", "APPSEC" -> SECURITY;
            case "OWNER" -> OWNER;
            case "ADMIN", "ADMINISTRATOR", "TENANT_ADMIN" -> ADMIN;
            default -> null;
        };
    }

    public enum Permission {
        /** Read inventory, findings, jobs. */
        VIEW,
        /** Queue passive remote scans. */
        EXECUTE,
        /** Queue active / resource-intensive scans. */
        APPROVE,
        /** Generate reports. */
        REPORT,
        /** Read the audit trail. */
        AUDIT,
        /** Manage enrollment tokens and tenant settings. */
        ADMIN
    }
}
