package com.securetest.autoconfigure.security;

import java.util.EnumSet;
import java.util.Locale;
import java.util.Set;

/** Role-based access control (SRS 3, SEC-002). Enforced server-side on every API call. */
public final class Rbac {
    private Rbac() { }

    public enum Permission { VIEW, CONFIGURE, EXECUTE, APPROVE, REMEDIATE, ADMIN, AUDIT }

    public enum Role {
        /** Auditor / read-only user. */
        VIEWER(EnumSet.of(Permission.VIEW, Permission.AUDIT)),
        DEVELOPER(EnumSet.of(Permission.VIEW, Permission.EXECUTE, Permission.REMEDIATE)),
        QA(EnumSet.of(Permission.VIEW, Permission.EXECUTE, Permission.CONFIGURE)),
        SECURITY(EnumSet.of(Permission.VIEW, Permission.EXECUTE, Permission.CONFIGURE, Permission.APPROVE, Permission.REMEDIATE, Permission.AUDIT)),
        DEVOPS(EnumSet.of(Permission.VIEW, Permission.EXECUTE, Permission.CONFIGURE)),
        /** Application owner. */
        OWNER(EnumSet.of(Permission.VIEW, Permission.EXECUTE, Permission.CONFIGURE, Permission.APPROVE, Permission.REMEDIATE, Permission.AUDIT)),
        ADMIN(EnumSet.allOf(Permission.class));

        private final Set<Permission> permissions;

        Role(Set<Permission> permissions) { this.permissions = permissions; }

        public Set<Permission> permissions() { return permissions; }

        public static Role parse(String s) {
            String v = s.trim().toUpperCase(Locale.ROOT).replace("ROLE_", "").replace("SECURETEST_", "");
            return switch (v) {
                case "AUDITOR", "READ_ONLY", "READONLY" -> VIEWER;
                case "APPLICATION_OWNER", "APP_OWNER" -> OWNER;
                case "SRE", "PLATFORM" -> DEVOPS;
                case "SECURITY_ANALYST", "APPSEC" -> SECURITY;
                case "ADMINISTRATOR" -> ADMIN;
                default -> Role.valueOf(v);
            };
        }
    }
}
