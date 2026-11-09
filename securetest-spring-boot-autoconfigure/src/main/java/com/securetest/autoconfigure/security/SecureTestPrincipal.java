package com.securetest.autoconfigure.security;

import com.securetest.autoconfigure.security.Rbac.Permission;
import com.securetest.autoconfigure.security.Rbac.Role;

import java.util.EnumSet;
import java.util.Set;

/** The authenticated dashboard user. */
public record SecureTestPrincipal(String name, Set<Role> roles, String authMethod, String remoteAddress) {

    public static final String REQUEST_ATTRIBUTE = SecureTestPrincipal.class.getName();

    public Set<Permission> permissions() {
        Set<Permission> p = EnumSet.noneOf(Permission.class);
        roles.forEach(r -> p.addAll(r.permissions()));
        return p;
    }

    public boolean has(Permission permission) {
        return permissions().contains(permission);
    }

    public static SecureTestPrincipal system() {
        return new SecureTestPrincipal("system", EnumSet.of(Role.ADMIN), "internal", null);
    }
}
