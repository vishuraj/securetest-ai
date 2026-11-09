package com.securetest.autoconfigure.security;

import com.securetest.autoconfigure.security.Rbac.Permission;
import com.securetest.autoconfigure.security.Rbac.Role;

import java.util.EnumSet;
import java.util.Set;

/**
 * The authenticated dashboard user. Passed explicitly into every API method (resolved from the request on Spring MVC
 * and from the exchange on WebFlux), so it works the same on both web stacks.
 */
public record SecureTestPrincipal(String name, Set<Role> roles, String authMethod, String remoteAddress, String correlationId) {

    /** Request / exchange attribute that carries the principal from the gate to the argument resolvers. */
    public static final String REQUEST_ATTRIBUTE = SecureTestPrincipal.class.getName();

    public SecureTestPrincipal(String name, Set<Role> roles, String authMethod, String remoteAddress) {
        this(name, roles, authMethod, remoteAddress, null);
    }

    public SecureTestPrincipal withCorrelationId(String id) {
        return new SecureTestPrincipal(name, roles, authMethod, remoteAddress, id);
    }

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
