package com.securetest.controlplane.security;

import java.util.Set;

/**
 * The authenticated user of a request, resolved from the OIDC access token.
 *
 * @param tenantSlug    tenant the token is scoped to (may be null for platform administrators)
 * @param platformAdmin may manage tenants
 */
public record Caller(String subject, String tenantSlug, Set<Role> roles, boolean platformAdmin) {

    public boolean has(Role.Permission p) {
        return roles.stream().anyMatch(r -> r.permissions().contains(p));
    }
}
