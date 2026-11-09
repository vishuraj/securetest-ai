package com.securetest.autoconfigure.security;

import com.securetest.autoconfigure.security.Rbac.Permission;

/** Server-side authorization checks used by every controller method. */
public final class Authz {
    private Authz() { }

    /**
     * @param principal resolved by the web-stack argument resolver (never trusted from the client)
     * @param permission required permission, or {@code null} to require only an authenticated user
     */
    public static SecureTestPrincipal require(SecureTestPrincipal principal, Permission permission) {
        if (principal == null) throw new ApiException(401, "unauthenticated", "Authentication required");
        if (permission != null && !principal.has(permission)) {
            throw ApiException.forbidden("Permission " + permission + " is required (your roles: " + principal.roles() + ")");
        }
        return principal;
    }
}
