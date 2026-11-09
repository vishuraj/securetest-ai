package com.securetest.controlplane.service;

import com.securetest.controlplane.security.ApiException;
import com.securetest.controlplane.security.Caller;
import com.securetest.controlplane.security.Role.Permission;
import com.securetest.controlplane.store.TenantStore;
import org.springframework.stereotype.Component;

/**
 * Turns an authenticated {@link Caller} into a tenant scope, enforcing tenant isolation and RBAC.
 * Every user-facing endpoint goes through {@link #require}; the returned tenant id is the only one
 * the request may read or write.
 */
@Component
public class TenantAccess {

    /** @param tenantId database id of the caller's tenant */
    public record Scope(String tenantId, String tenantSlug, String actor) { }

    private final TenantStore tenants;

    public TenantAccess(TenantStore tenants) { this.tenants = tenants; }

    public Scope require(Caller caller, Permission permission) {
        if (caller == null) throw new ApiException(org.springframework.http.HttpStatus.UNAUTHORIZED, "Authentication required");
        if (caller.tenantSlug() == null || caller.tenantSlug().isBlank()) {
            throw ApiException.forbidden("Access token has no tenant claim");
        }
        TenantStore.Tenant tenant = tenants.findBySlug(caller.tenantSlug())
                .orElseThrow(() -> ApiException.forbidden("Unknown tenant '" + caller.tenantSlug() + "'"));
        if (!caller.has(permission)) {
            throw ApiException.forbidden("Missing permission " + permission + " (roles: " + caller.roles() + ")");
        }
        return new Scope(tenant.id(), tenant.slug(), caller.subject());
    }

    public void requirePlatformAdmin(Caller caller) {
        if (caller == null || !caller.platformAdmin()) throw ApiException.forbidden("Platform administrator role required");
    }
}
