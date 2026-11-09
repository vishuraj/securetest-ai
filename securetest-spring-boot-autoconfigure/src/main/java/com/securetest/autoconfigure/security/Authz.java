package com.securetest.autoconfigure.security;

import com.securetest.autoconfigure.security.Rbac.Permission;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;

/** Server-side authorization checks used by every controller method. */
public final class Authz {
    private Authz() { }

    public static SecureTestPrincipal current() {
        RequestAttributes attrs = RequestContextHolder.getRequestAttributes();
        Object p = attrs == null ? null : attrs.getAttribute(SecureTestPrincipal.REQUEST_ATTRIBUTE, RequestAttributes.SCOPE_REQUEST);
        if (p instanceof SecureTestPrincipal principal) return principal;
        throw new ApiException(401, "unauthenticated", "Authentication required");
    }

    public static SecureTestPrincipal require(Permission permission) {
        SecureTestPrincipal p = current();
        if (!p.has(permission)) {
            throw ApiException.forbidden("Permission " + permission + " is required (your roles: " + p.roles() + ")");
        }
        return p;
    }

    public static String correlationId() {
        RequestAttributes attrs = RequestContextHolder.getRequestAttributes();
        Object c = attrs == null ? null : attrs.getAttribute(SecureTestSecurityFilter.CORRELATION_ATTRIBUTE, RequestAttributes.SCOPE_REQUEST);
        return c == null ? null : c.toString();
    }
}
