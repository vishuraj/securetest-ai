package com.securetest.controlplane.security;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.List;

/**
 * An embedded agent (authenticated by a tenant enrollment token) or a remote worker
 * (authenticated by a fleet token). {@code tenantId} is null for workers.
 */
public class MachineAuthentication extends AbstractAuthenticationToken {
    public enum Kind { AGENT, WORKER }

    private final Kind kind;
    private final String tenantId;
    private final String name;

    public MachineAuthentication(Kind kind, String tenantId, String name) {
        super(List.of(new SimpleGrantedAuthority("ROLE_" + kind.name())));
        this.kind = kind;
        this.tenantId = tenantId;
        this.name = name;
        setAuthenticated(true);
    }

    public Kind kind() { return kind; }
    public String tenantId() { return tenantId; }

    @Override public Object getCredentials() { return null; }
    @Override public Object getPrincipal() { return name; }
}
