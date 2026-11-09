package com.securetest.controlplane.security;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.ArrayList;
import java.util.List;

/** Authentication built from a validated JWT; the principal is a {@link Caller}. */
public class CallerAuthentication extends AbstractAuthenticationToken {
    private final Caller caller;
    private final Jwt jwt;

    public CallerAuthentication(Caller caller, Jwt jwt) {
        super(authorities(caller));
        this.caller = caller;
        this.jwt = jwt;
        setAuthenticated(true);
    }

    private static List<GrantedAuthority> authorities(Caller c) {
        List<GrantedAuthority> out = new ArrayList<>();
        c.roles().forEach(r -> out.add(new SimpleGrantedAuthority("ROLE_" + r.name())));
        if (c.platformAdmin()) out.add(new SimpleGrantedAuthority("ROLE_PLATFORM_ADMIN"));
        return out;
    }

    @Override public Object getCredentials() { return jwt; }
    @Override public Caller getPrincipal() { return caller; }
    @Override public String getName() { return caller.subject(); }
}
