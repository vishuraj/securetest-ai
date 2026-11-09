package com.securetest.controlplane.security;

import com.securetest.controlplane.ControlPlaneProperties;
import com.securetest.controlplane.store.TenantStore;
import com.securetest.core.util.Hashing;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Collection;
import java.util.EnumSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * Four stateless filter chains:
 * <ol>
 *   <li>{@code POST /api/v1/agents/register}: embedded agents, tenant enrollment token;</li>
 *   <li>{@code /api/v1/worker/**}: remote workers, fleet token;</li>
 *   <li>{@code /api/**}: users, OIDC JWT access token (tenant + roles from claims);</li>
 *   <li>everything else: health probes only.</li>
 * </ol>
 * No sessions and no cookies are used, so CSRF protection is not applicable.
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    @Order(1)
    SecurityFilterChain agentChain(HttpSecurity http, TenantStore tenants) throws Exception {
        TokenAuthenticationFilter filter = new TokenAuthenticationFilter(token -> tenants
                .tenantIdForEnrollmentToken(Hashing.sha256(token))
                .map(tenantId -> (Authentication) new MachineAuthentication(MachineAuthentication.Kind.AGENT, tenantId, "agent")));
        return machine(http.securityMatcher("/api/v1/agents/register"), filter, "AGENT");
    }

    @Bean
    @Order(2)
    SecurityFilterChain workerChain(HttpSecurity http, ControlPlaneProperties props) throws Exception {
        List<byte[]> hashes = props.getWorkers().getTokens().stream()
                .filter(t -> t != null && !t.isBlank())
                .map(t -> Hashing.sha256(t.trim()).getBytes(StandardCharsets.US_ASCII)).toList();
        TokenAuthenticationFilter filter = new TokenAuthenticationFilter(token -> {
            byte[] h = Hashing.sha256(token).getBytes(StandardCharsets.US_ASCII);
            boolean ok = false;
            for (byte[] candidate : hashes) ok |= MessageDigest.isEqual(candidate, h);
            return ok ? Optional.of(new MachineAuthentication(MachineAuthentication.Kind.WORKER, null, "worker")) : Optional.empty();
        });
        return machine(http.securityMatcher("/api/v1/worker/**"), filter, "WORKER");
    }

    private SecurityFilterChain machine(HttpSecurity http, TokenAuthenticationFilter filter, String role) throws Exception {
        return http
                .csrf(c -> c.disable())
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .addFilterBefore(filter, BasicAuthenticationFilter.class)
                .authorizeHttpRequests(a -> a.anyRequest().hasRole(role))
                .exceptionHandling(e -> e.authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED)))
                .build();
    }

    @Bean
    @Order(3)
    SecurityFilterChain userApiChain(HttpSecurity http, ControlPlaneProperties props) throws Exception {
        return http
                .securityMatcher("/api/**")
                .csrf(c -> c.disable())
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(a -> a.anyRequest().authenticated())
                .oauth2ResourceServer(o -> o.jwt(j -> j.jwtAuthenticationConverter(new CallerConverter(props.getSecurity()))))
                .build();
    }

    @Bean
    @Order(4)
    SecurityFilterChain defaultChain(HttpSecurity http) throws Exception {
        return http
                .csrf(c -> c.disable())
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(a -> a
                        .requestMatchers("/actuator/health", "/actuator/health/**", "/actuator/info", "/error").permitAll()
                        .anyRequest().denyAll())
                .build();
    }

    /** Maps OIDC claims to a {@link Caller}. */
    static final class CallerConverter implements Converter<Jwt, AbstractAuthenticationToken> {
        private final ControlPlaneProperties.Security cfg;

        CallerConverter(ControlPlaneProperties.Security cfg) { this.cfg = cfg; }

        @Override
        public AbstractAuthenticationToken convert(Jwt jwt) {
            Set<String> raw = new LinkedHashSet<>();
            Object claim = jwt.getClaims().get(cfg.getRolesClaim());
            if (claim instanceof Collection<?> c) c.forEach(v -> raw.add(String.valueOf(v)));
            else if (claim instanceof String s) raw.addAll(List.of(s.split("[,\s]+")));
            Set<Role> roles = EnumSet.noneOf(Role.class);
            for (String r : raw) {
                Role role = Role.parse(r);
                if (role != null) roles.add(role);
            }
            boolean platformAdmin = raw.stream().anyMatch(r -> r.equalsIgnoreCase(cfg.getPlatformAdminRole()));
            String tenant = jwt.getClaimAsString(cfg.getTenantClaim());
            String subject = jwt.getClaimAsString("preferred_username");
            if (subject == null) subject = jwt.getSubject();
            return new CallerAuthentication(new Caller(subject, tenant, roles, platformAdmin), jwt);
        }
    }
}
