package com.securetest.autoconfigure.reactive;

import com.securetest.autoconfigure.security.DashboardGate;
import com.securetest.autoconfigure.security.GateResponse;
import com.securetest.autoconfigure.security.RequestInfo;
import com.securetest.autoconfigure.security.SecureTestPrincipal;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import org.springframework.web.server.WebHandler;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.nio.charset.StandardCharsets;
import java.security.Principal;
import java.util.Optional;

/**
 * Applies the {@link DashboardGate} to dashboard requests on WebFlux.
 * <p>
 * For the built-in providers the filter runs before every other WebFilter (including Spring Security's) and, once the
 * gate lets a request through, hands it straight to the {@code DispatcherHandler}. That keeps the dashboard working in
 * reactive applications secured by Spring Security without changing the application's own security rules.
 * For provider=container it runs after Spring Security and uses the authenticated principal.
 */
public class ReactiveGateFilter implements WebFilter, Ordered {

    private final DashboardGate gate;
    private final WebHandler dispatcher;
    private final boolean container;

    public ReactiveGateFilter(DashboardGate gate, WebHandler dispatcher) {
        this.gate = gate;
        this.dispatcher = dispatcher;
        this.container = "container".equals(gate.provider());
    }

    @Override
    public int getOrder() {
        return container ? 0 : Ordered.HIGHEST_PRECEDENCE + 5;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        String path = exchange.getRequest().getPath().pathWithinApplication().value();
        if (!gate.applies(path)) return chain.filter(exchange);
        String base = gate.basePath();
        if (path.equals(base)) { // same behaviour as Spring MVC: /securetest -> /securetest/
            exchange.getResponse().setStatusCode(HttpStatus.FOUND);
            exchange.getResponse().getHeaders().setLocation(java.net.URI.create(exchange.getRequest().getPath().contextPath().value() + base + "/"));
            return exchange.getResponse().setComplete();
        }
        ServerWebExchange target = path.equals(base + "/")
                ? exchange.mutate().request(r -> r.path(exchange.getRequest().getPath().contextPath().value() + base + "/index.html")).build()
                : exchange;
        Mono<Optional<Principal>> principal = container
                ? exchange.getPrincipal().map(Optional::of).defaultIfEmpty(Optional.empty())
                : Mono.just(Optional.empty());
        return principal
                // the gate may call the identity provider (OIDC) and read files: keep it off the event loop
                .flatMap(p -> Mono.fromCallable(() -> gate.handle(new ReactiveGateRequest(exchange, p.orElse(null))))
                        .subscribeOn(Schedulers.boundedElastic()))
                .flatMap(d -> {
                    GateResponse g = d.response();
                    ServerHttpResponse res = target.getResponse();
                    g.headers().forEach((k, v) -> res.getHeaders().set(k, v));
                    g.cookies().forEach(c -> res.getHeaders().add("Set-Cookie", c));
                    if (!d.proceed()) {
                        res.setStatusCode(HttpStatus.valueOf(g.status()));
                        if (g.body() == null) return res.setComplete();
                        res.getHeaders().setContentType(MediaType.parseMediaType(g.contentType()));
                        DataBuffer buf = res.bufferFactory().wrap(g.body().getBytes(StandardCharsets.UTF_8));
                        return res.writeWith(Mono.just(buf));
                    }
                    target.getAttributes().put(RequestInfo.REQUEST_ATTRIBUTE, d.info());
                    if (d.principal() != null) target.getAttributes().put(SecureTestPrincipal.REQUEST_ATTRIBUTE, d.principal());
                    return container ? chain.filter(target) : dispatcher.handle(target);
                });
    }
}
