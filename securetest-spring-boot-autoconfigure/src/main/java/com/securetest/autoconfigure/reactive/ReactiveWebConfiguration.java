package com.securetest.autoconfigure.reactive;

import com.securetest.autoconfigure.SecureTestProperties;
import com.securetest.autoconfigure.security.DashboardGate;
import com.securetest.autoconfigure.security.RequestInfo;
import com.securetest.autoconfigure.security.SecureTestPrincipal;
import com.securetest.autoconfigure.service.TelemetryService;
import com.securetest.autoconfigure.web.EndpointCatalog;
import com.securetest.autoconfigure.web.ReactiveApiExceptionHandler;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.core.MethodParameter;
import org.springframework.core.Ordered;
import org.springframework.core.task.support.TaskExecutorAdapter;
import org.springframework.http.CacheControl;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.reactive.BindingContext;
import org.springframework.web.reactive.config.BlockingExecutionConfigurer;
import org.springframework.web.reactive.config.ResourceHandlerRegistry;
import org.springframework.web.reactive.config.WebFluxConfigurer;
import org.springframework.web.reactive.result.method.RequestMappingInfo;
import org.springframework.web.reactive.result.method.SyncHandlerMethodArgumentResolver;
import org.springframework.web.reactive.result.method.annotation.ArgumentResolverConfigurer;
import org.springframework.web.reactive.result.method.annotation.RequestMappingHandlerMapping;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebHandler;
import reactor.core.publisher.Mono;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;

/** Spring WebFlux wiring: gate filter, metrics filter, static dashboard, argument resolvers and blocking execution. */
@Configuration(proxyBeanMethods = false)
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.REACTIVE)
@ConditionalOnClass(name = "org.springframework.web.reactive.DispatcherHandler")
@Import(ReactiveApiExceptionHandler.class)
public class ReactiveWebConfiguration {

    static final String UI_LOCATION = "classpath:/META-INF/securetest-ui/";

    @Bean
    ReactiveGateFilter secureTestGateWebFilter(DashboardGate gate, @Qualifier("webHandler") WebHandler dispatcher) {
        return new ReactiveGateFilter(gate, dispatcher);
    }

    @Bean
    WebFilter secureTestHttpMetricsWebFilter(TelemetryService telemetry, SecureTestProperties props) {
        String excluded = props.normalizedPath() + "/";
        class MetricsFilter implements WebFilter, Ordered {
            @Override
            public Mono<Void> filter(ServerWebExchange exchange, org.springframework.web.server.WebFilterChain chain) {
                if (!telemetry.httpRecording() || exchange.getRequest().getPath().value().contains(excluded)) return chain.filter(exchange);
                long start = System.nanoTime();
                return chain.filter(exchange).doFinally(s -> {
                    var code = exchange.getResponse().getStatusCode();
                    telemetry.http().record((System.nanoTime() - start) / 1_000_000, code == null ? 200 : code.value());
                });
            }

            @Override
            public int getOrder() { return Ordered.HIGHEST_PRECEDENCE + 20; }
        }
        return new MetricsFilter();
    }

    @Bean
    WebFluxConfigurer secureTestWebFlux(SecureTestProperties props) {
        String path = props.normalizedPath();
        return new WebFluxConfigurer() {
            @Override
            public void addResourceHandlers(ResourceHandlerRegistry registry) {
                registry.addResourceHandler(path + "/**").addResourceLocations(UI_LOCATION).setCacheControl(CacheControl.noCache());
            }

            @Override
            public void configureArgumentResolvers(ArgumentResolverConfigurer configurer) {
                configurer.addCustomResolver(new SyncHandlerMethodArgumentResolver() {
                    @Override
                    public boolean supportsParameter(MethodParameter p) {
                        return p.getParameterType() == SecureTestPrincipal.class || p.getParameterType() == RequestInfo.class;
                    }

                    @Override
                    public Object resolveArgumentValue(MethodParameter p, BindingContext ctx, ServerWebExchange exchange) {
                        String key = p.getParameterType() == SecureTestPrincipal.class ? SecureTestPrincipal.REQUEST_ATTRIBUTE : RequestInfo.REQUEST_ATTRIBUTE;
                        return exchange.getAttribute(key);
                    }
                });
            }
        };
    }

    /**
     * SecureTest's API does blocking work (files, scanners, HTTP preflights): on Spring Framework 6.1+ (Boot 3.2+) it runs on
     * its own threads, never on the event loop. Spring Framework 6.0 (Boot 3.0/3.1) has no such hook; there the gate and
     * most handlers still run on Reactor's bounded-elastic threads (see {@link ReactiveGateFilter}).
     */
    @Configuration(proxyBeanMethods = false)
    @ConditionalOnClass(name = "org.springframework.web.reactive.config.BlockingExecutionConfigurer")
    static class BlockingExecution {

        @Bean
        WebFluxConfigurer secureTestBlockingExecution() {
            AtomicInteger seq = new AtomicInteger();
            TaskExecutorAdapter blocking = new TaskExecutorAdapter(Executors.newFixedThreadPool(8, r -> {
                Thread t = new Thread(r, "securetest-api-" + seq.incrementAndGet());
                t.setDaemon(true);
                return t;
            }));
            return new WebFluxConfigurer() {
                @Override
                public void configureBlockingExecution(BlockingExecutionConfigurer configurer) {
                    configurer.setExecutor(blocking);
                    configurer.setControllerMethodPredicate(m -> m.getBeanType().getPackageName().startsWith("com.securetest.autoconfigure"));
                }
            };
        }
    }

    @Bean
    EndpointCatalog secureTestEndpointCatalog(ApplicationContext context) {
        return () -> {
            List<EndpointCatalog.Endpoint> out = new ArrayList<>();
            RequestMappingHandlerMapping mapping = context.getBean("requestMappingHandlerMapping", RequestMappingHandlerMapping.class);
            for (Map.Entry<RequestMappingInfo, HandlerMethod> e : mapping.getHandlerMethods().entrySet()) {
                HandlerMethod hm = e.getValue();
                if (!hm.getBeanType().getPackageName().startsWith("com.securetest")) continue;
                e.getKey().getPatternsCondition().getPatterns().forEach(p ->
                        e.getKey().getMethodsCondition().getMethods().forEach(m ->
                                out.add(new EndpointCatalog.Endpoint(p.getPatternString(), m.name(), hm.getMethod(), hm.getBeanType()))));
            }
            return out;
        };
    }
}
