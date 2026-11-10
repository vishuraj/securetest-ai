package com.securetest.autoconfigure.servlet;

import com.securetest.autoconfigure.SecureTestProperties;
import com.securetest.autoconfigure.security.DashboardGate;
import com.securetest.autoconfigure.security.RequestInfo;
import com.securetest.autoconfigure.security.SecureTestPrincipal;
import com.securetest.autoconfigure.service.TelemetryService;
import com.securetest.autoconfigure.web.ApiExceptionHandler;
import com.securetest.autoconfigure.web.EndpointCatalog;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.core.MethodParameter;
import org.springframework.core.Ordered;
import org.springframework.http.CacheControl;
import org.springframework.web.bind.support.WebDataBinderFactory;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.method.support.ModelAndViewContainer;
import org.springframework.web.servlet.DispatcherServlet;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.web.servlet.mvc.method.RequestMappingInfo;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/** Spring MVC (Servlet) wiring: gate filter, metrics filter, static dashboard, argument resolvers, Spring Security exemption. */
@Configuration(proxyBeanMethods = false)
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@ConditionalOnClass(DispatcherServlet.class)
@Import({ApiExceptionHandler.class, ServletWebConfiguration.SpringSecurityExemption.class})
public class ServletWebConfiguration {

    static final String UI_LOCATION = "classpath:/META-INF/securetest-ui/";

    @Bean
    FilterRegistrationBean<ServletGateFilter> secureTestGateFilter(DashboardGate gate) {
        FilterRegistrationBean<ServletGateFilter> reg = new FilterRegistrationBean<>(new ServletGateFilter(gate));
        reg.addUrlPatterns(gate.basePath(), gate.basePath() + "/*");
        reg.setName("secureTestGateFilter");
        reg.setOrder(0); // after Spring Security (-100) so "container" authentication can see the host principal
        return reg;
    }

    /** /.well-known/security.txt (RFC 9116), only when the disclosure program is on; served before any host security. */
    @Bean
    @org.springframework.boot.autoconfigure.condition.ConditionalOnProperty(prefix = "securetest.disclosure", name = "enabled", havingValue = "true")
    FilterRegistrationBean<OncePerRequestFilter> secureTestSecurityTxtFilter(SecureTestProperties props) {
        OncePerRequestFilter f = new OncePerRequestFilter() {
            @Override
            protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain) throws ServletException, IOException {
                String origin = req.getScheme() + "://" + req.getServerName()
                        + ((req.getServerPort() == 80 && "http".equals(req.getScheme())) || (req.getServerPort() == 443 && "https".equals(req.getScheme())) ? "" : ":" + req.getServerPort())
                        + req.getContextPath();
                String body = com.securetest.autoconfigure.disclosure.SecurityTxt.render(props, origin);
                if (body == null || !"GET".equals(req.getMethod())) {
                    chain.doFilter(req, res);
                    return;
                }
                res.setContentType("text/plain;charset=UTF-8");
                res.setHeader("Cache-Control", "max-age=86400");
                res.getWriter().write(body);
            }
        };
        FilterRegistrationBean<OncePerRequestFilter> reg = new FilterRegistrationBean<>(f);
        reg.addUrlPatterns(com.securetest.autoconfigure.disclosure.SecurityTxt.PATH);
        reg.setName("secureTestSecurityTxt");
        reg.setOrder(org.springframework.core.Ordered.HIGHEST_PRECEDENCE + 5);
        return reg;
    }

    @Bean
    FilterRegistrationBean<OncePerRequestFilter> secureTestHttpMetricsFilter(TelemetryService telemetry, SecureTestProperties props) {
        String excluded = props.normalizedPath() + "/";
        OncePerRequestFilter f = new OncePerRequestFilter() {
            @Override
            protected boolean shouldNotFilter(HttpServletRequest request) {
                return !telemetry.httpRecording() || request.getRequestURI().contains(excluded);
            }

            @Override
            protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain) throws ServletException, IOException {
                long start = System.nanoTime();
                try {
                    chain.doFilter(req, res);
                } finally {
                    telemetry.http().record((System.nanoTime() - start) / 1_000_000, res.getStatus());
                }
            }
        };
        FilterRegistrationBean<OncePerRequestFilter> reg = new FilterRegistrationBean<>(f);
        reg.addUrlPatterns("/*");
        reg.setName("secureTestHttpMetricsFilter");
        reg.setOrder(Ordered.HIGHEST_PRECEDENCE + 20);
        return reg;
    }

    @Bean
    WebMvcConfigurer secureTestWebMvc(SecureTestProperties props) {
        String path = props.normalizedPath();
        return new WebMvcConfigurer() {
            @Override
            public void addResourceHandlers(ResourceHandlerRegistry registry) {
                registry.addResourceHandler(path + "/**").addResourceLocations(UI_LOCATION).setCacheControl(CacheControl.noCache());
            }

            @Override
            public void addViewControllers(ViewControllerRegistry registry) {
                registry.addRedirectViewController(path, path + "/");
                registry.addViewController(path + "/").setViewName("forward:" + path + "/index.html");
            }

            @Override
            public void addArgumentResolvers(List<HandlerMethodArgumentResolver> resolvers) {
                resolvers.add(new HandlerMethodArgumentResolver() {
                    @Override
                    public boolean supportsParameter(MethodParameter p) {
                        return p.getParameterType() == SecureTestPrincipal.class || p.getParameterType() == RequestInfo.class;
                    }

                    @Override
                    public Object resolveArgument(MethodParameter p, ModelAndViewContainer m, NativeWebRequest req, WebDataBinderFactory b) {
                        String key = p.getParameterType() == SecureTestPrincipal.class ? SecureTestPrincipal.REQUEST_ATTRIBUTE : RequestInfo.REQUEST_ATTRIBUTE;
                        return req.getAttribute(key, RequestAttributes.SCOPE_REQUEST);
                    }
                });
            }
        };
    }

    @Bean
    EndpointCatalog secureTestEndpointCatalog(ApplicationContext context) {
        return () -> {
            List<EndpointCatalog.Endpoint> out = new ArrayList<>();
            RequestMappingHandlerMapping mapping = context.getBean("requestMappingHandlerMapping", RequestMappingHandlerMapping.class);
            for (Map.Entry<RequestMappingInfo, HandlerMethod> e : mapping.getHandlerMethods().entrySet()) {
                HandlerMethod hm = e.getValue();
                if (!hm.getBeanType().getPackageName().startsWith("com.securetest")) continue;
                for (String p : e.getKey().getPatternValues()) {
                    e.getKey().getMethodsCondition().getMethods().forEach(m -> out.add(new EndpointCatalog.Endpoint(p, m.name(), hm.getMethod(), hm.getBeanType())));
                }
            }
            return out;
        };
    }

    /**
     * Lets the dashboard work in applications secured by Spring Security without any configuration: Spring Security
     * ignores {@code /securetest/**} and SecureTest's own gate authenticates those requests. A WebSecurityCustomizer (unlike
     * a SecurityFilterChain bean) leaves Spring Boot's default security for the rest of the application untouched.
     * Skipped for provider=container, where the host's Spring Security must authenticate the dashboard user.
     */
    @Configuration(proxyBeanMethods = false)
    @ConditionalOnClass(name = "org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer")
    static class SpringSecurityExemption {
        @Bean
        org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer secureTestWebSecurityCustomizer(SecureTestProperties props) {
            String base = props.normalizedPath();
            boolean container = "container".equalsIgnoreCase(props.getDashboard().getAuthentication().getProvider());
            return web -> {
                if (container) return;
                web.ignoring().requestMatchers(request -> {
                    String uri = request.getRequestURI();
                    String ctx = request.getContextPath();
                    String path = ctx != null && !ctx.isEmpty() && uri.startsWith(ctx) ? uri.substring(ctx.length()) : uri;
                    return path.equals(base) || path.startsWith(base + "/");
                });
            };
        }
    }
}
