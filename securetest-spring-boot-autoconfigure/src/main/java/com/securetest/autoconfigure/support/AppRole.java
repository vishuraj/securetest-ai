package com.securetest.autoconfigure.support;

import com.securetest.core.model.ModuleCatalog;

import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.function.Predicate;

/**
 * What this application is in a microservice system, so the starter can sit in a parent POM and still do the right thing
 * in every module: business services get every module; Spring Cloud infrastructure apps (config server, service registry,
 * gateway, admin server) get runtime modules only, because they hold little code of their own to test or analyse.
 */
public record AppRole(Kind kind, String detail, boolean detected) {

    public enum Kind { SERVICE, INFRA }

    /** Modules that analyse or change the application's own source code: off and locked for infrastructure apps. */
    public static final Set<String> SOURCE_MODULES = Set.of(ModuleCatalog.TESTING, ModuleCatalog.CODE_QUALITY, ModuleCatalog.MIGRATION);

    private record Marker(String className, String label) { }

    private static final List<Marker> INFRA_MARKERS = List.of(
            new Marker("org.springframework.cloud.config.server.EnableConfigServer", "Spring Cloud Config Server"),
            new Marker("org.springframework.cloud.netflix.eureka.server.EnableEurekaServer", "Eureka service registry"),
            new Marker("org.springframework.cloud.gateway.route.RouteLocator", "Spring Cloud Gateway"),
            new Marker("org.springframework.cloud.gateway.server.mvc.handler.GatewayRouterFunctions", "Spring Cloud Gateway (MVC)"),
            new Marker("de.codecentric.boot.admin.server.config.EnableAdminServer", "Spring Boot Admin server"));

    public static AppRole service() {
        return new AppRole(Kind.SERVICE, "Application service", false);
    }

    public static AppRole resolve(String configured, Predicate<String> classPresent) {
        String c = configured == null ? "auto" : configured.trim().toLowerCase(Locale.ROOT);
        if (c.equals("service")) return new AppRole(Kind.SERVICE, "Application service (securetest.role=service)", false);
        if (c.equals("infra")) return new AppRole(Kind.INFRA, "Infrastructure service (securetest.role=infra)", false);
        for (Marker m : INFRA_MARKERS) {
            if (classPresent.test(m.className())) return new AppRole(Kind.INFRA, m.label(), true);
        }
        return service();
    }

    public boolean infra() {
        return kind == Kind.INFRA;
    }

    public String id() {
        return kind.name().toLowerCase(Locale.ROOT);
    }

    /** True when the module is switched off because this is an infrastructure app. */
    public boolean excludes(String moduleId) {
        return infra() && SOURCE_MODULES.contains(moduleId);
    }
}
