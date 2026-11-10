package com.securetest.autoconfigure;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.securetest.autoconfigure.security.ApiException;
import com.securetest.autoconfigure.service.ModuleService;
import com.securetest.autoconfigure.support.AppRole;
import com.securetest.autoconfigure.support.LocalStore;
import org.junit.jupiter.api.Test;

import java.nio.file.Path;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AppRoleTest {

    @Test
    void springCloudInfrastructureAppsAreDetected() {
        AppRole config = AppRole.resolve("auto", n -> n.endsWith("EnableConfigServer"));
        assertThat(config.infra()).isTrue();
        assertThat(config.detail()).isEqualTo("Spring Cloud Config Server");
        assertThat(AppRole.resolve("auto", n -> n.endsWith("EnableEurekaServer")).infra()).isTrue();
        assertThat(AppRole.resolve("auto", n -> n.endsWith("RouteLocator")).infra()).isTrue();
        assertThat(AppRole.resolve("auto", n -> false).infra()).isFalse();
        assertThat(AppRole.resolve("service", n -> true).infra()).isFalse(); // explicit setting wins
        assertThat(AppRole.resolve("infra", n -> false).infra()).isTrue();
    }

    @Test
    void infrastructureAppsKeepRuntimeModulesAndLockSourceModules() {
        SecureTestProperties props = new SecureTestProperties();
        props.module("testing").setEnabled(true); // e.g. switched on for every service from a shared config server
        LocalStore store = new LocalStore(Path.of("target/app-role-test"), false, new ObjectMapper());
        ModuleService modules = new ModuleService(props, store, AppRole.resolve("auto", n -> n.endsWith("EnableEurekaServer")));

        assertThat(modules.isEnabled("testing")).isFalse();
        assertThat(modules.isLocked("code-quality")).isTrue();
        assertThat(modules.source("migration")).contains("Eureka");
        assertThatThrownBy(() -> modules.set("testing", true, Map.of(), "alice")).isInstanceOf(ApiException.class);

        assertThat(modules.isEnabled("health")).isFalse(); // every module is off by default
        modules.set("metrics", true, Map.of(), "alice");
        assertThat(modules.isEnabled("metrics")).isTrue();
    }
}
