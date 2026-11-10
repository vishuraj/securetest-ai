package com.securetest.autoconfigure.footprint;

import com.securetest.autoconfigure.service.ModuleService;
import com.securetest.autoconfigure.service.PlatformServices.Housekeeping;
import com.securetest.autoconfigure.service.TelemetryService;
import com.securetest.core.model.ModuleCatalog;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.context.ConfigurableApplicationContext;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Adding the dependency to a production application must cost nothing until someone uses SecureTest: every module is off,
 * no background task is scheduled and nothing is written to disk.
 */
class ZeroFootprintTest {

    @SpringBootApplication
    static class App { }

    @Test
    void aFreshApplicationRunsNoSecureTestWork() {
        Path data = Path.of("target/zero-footprint-" + System.nanoTime());
        try (ConfigurableApplicationContext ctx = new SpringApplicationBuilder(App.class).properties(
                "server.port=0", "spring.main.web-application-type=servlet", "securetest.data.storage-dir=" + data).run()) {
            ModuleService modules = ctx.getBean(ModuleService.class);
            ModuleCatalog.MODULES.forEach(m -> assertThat(modules.isEnabled(m.id())).as(m.id()).isFalse());

            assertThat(ctx.getBean(Housekeeping.class).started()).as("housekeeping scheduled").isFalse();
            assertThat(ctx.getBean(TelemetryService.class).httpRecording()).as("HTTP timing").isFalse();
            assertThat(ctx.getBean(TelemetryService.class).sampling()).as("metrics sampler").isFalse();
            // only the generated sign-in password may exist; no data documents are written
            assertThat(data.resolve("modules.json")).doesNotExist();
            assertThat(Files.exists(data.resolve("jobs.json"))).isFalse();
        }
    }
}
