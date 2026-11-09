package com.securetest.autoconfigure;

import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.ApplicationListener;
import org.springframework.context.annotation.Bean;

/** FR-007: unsupported combinations get a warning instead of a crash. */
@AutoConfiguration
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.REACTIVE)
public class SecureTestCompatibilityAutoConfiguration {

    @Bean
    ApplicationListener<ApplicationReadyEvent> secureTestReactiveWarning() {
        return e -> LoggerFactory.getLogger("SecureTest").warn(
                "SecureTest: reactive (WebFlux) applications are not supported by the embedded dashboard in this release. "
                        + "Use CI/worker-based analysis or a servlet (Spring MVC) application.");
    }
}
