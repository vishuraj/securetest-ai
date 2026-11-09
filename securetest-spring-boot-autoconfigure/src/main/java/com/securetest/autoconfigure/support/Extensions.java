package com.securetest.autoconfigure.support;

import java.util.List;
import java.util.Map;

/** Optional integrations bridged in only when the corresponding library is on the classpath. */
public final class Extensions {
    private Extensions() { }

    /** Bridges Spring Boot Actuator health (status + component statuses only, never details). */
    public interface HealthSource {
        Map<String, Object> health();
    }

    /** Bridges Spring's MailSender (spring-boot-starter-mail) for e-mail notifications. */
    public interface MailBridge {
        void send(String from, List<String> to, String subject, String body);
    }

    /** Bridges custom Micrometer meters registered by the application. */
    public interface MeterSource {
        List<Map<String, Object>> customMeters();

        /** Optional HTTP server metrics from http.server.requests: count, errors, mean/max ms. */
        Map<String, Object> httpServerRequests();
    }
}
