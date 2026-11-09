package com.securetest.autoconfigure;

import org.springframework.boot.autoconfigure.condition.ConditionOutcome;
import org.springframework.boot.autoconfigure.condition.SpringBootCondition;
import org.springframework.context.annotation.ConditionContext;
import org.springframework.core.type.AnnotatedTypeMetadata;

import java.util.Arrays;
import java.util.Locale;

/**
 * The dashboard is on by default for developer convenience, except under production-like profiles where it must be
 * enabled explicitly (SRS 9.1: adding a dependency must not silently create an admin endpoint in production).
 */
class DashboardEnabledCondition extends SpringBootCondition {

    @Override
    public ConditionOutcome getMatchOutcome(ConditionContext context, AnnotatedTypeMetadata metadata) {
        String explicit = context.getEnvironment().getProperty("securetest.dashboard.enabled");
        if (explicit != null) {
            return Boolean.parseBoolean(explicit) ? ConditionOutcome.match("securetest.dashboard.enabled=true")
                    : ConditionOutcome.noMatch("securetest.dashboard.enabled=false");
        }
        boolean prod = Arrays.stream(context.getEnvironment().getActiveProfiles())
                .map(p -> p.toLowerCase(Locale.ROOT)).anyMatch(p -> p.equals("prod") || p.equals("production") || p.equals("live"));
        return prod ? ConditionOutcome.noMatch("production profile active; set securetest.dashboard.enabled=true to opt in")
                : ConditionOutcome.match("non-production profile");
    }
}
