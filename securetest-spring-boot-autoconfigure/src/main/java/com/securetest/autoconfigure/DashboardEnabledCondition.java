package com.securetest.autoconfigure;

import org.springframework.boot.autoconfigure.condition.ConditionOutcome;
import org.springframework.boot.autoconfigure.condition.SpringBootCondition;
import org.springframework.context.annotation.ConditionContext;
import org.springframework.core.type.AnnotatedTypeMetadata;

/**
 * The dashboard is on by default in every environment. In production it is never open: the gate requires sign-in
 * (generated admin password, configured users, OIDC or container authentication). Set securetest.dashboard.enabled=false
 * to switch it off.
 */
class DashboardEnabledCondition extends SpringBootCondition {

    @Override
    public ConditionOutcome getMatchOutcome(ConditionContext context, AnnotatedTypeMetadata metadata) {
        String explicit = context.getEnvironment().getProperty("securetest.dashboard.enabled");
        return explicit == null || Boolean.parseBoolean(explicit)
                ? ConditionOutcome.match("dashboard enabled")
                : ConditionOutcome.noMatch("securetest.dashboard.enabled=false");
    }
}
