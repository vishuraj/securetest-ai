package com.securetest.core.model;

import java.time.Instant;
import java.util.Map;

/**
 * Tamper-evident audit record (SEC-008). Each event carries the hash of the previous event,
 * forming a hash chain that {@code AuditService.verify()} can check.
 */
public record AuditEvent(
        long sequence,
        String id,
        Instant timestamp,
        String actor,
        String action,
        String target,
        String outcome,
        String correlationId,
        String remoteAddress,
        Map<String, String> details,
        String previousHash,
        String hash) {
}
