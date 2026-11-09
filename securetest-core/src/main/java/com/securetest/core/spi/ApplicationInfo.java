package com.securetest.core.spi;

import java.time.Instant;
import java.util.List;

/** Identity of the host application (SRS 5.2). Contains nothing sensitive. */
public record ApplicationInfo(
        String name,
        String serviceId,
        String version,
        String environment,
        List<String> activeProfiles,
        String javaVersion,
        String javaVendor,
        String springBootVersion,
        String springFrameworkVersion,
        String buildTool,
        String host,
        Integer serverPort,
        String contextPath,
        Instant startedAt) {
}
