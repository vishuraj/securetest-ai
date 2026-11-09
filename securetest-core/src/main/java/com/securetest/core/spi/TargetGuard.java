package com.securetest.core.spi;

import java.net.URI;
import java.util.List;

/** Scope authorization for every network target (SEC-010). */
public interface TargetGuard {

    /** Validates scheme and host against the allowlist; throws {@link ScanRejectedException} otherwise. */
    URI requireAllowedUrl(String url);

    /** Validates a bare host name or IP address against the allowlist. */
    String requireAllowedHost(String host);

    boolean isAllowedHost(String host);

    /** Base URL of the host application itself, e.g. {@code http://localhost:8080}. */
    String selfBaseUrl();

    List<String> allowlist();
}
