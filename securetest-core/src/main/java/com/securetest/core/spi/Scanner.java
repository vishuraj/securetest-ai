package com.securetest.core.spi;

import java.util.ArrayList;
import java.util.List;

/**
 * Port for every scanner / tool adapter (ports-and-adapters, SRS 4.4).
 * <p>
 * Implementations are discovered as Spring beans, so adopters can add their own scanners
 * by declaring a {@code @Bean} of this type. A scanner must:
 * <ul>
 *   <li>describe its inputs, impact and permissions through {@link #descriptor()} (drives the UI modal);</li>
 *   <li>never contact a host without going through {@link ScanContext#http()} or {@link ScanContext#targets()};</li>
 *   <li>check {@link ScanContext#cancelled()} regularly and stop promptly.</li>
 * </ul>
 */
public interface Scanner {

    ScannerDescriptor descriptor();

    /** Environment / tool checks run before a job is created. Default: none. */
    default List<PreflightCheck> preflight(ScanContext context) {
        return new ArrayList<>();
    }

    /** Executes the scan. Findings are emitted through {@link ScanContext#report}. */
    void scan(ScanContext context) throws Exception;
}
