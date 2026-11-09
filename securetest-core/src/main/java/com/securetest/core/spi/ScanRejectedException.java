package com.securetest.core.spi;

/** Thrown when a scan or action is refused by policy (scope, allowlist, permissions, missing approval...). */
public class ScanRejectedException extends RuntimeException {
    public ScanRejectedException(String message) {
        super(message);
    }
}
