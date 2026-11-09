package com.securetest.core.spi;

/** Result of a single preflight check (connectivity, tool availability, allowlist, limits). */
public record PreflightCheck(String name, Level level, String message) {

    public enum Level { OK, WARN, ERROR }

    public static PreflightCheck ok(String name, String message) { return new PreflightCheck(name, Level.OK, message); }
    public static PreflightCheck warn(String name, String message) { return new PreflightCheck(name, Level.WARN, message); }
    public static PreflightCheck error(String name, String message) { return new PreflightCheck(name, Level.ERROR, message); }

    public boolean blocking() { return level == Level.ERROR; }
}
