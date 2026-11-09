package com.securetest.adapters.external;

import com.securetest.core.spi.CommandRunner;
import com.securetest.core.spi.PreflightCheck;
import com.securetest.core.spi.ScanContext;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

/** Shared preflight / version helpers for adapters that run installed CLI tools. */
final class ExternalTools {
    private ExternalTools() { }

    static List<PreflightCheck> toolChecks(ScanContext ctx, String exe, String installHint) {
        List<PreflightCheck> out = new ArrayList<>();
        CommandRunner r = ctx.commands();
        out.add(r.isAllowed(exe) ? PreflightCheck.ok("Command allowlist", exe + " is allowlisted")
                : PreflightCheck.error("Command allowlist", "Add '" + exe + "' to securetest.execution.allowed-commands to enable this adapter."));
        out.add(r.locate(exe).isPresent() ? PreflightCheck.ok("Tool installed", r.locate(exe).get().toString())
                : PreflightCheck.error("Tool installed", exe + " was not found on the PATH. " + installHint));
        return out;
    }

    static String version(ScanContext ctx, String exe, String... args) {
        try {
            List<String> cmd = new ArrayList<>();
            cmd.add(exe);
            cmd.addAll(List.of(args));
            CommandRunner.CommandResult res = ctx.commands().run(cmd, null, Duration.ofSeconds(30));
            String out = (res.stdout() + " " + res.stderr()).trim();
            java.util.regex.Matcher m = java.util.regex.Pattern.compile("(\\d+\\.\\d+(\\.\\d+)?)").matcher(out);
            return m.find() ? m.group(1) : "unknown";
        } catch (Exception e) {
            return "unknown";
        }
    }
}
