package com.securetest.adapters.builtin;

import com.securetest.adapters.support.ScanSupport;
import com.securetest.core.model.Enums.ExecutionLocation;
import com.securetest.core.model.Enums.FieldType;
import com.securetest.core.model.Enums.ScanMode;
import com.securetest.core.model.ModuleCatalog;
import com.securetest.core.spi.CommandRunner;
import com.securetest.core.spi.FieldSpec;
import com.securetest.core.spi.PreflightCheck;
import com.securetest.core.spi.ScanContext;
import com.securetest.core.spi.Scanner;
import com.securetest.core.spi.ScannerDescriptor;

import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Runs an allowlisted test command (e.g. {@code mvn -B test}) in a separate process, then imports the
 * results. Never runs automatically (SRS 5.4): the command must be allowlisted and the run confirmed.
 */
public class TestRunnerScanner implements Scanner {

    public static final String ID = "test-runner";

    @Override
    public ScannerDescriptor descriptor() {
        return ScannerDescriptor.builder(ID, ModuleCatalog.TESTING, "Run test suite (unit / integration / regression / Selenium / Appium)")
                .purpose("Starts your build tool (or a Selenium / Appium suite)'s test command as a separate OS process in the workspace, then imports the "
                        + "JUnit/TestNG and JaCoCo reports it produces. Use profiles/arguments to select unit, integration or regression suites.")
                .access("Executes an allowlisted command in the source workspace with the application's OS user.")
                .mode(ScanMode.RESOURCE_INTENSIVE).location(ExecutionLocation.EXTERNAL_TOOL)
                .requiresSourceRoot()
                .tool("Maven / Gradle", "installed")
                .duration("Depends on the suite (minutes)")
                .resources("Separate JVM: CPU and memory of your normal test run")
                .prerequisite("The executable (mvn, mvnw, gradle, gradlew) is listed in securetest.execution.allowed-commands")
                .field(FieldSpec.required("command", "Test command", FieldType.TEXT, "mvn -B -q test",
                        "Executable and arguments, e.g. 'mvn -B verify -Pintegration' or 'gradlew test'. No shell operators."))
                .field(FieldSpec.number("timeoutMinutes", "Timeout (minutes)", 20, 1, 240, "The process is killed after this time."))
                .field(FieldSpec.number("minLineCoverage", "Minimum line coverage %", 60, 0, 100, ""))
                .field(FieldSpec.optional("suite", "Suite type", FieldType.TEXT, "unit",
                        "Label for trends: unit, module, integration, regression, api, ui (Selenium), device (Appium)."))
                .field(FieldSpec.optional("deviceLabel", "Device / browser label", FieldType.TEXT, "",
                        "For Selenium/Appium suites: e.g. 'Android 14 / Pixel 8' or 'Chrome 129 / Windows'. Builds the device matrix."))
                .build();
    }

    @Override
    public List<PreflightCheck> preflight(ScanContext ctx) {
        List<PreflightCheck> out = new ArrayList<>();
        String cmd = ctx.option("command", "mvn -B -q test").trim();
        String exe = cmd.split("\\s+")[0];
        CommandRunner r = ctx.commands();
        out.add(r.isAllowed(exe) ? PreflightCheck.ok("Command allowlist", exe + " is allowlisted")
                : PreflightCheck.error("Command allowlist", exe + " is not in securetest.execution.allowed-commands"));
        out.add(r.locate(exe).isPresent() || (ctx.sourceRoot().isPresent() && ctx.sourceRoot().get().resolve(exe).toFile().exists())
                ? PreflightCheck.ok("Executable", exe + " found") : PreflightCheck.warn("Executable", exe + " was not found on the PATH"));
        if (ctx.sourceRoot().isEmpty()) out.add(PreflightCheck.error("Source workspace", "No source workspace configured."));
        return out;
    }

    @Override
    public void scan(ScanContext ctx) throws Exception {
        Path root = ScanSupport.requireSource(ctx);
        List<String> command = new ArrayList<>(Arrays.asList(ctx.option("command", "mvn -B -q test").trim().split("\\s+")));
        Path local = root.resolve(command.get(0));
        if (local.toFile().isFile()) command.set(0, local.toString());
        ctx.progress(5, "Running " + String.join(" ", command));
        CommandRunner.CommandResult r = ctx.commands().run(command, root, Duration.ofMinutes(ctx.intOption("timeoutMinutes", 20, 1, 240)));
        ctx.log("Exit code " + r.exitCode() + " after " + r.durationMs() / 1000 + "s" + (r.timedOut() ? " (timed out)" : ""));
        String tail = r.stdout().length() > 4000 ? r.stdout().substring(r.stdout().length() - 4000) : r.stdout();
        ctx.putResult("commandOutputTail", tail);
        ctx.putResult("exitCode", r.exitCode());
        ctx.putResult("suite", ctx.option("suite", "unit"));
        if (!ctx.option("deviceLabel", "").isBlank()) ctx.putResult("device", ctx.option("deviceLabel", ""));
        ctx.progress(60, "Importing results");
        TestResultsScanner.importResults(ctx, root, "", ctx.intOption("minLineCoverage", 60, 0, 100), ID);
        if (r.timedOut()) throw new IllegalStateException("Test command timed out");
    }
}
