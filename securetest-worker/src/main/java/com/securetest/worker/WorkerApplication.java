package com.securetest.worker;

import com.securetest.worker.sandbox.SandboxMain;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

import java.util.Arrays;
import java.util.Map;

/**
 * SecureTest AI remote worker.
 * <ul>
 *   <li>{@code java -jar securetest-worker-exec.jar} runs the worker (polls the control plane);</li>
 *   <li>{@code java -jar securetest-worker-exec.jar sandbox <request.json> <result.json>} runs exactly one scan
 *       and exits. This is what the worker starts inside the sandbox container (or child process).</li>
 * </ul>
 */
@SpringBootApplication
@EnableConfigurationProperties(WorkerProperties.class)
public class WorkerApplication {

    public static void main(String[] args) throws Exception {
        if (args.length > 0 && "sandbox".equals(args[0])) {
            SandboxMain.main(Arrays.copyOfRange(args, 1, args.length));
            return;
        }
        builder().run(args);
    }

    public static SpringApplicationBuilder builder() {
        return new SpringApplicationBuilder(WorkerApplication.class).properties(Map.of(
                "spring.application.name", "securetest-worker",
                "spring.main.web-application-type", "none"));
    }
}
