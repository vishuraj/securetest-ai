package com.securetest.worker;

import com.securetest.adapters.builtin.ActiveProbeScanner;
import com.securetest.adapters.builtin.ApiContractScanner;
import com.securetest.adapters.builtin.HttpSecurityScanner;
import com.securetest.adapters.builtin.LoadTestScanner;
import com.securetest.adapters.builtin.PortScanner;
import com.securetest.adapters.builtin.TlsScanner;
import com.securetest.adapters.external.JMeterAdapter;
import com.securetest.adapters.external.ProwlerAdapter;
import com.securetest.adapters.external.ZapAdapter;
import com.securetest.core.spi.Scanner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Scanner beans from {@code securetest-adapters} that can run away from the application: they need a network
 * target and no source workspace. Source-based scanners (SAST, secrets, SCA, IaC, tests) stay in the embedded
 * agent, which has the workspace. Adopters can add their own {@link Scanner} beans; they must have a public
 * no-argument constructor because the sandbox re-creates them by class name.
 */
@Configuration
public class WorkerScanners {

    @Bean HttpSecurityScanner workerHttpSecurity() { return new HttpSecurityScanner(); }
    @Bean ActiveProbeScanner workerActiveProbe() { return new ActiveProbeScanner(); }
    @Bean ApiContractScanner workerApiContract() { return new ApiContractScanner(); }
    @Bean TlsScanner workerTls() { return new TlsScanner(); }
    @Bean PortScanner workerPorts() { return new PortScanner(); }
    @Bean LoadTestScanner workerLoadTest() { return new LoadTestScanner(); }
    @Bean ZapAdapter workerZap() { return new ZapAdapter(); }
    @Bean JMeterAdapter workerJMeter() { return new JMeterAdapter(); }
    @Bean ProwlerAdapter workerProwler() { return new ProwlerAdapter(); }

    /** The scanners this worker serves, by id. */
    @Bean
    Catalog workerScannerCatalog(List<Scanner> scanners, WorkerProperties props) {
        return new Catalog(scanners, props.getScanners());
    }

    public static final class Catalog {
        private final Map<String, Scanner> byId = new LinkedHashMap<>();

        public Catalog(List<Scanner> scanners, List<String> include) {
            for (Scanner s : scanners) {
                var d = s.descriptor();
                boolean remoteCapable = d.isRequiresTarget() && !d.isRequiresSourceRoot();
                boolean included = include == null || include.isEmpty() || include.contains(d.getId());
                if (remoteCapable && included) byId.putIfAbsent(d.getId(), s);
            }
        }

        public Map<String, Scanner> scanners() { return byId; }

        public Scanner get(String id) { return byId.get(id); }
    }
}
