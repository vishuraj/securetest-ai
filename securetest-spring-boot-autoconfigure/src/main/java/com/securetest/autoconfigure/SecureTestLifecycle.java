package com.securetest.autoconfigure;

import com.securetest.autoconfigure.service.ModuleService;
import com.securetest.autoconfigure.service.PlatformServices.ControlPlaneClient;
import com.securetest.autoconfigure.service.ScannerRegistry;
import com.securetest.autoconfigure.support.AppContext;
import com.securetest.core.model.ModuleCatalog;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.ApplicationListener;

import java.util.List;

/** Prints where the dashboard lives, warns about unsafe exposure (SRS 9.1) and starts connected mode without blocking startup. */
public class SecureTestLifecycle implements ApplicationListener<ApplicationReadyEvent> {

    private static final Logger log = LoggerFactory.getLogger("SecureTest");

    private final SecureTestProperties props;
    private final AppContext app;
    private final ControlPlaneClient controlPlane;
    private final ScannerRegistry registry;
    private final ModuleService modules;

    public SecureTestLifecycle(SecureTestProperties props, AppContext app, ControlPlaneClient controlPlane, ScannerRegistry registry, ModuleService modules) {
        this.props = props;
        this.app = app;
        this.controlPlane = controlPlane;
        this.registry = registry;
        this.modules = modules;
    }

    @Override
    public void onApplicationEvent(ApplicationReadyEvent event) {
        String bind = props.getDashboard().getBindAddress();
        boolean loopback = bind == null || bind.startsWith("127.") || bind.equals("::1") || bind.equalsIgnoreCase("localhost");
        var auth = props.getDashboard().getAuthentication();
        long enabled = ModuleCatalog.MODULES.stream().filter(m -> modules.isEnabled(m.id())).count();
        log.info("SecureTest dashboard: {}{}/  ({} scanners available, {} of {} modules enabled, auth={}, {})",
                app.selfBaseUrl(), props.normalizedPath(), registry.size(), enabled, ModuleCatalog.MODULES.size(),
                auth.isEnabled() ? auth.getProvider() : "disabled", loopback ? "loopback only" : "network: " + bind);
        if (!loopback && (!auth.isEnabled() || "local-dev".equalsIgnoreCase(auth.getProvider()))) {
            log.warn("SecureTest: the dashboard is configured for network access (bind-address={}) without basic/container authentication. "
                    + "Remote clients will be rejected. Configure securetest.dashboard.authentication.provider=basic|container and TLS.", bind);
        }
        if (!auth.isEnabled()) {
            log.warn("SecureTest: dashboard authentication is DISABLED. Only loopback clients are served.");
        }
        if (app.productionLike()) {
            log.warn("SecureTest: dashboard explicitly enabled under a production profile. Keep it protected; source changes are blocked in this mode.");
        }
        if (props.getSecurity().isAllowAutoRemediation()) {
            log.info("SecureTest: assisted remediation is enabled by policy (securetest.security.allow-auto-remediation=true).");
        }
        controlPlane.start(List.of(ModuleCatalog.MODULES.stream().map(ModuleCatalog.ModuleInfo::id).toArray(String[]::new)));
    }
}
