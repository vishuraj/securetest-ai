package com.securetest.autoconfigure;

import com.securetest.autoconfigure.security.DashboardGate;
import com.securetest.autoconfigure.security.InitialAdminCredential;
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

/** Prints where the dashboard lives and how to sign in, and starts connected mode without blocking startup. */
public class SecureTestLifecycle implements ApplicationListener<ApplicationReadyEvent> {

    private static final Logger log = LoggerFactory.getLogger("SecureTest");

    private final SecureTestProperties props;
    private final AppContext app;
    private final ControlPlaneClient controlPlane;
    private final ScannerRegistry registry;
    private final ModuleService modules;
    private final DashboardGate gate;
    private final InitialAdminCredential initialAdmin;

    public SecureTestLifecycle(SecureTestProperties props, AppContext app, ControlPlaneClient controlPlane, ScannerRegistry registry,
                               ModuleService modules, DashboardGate gate, InitialAdminCredential initialAdmin) {
        this.props = props;
        this.app = app;
        this.controlPlane = controlPlane;
        this.registry = registry;
        this.modules = modules;
        this.gate = gate;
        this.initialAdmin = initialAdmin;
    }

    @Override
    public void onApplicationEvent(ApplicationReadyEvent event) {
        String url = app.selfBaseUrl() + props.normalizedPath() + "/";
        long enabled = ModuleCatalog.MODULES.stream().filter(m -> modules.isEnabled(m.id())).count();
        String access = gate.loopbackOnly() ? "local-only"
                : app.productionLike() ? "sign-in required (production profile)" : "local developers direct, sign-in from other machines";
        log.info("SecureTest dashboard: {}  ({} scanners, {} of {} modules enabled, auth={}, {})",
                url, registry.size(), enabled, ModuleCatalog.MODULES.size(), gate.provider(), access);
        if (gate.generatedAdminActive() && !gate.loopbackOnly()) {
            initialAdmin.announce(url);
        }
        if ("none".equals(gate.provider())) {
            log.warn("SecureTest: dashboard authentication is DISABLED. Only same-machine, non-production requests are served.");
        }
        if (app.productionLike()) {
            log.info("SecureTest: production profile active: dashboard sign-in is always required and source changes are blocked.");
        }
        if (props.getSecurity().isAllowAutoRemediation()) {
            log.info("SecureTest: assisted remediation is enabled by policy (securetest.security.allow-auto-remediation=true).");
        }
        controlPlane.start(List.of(ModuleCatalog.MODULES.stream().map(ModuleCatalog.ModuleInfo::id).toArray(String[]::new)));
    }
}
