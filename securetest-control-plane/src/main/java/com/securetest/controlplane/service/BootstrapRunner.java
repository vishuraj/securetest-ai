package com.securetest.controlplane.service;

import com.securetest.controlplane.ControlPlaneProperties;
import com.securetest.controlplane.store.AuditStore;
import com.securetest.controlplane.store.InventoryStore;
import com.securetest.controlplane.store.TenantStore;
import com.securetest.core.util.Hashing;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

/** Seeds the bootstrap tenant and enrollment token on first start (idempotent). */
@Component
public class BootstrapRunner implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(BootstrapRunner.class);

    private final ControlPlaneProperties props;
    private final TenantStore tenants;
    private final InventoryStore inventory;
    private final AuditStore audit;

    public BootstrapRunner(ControlPlaneProperties props, TenantStore tenants, InventoryStore inventory, AuditStore audit) {
        this.props = props;
        this.tenants = tenants;
        this.inventory = inventory;
        this.audit = audit;
    }

    @Override
    public void run(ApplicationArguments args) {
        var b = props.getBootstrap();
        if (b.getTenantSlug() == null || b.getTenantSlug().isBlank()) {
            if (props.getWorkers().getTokens().isEmpty()) {
                log.warn("No worker tokens configured (securetest.control-plane.workers.tokens): remote workers cannot connect.");
            }
            return;
        }
        TenantStore.Tenant tenant = tenants.findBySlug(b.getTenantSlug()).orElseGet(() -> {
            TenantStore.Tenant t = tenants.create(b.getTenantSlug(), b.getTenantName() == null ? b.getTenantSlug() : b.getTenantName());
            audit.append(null, "bootstrap", "TENANT_CREATED", "tenant:" + t.slug(), null);
            log.info("Created bootstrap tenant '{}'", t.slug());
            return t;
        });
        inventory.defaultProject(tenant.id());
        String token = b.getEnrollmentToken();
        if (token != null && !token.isBlank()) {
            if (token.length() < 16) throw new IllegalStateException("Bootstrap enrollment token must be at least 16 characters");
            String hash = Hashing.sha256(token.trim());
            if (!tenants.enrollmentTokenExists(hash)) {
                tenants.addEnrollmentToken(tenant.id(), hash, "bootstrap", "bootstrap");
                audit.append(tenant.id(), "bootstrap", "ENROLLMENT_TOKEN_CREATED", "tenant:" + tenant.slug(), "bootstrap token");
            }
        }
    }
}
