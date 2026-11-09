package com.securetest.controlplane.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.securetest.controlplane.security.ApiException;
import com.securetest.controlplane.store.AuditStore;
import com.securetest.controlplane.store.InventoryStore;
import com.securetest.controlplane.store.InventoryStore.Application;
import com.securetest.controlplane.store.InventoryStore.Environment;
import org.springframework.stereotype.Service;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Handles {@code POST /api/v1/agents/register} from the embedded starter's {@code ControlPlaneClient}.
 * The call doubles as a heartbeat: the agent repeats it every {@code securetest.control-plane.heartbeat}.
 */
@Service
public class RegistrationService {

    /** Payload sent by {@code PlatformServices.ControlPlaneClient}. Unknown fields are ignored. */
    public record AgentRegistration(String serviceId, String application, String environment, String version,
                                    Map<String, Object> runtime, String agentVersion, List<String> capabilities) { }

    private static final Pattern SAFE_ID = Pattern.compile("[\\w.:@/-]{1,200}");

    private final InventoryStore inventory;
    private final AuditStore audit;
    private final ObjectMapper mapper;

    public RegistrationService(InventoryStore inventory, AuditStore audit, ObjectMapper mapper) {
        this.inventory = inventory;
        this.audit = audit;
        this.mapper = mapper;
    }

    // Not transactional on purpose: get-or-create relies on unique-constraint violations, which would abort
    // an enclosing PostgreSQL transaction.
    public Map<String, Object> register(String tenantId, AgentRegistration req, String remoteAddress) {
        if (req == null || req.serviceId() == null || !SAFE_ID.matcher(req.serviceId()).matches()) {
            throw ApiException.badRequest("serviceId is required (letters, digits and . _ - : @ / only, max 200)");
        }
        String envName = req.environment() == null || req.environment().isBlank() ? "default" : req.environment().trim();
        if (!SAFE_ID.matcher(envName).matches() || envName.length() > 100) throw ApiException.badRequest("Invalid environment name");
        String name = req.application() == null || req.application().isBlank() ? req.serviceId() : truncate(req.application(), 200);

        Application app = inventory.upsertApplication(tenantId, req.serviceId(), name);
        Environment env = inventory.upsertEnvironment(tenantId, app.id(), envName);
        List<String> caps = req.capabilities() == null ? List.of()
                : req.capabilities().stream().limit(500).map(c -> truncate(String.valueOf(c), 200)).toList();
        boolean created = inventory.upsertAgent(tenantId, app.id(), env.id(), truncate(req.agentVersion(), 50),
                truncate(req.version(), 100), json(req.runtime()), json(caps), truncate(remoteAddress, 100));
        if (created) {
            audit.append(tenantId, "agent:" + req.serviceId(), "AGENT_REGISTERED", app.serviceId() + "/" + env.name(),
                    "agentVersion=" + req.agentVersion() + ", capabilities=" + caps.size());
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("status", created ? "REGISTERED" : "UPDATED");
        out.put("applicationId", app.id());
        out.put("environmentId", env.id());
        return out;
    }

    private String json(Object o) {
        if (o == null) return null;
        try {
            String s = mapper.writeValueAsString(o);
            return s.length() > 100_000 ? null : s;
        } catch (JsonProcessingException e) {
            return null;
        }
    }

    private static String truncate(String s, int max) {
        return s == null ? null : s.length() <= max ? s : s.substring(0, max);
    }
}
