package com.securetest.controlplane.web;

import com.securetest.controlplane.security.ApiException;
import com.securetest.controlplane.security.MachineAuthentication;
import com.securetest.controlplane.service.JobService;
import com.securetest.controlplane.service.JobService.Completion;
import com.securetest.controlplane.service.JobService.WorkerRegistration;
import com.securetest.controlplane.service.RegistrationService;
import com.securetest.controlplane.service.RegistrationService.AgentRegistration;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

/** Endpoints used by machines: embedded agents (enrollment token) and remote workers (fleet token). */
@RestController
@RequestMapping("/api/v1")
public class MachineApiController {

    private final RegistrationService registration;
    private final JobService jobs;

    public MachineApiController(RegistrationService registration, JobService jobs) {
        this.registration = registration;
        this.jobs = jobs;
    }

    /** Called by {@code PlatformServices.ControlPlaneClient} in the starter at start-up and on every heartbeat. */
    @PostMapping("/agents/register")
    public Map<String, Object> register(@RequestBody AgentRegistration body, Authentication auth, HttpServletRequest request) {
        MachineAuthentication agent = machine(auth, MachineAuthentication.Kind.AGENT);
        return registration.register(agent.tenantId(), body, request.getRemoteAddr());
    }

    // ------------------------------------------------------------------ workers

    public record ClaimRequest(String workerId, List<String> scanners) { }

    public record Heartbeat(String workerId, int progress, String message) { }

    @PostMapping("/worker/register")
    public Map<String, Object> registerWorker(@RequestBody WorkerRegistration body, Authentication auth) {
        machine(auth, MachineAuthentication.Kind.WORKER);
        jobs.registerWorker(body);
        return Map.of("status", "OK");
    }

    @PostMapping("/worker/jobs/claim")
    public ResponseEntity<Map<String, Object>> claim(@RequestBody ClaimRequest body, Authentication auth) {
        machine(auth, MachineAuthentication.Kind.WORKER);
        return jobs.claim(body.workerId(), body.scanners())
                .map(ResponseEntity::ok)
                .orElseGet(() -> ResponseEntity.noContent().build());
    }

    @PostMapping("/worker/jobs/{id}/heartbeat")
    public Map<String, Object> heartbeat(@PathVariable String id, @RequestBody Heartbeat body, Authentication auth) {
        machine(auth, MachineAuthentication.Kind.WORKER);
        return jobs.heartbeat(id, body.workerId(), body.progress(), body.message());
    }

    @PostMapping("/worker/jobs/{id}/complete")
    public Map<String, Object> complete(@PathVariable String id, @RequestBody Completion body, Authentication auth) {
        machine(auth, MachineAuthentication.Kind.WORKER);
        return jobs.complete(id, body);
    }

    private static MachineAuthentication machine(Authentication auth, MachineAuthentication.Kind kind) {
        if (auth instanceof MachineAuthentication m && m.kind() == kind) return m;
        throw ApiException.forbidden("Not a " + kind.name().toLowerCase() + " credential");
    }
}
