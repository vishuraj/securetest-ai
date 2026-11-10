package com.securetest.autoconfigure.web;

import com.securetest.autoconfigure.SecureTestProperties;
import com.securetest.autoconfigure.fleet.FleetService;
import com.securetest.autoconfigure.security.ApiException;
import com.securetest.autoconfigure.security.Authz;
import com.securetest.autoconfigure.security.Rbac.Permission;
import com.securetest.autoconfigure.security.RequestInfo;
import com.securetest.autoconfigure.security.SecureTestPrincipal;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.Map;

/** The "All services" view of a microservice system, and drill-down into each service's own dashboard. */
@RestController
@RequestMapping("${securetest.dashboard.path:/securetest}")
public class FleetApiController {

    private final FleetService fleet;
    private final SecureTestProperties props;

    public FleetApiController(FleetService fleet, SecureTestProperties props) {
        this.fleet = fleet;
        this.props = props;
    }

    /** Every service with its health, performance, release gate, findings and module status. */
    @GetMapping("/api/v1/fleet")
    public Map<String, Object> view(@RequestParam(defaultValue = "false") boolean refresh, SecureTestPrincipal principal) {
        Authz.require(principal, Permission.VIEW);
        if (!fleet.microservices()) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("architecture", fleet.architecture());
            m.put("services", java.util.List.of());
            return m;
        }
        return fleet.view(refresh);
    }

    /** This instance's compact status, read by the other services. */
    @GetMapping("/api/v1/fleet/summary")
    public Map<String, Object> summary(SecureTestPrincipal principal) {
        Authz.require(principal, Permission.VIEW);
        return fleet.localSummary();
    }

    @GetMapping("/fleet/{member}")
    public ResponseEntity<Void> slash(@PathVariable String member) {
        return ResponseEntity.status(302).header(HttpHeaders.LOCATION, member + "/").build();
    }

    /** Another service's dashboard (pages and API), fetched for the signed-in user. */
    @RequestMapping("/fleet/{member}/**")
    public ResponseEntity<byte[]> proxy(@PathVariable String member, HttpMethod method, @RequestHeader HttpHeaders headers,
                                        @RequestBody(required = false) byte[] body, RequestInfo info, SecureTestPrincipal principal) {
        SecureTestPrincipal p = Authz.require(principal, Permission.VIEW);
        String prefix = props.normalizedPath() + "/fleet/" + member;
        String path = info == null ? null : info.path();
        if (path == null || !path.startsWith(prefix)) throw ApiException.notFound("Service " + member);
        Map<String, String> h = new LinkedHashMap<>();
        headers.forEach((k, v) -> { if (!v.isEmpty()) h.put(k, v.get(0)); });
        FleetService.Forwarded r = fleet.forward(member, method.name(), path.substring(prefix.length()), info.query(), h, body, p);
        ResponseEntity.BodyBuilder b = ResponseEntity.status(r.status());
        r.headers().forEach(b::header);
        return b.body(r.body());
    }
}
