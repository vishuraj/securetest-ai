package com.securetest.autoconfigure.fleet;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.client.ServiceInstance;
import org.springframework.cloud.client.discovery.DiscoveryClient;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Service discovery through Spring Cloud's {@link DiscoveryClient}: Eureka, Consul, Zookeeper, Nacos, Kubernetes, or the
 * simple (static) client. Only loaded when Spring Cloud Commons is on the application's classpath.
 */
public class SpringCloudFleetDiscovery implements FleetDiscovery {

    private static final Logger log = LoggerFactory.getLogger(SpringCloudFleetDiscovery.class);

    private final DiscoveryClient client;

    public SpringCloudFleetDiscovery(DiscoveryClient client) {
        this.client = client;
    }

    @Override
    public String description() {
        try {
            String d = client.description();
            return d == null || d.isBlank() ? "Spring Cloud service discovery" : d;
        } catch (RuntimeException e) {
            return "Spring Cloud service discovery";
        }
    }

    @Override
    public List<Instance> instances() {
        List<Instance> out = new ArrayList<>();
        try {
            for (String service : client.getServices()) {
                for (ServiceInstance si : client.getInstances(service)) {
                    if (si.getUri() == null) continue;
                    String id = si.getInstanceId() != null ? si.getInstanceId() : si.getHost() + ":" + si.getPort();
                    Map<String, String> meta = si.getMetadata() == null ? Map.of() : si.getMetadata();
                    out.add(new Instance(service, id, si.getUri(), meta));
                }
            }
        } catch (RuntimeException e) {
            log.debug("SecureTest: service discovery lookup failed", e);
        }
        return out;
    }
}
