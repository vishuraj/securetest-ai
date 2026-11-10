package com.securetest.autoconfigure.fleet;

import java.net.URI;
import java.util.List;
import java.util.Map;

/** Finds the other running services of a microservice system (Spring Cloud service discovery, Kubernetes, ...). */
public interface FleetDiscovery {

    /** One running instance: its service name, instance id, base URI and registry metadata. */
    record Instance(String service, String instanceId, URI baseUri, Map<String, String> metadata) { }

    /** Human-readable source, e.g. "Eureka" or "Kubernetes". */
    String description();

    List<Instance> instances();
}
