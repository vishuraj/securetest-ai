package com.securetest.autoconfigure.web;

import java.lang.reflect.Method;
import java.util.List;

/** Lists SecureTest's own endpoints for the OpenAPI document; implemented per web stack. */
public interface EndpointCatalog {

    record Endpoint(String path, String httpMethod, Method method, Class<?> beanType) { }

    List<Endpoint> endpoints();
}
