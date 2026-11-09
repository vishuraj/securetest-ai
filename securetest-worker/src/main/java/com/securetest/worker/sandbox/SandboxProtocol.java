package com.securetest.worker.sandbox;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.securetest.core.model.Finding;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * File-based contract between the worker and its sandbox: the worker writes {@code request.json} into an
 * otherwise empty job directory, the sandbox writes {@code result.json} (and a {@code progress} file while running).
 * Nothing else crosses the boundary: no worker token, no control-plane URL, no environment variables.
 */
public final class SandboxProtocol {
    private SandboxProtocol() { }

    public static final String REQUEST = "request.json";
    public static final String RESULT = "result.json";
    public static final String PROGRESS = "progress";

    public record App(String serviceId, String name, String environment) { }

    public record Request(String jobId, String scannerId, String scannerClass, String targetUrl, Map<String, String> options,
                          List<String> allowedTargets, List<String> allowedCommands, int maxRequestsPerSecond, App application) { }

    public static class Result {
        public String status = "FAILED";
        public String error;
        public List<Finding> findings = new ArrayList<>();
        public Map<String, Object> results = new LinkedHashMap<>();
        public List<String> log = new ArrayList<>();
        public long durationMs;

        public static Result failed(String error) {
            Result r = new Result();
            r.error = error;
            return r;
        }
    }

    public static ObjectMapper mapper() {
        return new ObjectMapper()
                .registerModule(new JavaTimeModule())
                .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS)
                .disable(SerializationFeature.FAIL_ON_EMPTY_BEANS)
                .disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
                .setSerializationInclusion(JsonInclude.Include.NON_NULL);
    }
}
