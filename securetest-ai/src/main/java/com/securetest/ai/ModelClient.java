package com.securetest.ai;

/** Seam between the remediation logic and the model API (replaced by a fake in tests). */
public interface ModelClient {

    /**
     * @param status OK, REFUSED (safety decline), TRUNCATED (hit max_tokens) or ERROR
     */
    record Reply(String status, AiFixResponse fix, String requestId, String model, long inputTokens, long outputTokens, String detail) { }

    Reply complete(String system, String user);

    String provider();

    String model();
}
