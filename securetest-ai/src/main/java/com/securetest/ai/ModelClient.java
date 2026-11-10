package com.securetest.ai;

import java.util.List;

/** Seam between the remediation logic and the model API (replaced by a fake in tests). */
public interface ModelClient {

    /**
     * @param status OK, REFUSED (safety decline), TRUNCATED (hit max_tokens) or ERROR
     */
    record Reply(String status, AiFixResponse fix, String requestId, String model, long inputTokens, long outputTokens, String detail) { }

    /** One message of a conversation: role is "user" or "assistant". */
    record Turn(String role, String text) { }

    /**
     * @param status OK, REFUSED, TRUNCATED or ERROR
     */
    record ChatReply(String status, String text, String requestId, String model, long inputTokens, long outputTokens, String detail) { }

    Reply complete(String system, String user);

    /** Free-text conversation (the security assistant). */
    default ChatReply chat(String system, List<Turn> turns) {
        return new ChatReply("ERROR", null, null, model(), 0, 0, "Chat is not supported by " + provider());
    }

    String provider();

    String model();
}
