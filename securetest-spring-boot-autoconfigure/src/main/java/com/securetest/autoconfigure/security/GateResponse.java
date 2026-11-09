package com.securetest.autoconfigure.security;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Buffered response produced by the gate. Headers always apply; when {@link #isComplete()} the gate answered the
 * request itself (deny, redirect, sign-in page) and the web stack must not continue to the controllers.
 */
public class GateResponse {

    private int status = 200;
    private final Map<String, String> headers = new LinkedHashMap<>();
    private final List<String> cookies = new ArrayList<>();
    private String contentType;
    private String body;
    private boolean complete;

    public void header(String name, String value) { headers.put(name, value); }

    public void cookie(String name, String value, String path, long maxAgeSeconds, boolean secure) {
        cookies.add(name + "=" + value + "; Path=" + (path == null || path.isEmpty() ? "/" : path) + "; Max-Age=" + maxAgeSeconds
                + "; HttpOnly; SameSite=Lax" + (secure ? "; Secure" : ""));
    }

    public void redirect(String location) {
        status = 302;
        headers.put("Location", location);
        complete = true;
    }

    public void send(int status, String contentType, String body) {
        this.status = status;
        this.contentType = contentType;
        this.body = body;
        this.complete = true;
    }

    public void json(int status, String message) {
        send(status, "application/json;charset=UTF-8", "{\"status\":" + status + ",\"error\":\"" + message.replace("\\", "\\\\").replace("\"", "'") + "\"}");
    }

    public int status() { return status; }
    public Map<String, String> headers() { return headers; }
    public List<String> cookies() { return cookies; }
    public String contentType() { return contentType; }
    public String body() { return body; }
    public boolean isComplete() { return complete; }
}
