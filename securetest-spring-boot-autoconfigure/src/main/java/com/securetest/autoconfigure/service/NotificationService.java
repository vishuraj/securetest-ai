package com.securetest.autoconfigure.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.securetest.autoconfigure.SecureTestProperties;
import com.securetest.autoconfigure.support.SecretResolver;
import com.securetest.core.util.Redactor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/** Event-driven notifications to Slack/Teams-compatible or generic webhooks (SRS 10). Best effort, never blocking. */
public class NotificationService {

    private static final Logger log = LoggerFactory.getLogger(NotificationService.class);

    public record Notice(Instant at, String event, String message, Map<String, String> data) { }

    private final SecureTestProperties props;
    private final SecretResolver secrets;
    private final ObjectMapper mapper;
    // created on first webhook: building a JDK HttpClient starts a selector thread
    private volatile HttpClient http;

    private HttpClient http() {
        HttpClient h = http;
        if (h == null) {
            synchronized (this) {
                if (http == null) http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();
                h = http;
            }
        }
        return h;
    }
    private final ExecutorService sender = Executors.newSingleThreadExecutor(r -> {
        Thread t = new Thread(r, "securetest-notify");
        t.setDaemon(true);
        return t;
    });
    private final Deque<Notice> recent = new ArrayDeque<>();
    private final com.securetest.autoconfigure.support.Extensions.MailBridge mail;

    public NotificationService(SecureTestProperties props, SecretResolver secrets, ObjectMapper mapper) {
        this(props, secrets, mapper, null);
    }

    public NotificationService(SecureTestProperties props, SecretResolver secrets, ObjectMapper mapper,
                               com.securetest.autoconfigure.support.Extensions.MailBridge mail) {
        this.props = props;
        this.secrets = secrets;
        this.mapper = mapper;
        this.mail = mail;
    }

    public boolean emailAvailable() { return mail != null; }

    public void publish(String event, String message, Map<String, String> data) {
        String safe = Redactor.redact(message);
        synchronized (recent) {
            recent.addFirst(new Notice(Instant.now(), event, safe, data));
            while (recent.size() > 100) recent.removeLast();
        }
        SecureTestProperties.Email email = props.getNotifications().getEmail();
        if (email.isEnabled() && mail != null && !email.getTo().isEmpty() && email.getEvents().contains(event)) {
            sender.submit(() -> {
                try {
                    mail.send(email.getFrom(), email.getTo(), "[SecureTest] " + event + " - " + (safe.length() > 80 ? safe.substring(0, 80) + "…" : safe),
                            safe + "\n\nEvent: " + event + "\nDetails: " + data + "\nTime: " + Instant.now()
                                    + "\n\nThis message was sent by the SecureTest dashboard. Do not reply.");
                } catch (RuntimeException e) {
                    log.warn("SecureTest e-mail notification failed: {}", e.getMessage());
                }
            });
        }
        for (SecureTestProperties.Webhook w : props.getNotifications().getWebhooks()) {
            if (w.getUrl() == null || !w.getEvents().contains(event)) continue;
            sender.submit(() -> send(w, event, safe, data));
        }
    }

    private void send(SecureTestProperties.Webhook w, String event, String message, Map<String, String> data) {
        try {
            String url = Redactor.isReference(w.getUrl()) ? secrets.resolve(w.getUrl()) : w.getUrl();
            if (url == null) return;
            Map<String, Object> body = new LinkedHashMap<>();
            String text = "[SecureTest] " + event + ": " + message;
            switch (w.getFormat()) {
                case "teams" -> { body.put("@type", "MessageCard"); body.put("summary", event); body.put("text", text); }
                case "generic" -> { body.put("event", event); body.put("message", message); body.put("data", data); body.put("timestamp", Instant.now().toString()); }
                default -> body.put("text", text);
            }
            HttpResponse<Void> r = http().send(HttpRequest.newBuilder(URI.create(url)).timeout(Duration.ofSeconds(10))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(mapper.writeValueAsString(body))).build(), HttpResponse.BodyHandlers.discarding());
            if (r.statusCode() >= 300) log.warn("SecureTest webhook '{}' returned HTTP {}", w.getName(), r.statusCode());
        } catch (Exception e) {
            log.warn("SecureTest webhook '{}' failed: {}", w.getName(), e.getMessage());
        }
    }

    public List<Notice> recent() {
        synchronized (recent) {
            return new ArrayList<>(recent);
        }
    }

    public void shutdown() { sender.shutdownNow(); }
}
