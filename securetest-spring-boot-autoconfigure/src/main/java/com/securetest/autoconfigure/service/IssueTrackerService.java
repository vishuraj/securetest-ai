package com.securetest.autoconfigure.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.securetest.autoconfigure.SecureTestProperties;
import com.securetest.autoconfigure.security.ApiException;
import com.securetest.autoconfigure.support.AppContext;
import com.securetest.autoconfigure.support.SecretResolver;
import com.securetest.core.model.Finding;
import com.securetest.core.util.Redactor;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Creates and refreshes Jira / GitHub issues for findings. Calls are made only when a user asks (no polling), only to the
 * configured tracker, and issue text never contains raw evidence: secrets are redacted and evidence is not copied.
 */
public class IssueTrackerService {

    private final SecureTestProperties props;
    private final SecretResolver secrets;
    private final AppContext app;
    private final ObjectMapper json = new ObjectMapper();
    private volatile HttpClient http;

    public IssueTrackerService(SecureTestProperties props, SecretResolver secrets, AppContext app) {
        this.props = props;
        this.secrets = secrets;
        this.app = app;
    }

    private HttpClient http() {
        HttpClient h = http;
        if (h == null) {
            synchronized (this) {
                if (http == null) http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).followRedirects(HttpClient.Redirect.NEVER).build();
                h = http;
            }
        }
        return h;
    }

    /** Configured trackers, for the dashboard's "Create issue" buttons. */
    public List<Map<String, Object>> trackers() {
        List<Map<String, Object>> out = new ArrayList<>();
        var jira = props.getIntegrations().getJira();
        if (jira.configured()) out.add(Map.of("id", "jira", "name", "Jira", "target", jira.getProjectKey() + " @ " + host(jira.getUrl())));
        var gh = props.getIntegrations().getGithub();
        if (gh.configured()) out.add(Map.of("id", "github", "name", "GitHub Issues", "target", gh.getRepository()));
        return out;
    }

    public Finding.IssueLink create(String tracker, Finding f) {
        return switch (tracker) {
            case "jira" -> createJira(f);
            case "github" -> createGitHub(f);
            default -> throw ApiException.badRequest("Unknown tracker " + tracker + " (jira or github)");
        };
    }

    /** Reads the issue's current state (open / closed / Jira status) on request. */
    public Finding.IssueLink refresh(Finding.IssueLink link) {
        try {
            if ("jira".equals(link.tracker)) {
                var jira = props.getIntegrations().getJira();
                JsonNode r = send(jiraRequest(jira, "/issue/" + link.key + "?fields=status").GET(), 200);
                link.state = r.path("fields").path("status").path("name").asText(link.state);
            } else if ("github".equals(link.tracker)) {
                var gh = props.getIntegrations().getGithub();
                JsonNode r = send(gitHubRequest(gh, "/issues/" + link.key).GET(), 200);
                link.state = r.path("state").asText(link.state);
            }
            link.checkedAt = Instant.now();
            return link;
        } catch (IOException e) {
            throw new ApiException(502, "bad_gateway", "Cannot reach " + link.tracker + ": " + e.getMessage());
        }
    }

    // ------------------------------------------------------------------ Jira

    private Finding.IssueLink createJira(Finding f) {
        var jira = props.getIntegrations().getJira();
        if (!jira.configured()) throw ApiException.conflict("Jira is not configured (securetest.integrations.jira.url and project-key)");
        ObjectNode fields = json.createObjectNode();
        fields.putObject("project").put("key", jira.getProjectKey());
        fields.put("summary", summary(f));
        fields.putObject("issuetype").put("name", jira.getIssueType());
        ArrayNode labels = fields.putArray("labels");
        jira.getLabels().forEach(labels::add);
        String text = body(f);
        if (jira.getApiVersion() >= 3) fields.set("description", adf(text)); else fields.put("description", text);
        ObjectNode bodyNode = json.createObjectNode();
        bodyNode.set("fields", fields);
        try {
            JsonNode r = send(jiraRequest(jira, "/issue").POST(HttpRequest.BodyPublishers.ofString(bodyNode.toString())), 201);
            Finding.IssueLink link = new Finding.IssueLink();
            link.tracker = "jira";
            link.key = r.path("key").asText();
            link.url = stripSlash(jira.getUrl()) + "/browse/" + link.key;
            link.state = "Open";
            link.createdAt = Instant.now();
            return link;
        } catch (IOException e) {
            throw new ApiException(502, "bad_gateway", "Cannot reach Jira: " + e.getMessage());
        }
    }

    private HttpRequest.Builder jiraRequest(SecureTestProperties.Jira jira, String path) {
        String token = token(jira.getTokenRef(), "Jira");
        String auth = jira.getEmail() == null || jira.getEmail().isBlank() ? "Bearer " + token
                : "Basic " + Base64.getEncoder().encodeToString((jira.getEmail() + ":" + token).getBytes(StandardCharsets.UTF_8));
        return HttpRequest.newBuilder(URI.create(stripSlash(jira.getUrl()) + "/rest/api/" + jira.getApiVersion() + path))
                .timeout(Duration.ofSeconds(20)).header("Authorization", auth)
                .header("Accept", "application/json").header("Content-Type", "application/json");
    }

    /** Minimal Atlassian Document Format: one paragraph per line. */
    private ObjectNode adf(String text) {
        ObjectNode doc = json.createObjectNode();
        doc.put("type", "doc");
        doc.put("version", 1);
        ArrayNode content = doc.putArray("content");
        for (String line : text.split("\n")) {
            ObjectNode p = content.addObject();
            p.put("type", "paragraph");
            if (!line.isBlank()) p.putArray("content").addObject().put("type", "text").put("text", line);
        }
        return doc;
    }

    // ------------------------------------------------------------------ GitHub

    private Finding.IssueLink createGitHub(Finding f) {
        var gh = props.getIntegrations().getGithub();
        if (!gh.configured()) throw ApiException.conflict("GitHub is not configured (securetest.integrations.github.repository: owner/name)");
        ObjectNode bodyNode = json.createObjectNode();
        bodyNode.put("title", summary(f));
        bodyNode.put("body", body(f));
        ArrayNode labels = bodyNode.putArray("labels");
        gh.getLabels().forEach(labels::add);
        try {
            JsonNode r = send(gitHubRequest(gh, "/issues").POST(HttpRequest.BodyPublishers.ofString(bodyNode.toString())), 201);
            Finding.IssueLink link = new Finding.IssueLink();
            link.tracker = "github";
            link.key = r.path("number").asText();
            link.url = r.path("html_url").asText();
            link.state = r.path("state").asText("open");
            link.createdAt = Instant.now();
            return link;
        } catch (IOException e) {
            throw new ApiException(502, "bad_gateway", "Cannot reach GitHub: " + e.getMessage());
        }
    }

    private HttpRequest.Builder gitHubRequest(SecureTestProperties.GitHub gh, String path) {
        return HttpRequest.newBuilder(URI.create(stripSlash(gh.getApiUrl()) + "/repos/" + gh.getRepository() + path))
                .timeout(Duration.ofSeconds(20)).header("Authorization", "Bearer " + token(gh.getTokenRef(), "GitHub"))
                .header("Accept", "application/vnd.github+json").header("X-GitHub-Api-Version", "2022-11-28")
                .header("Content-Type", "application/json");
    }

    // ------------------------------------------------------------------ shared

    private JsonNode send(HttpRequest.Builder b, int expected) throws IOException {
        try {
            HttpResponse<String> r = http().send(b.build(), HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            if (r.statusCode() != expected && r.statusCode() != 200) {
                String msg = r.body() == null ? "" : r.body();
                throw new ApiException(502, "bad_gateway", "Tracker answered HTTP " + r.statusCode() + ": " + Redactor.redact(msg.length() > 300 ? msg.substring(0, 300) : msg));
            }
            return r.body() == null || r.body().isBlank() ? json.createObjectNode() : json.readTree(r.body());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("interrupted", e);
        }
    }

    private String token(String ref, String tracker) {
        String t = secrets.resolve(ref);
        if (t == null || t.isBlank()) throw ApiException.conflict(tracker + " token is not set (" + ref + ")");
        return t.trim();
    }

    private static String summary(Finding f) {
        String sev = f.priority == null ? f.sourceSeverity.name() : f.priority.name();
        String s = "[" + sev + "] " + f.title + " (" + f.id + ")";
        return s.length() > 250 ? s.substring(0, 250) : s;
    }

    /** Issue text: what, where, why and how to fix. Evidence is deliberately not copied out of SecureTest. */
    private String body(Finding f) {
        Map<String, String> rows = new LinkedHashMap<>();
        rows.put("Finding", f.id + " (" + f.moduleId + ", " + f.source + (f.ruleId == null ? "" : " / " + f.ruleId) + ")");
        rows.put("Priority", f.priority == null ? f.sourceSeverity.name() : f.priority.name());
        rows.put("Application", app.name() + " (" + app.environmentName() + ")");
        if (f.asset != null) rows.put("Asset", f.asset);
        if (f.filePath != null) rows.put("Location", f.filePath + (f.lineStart == null ? "" : ":" + f.lineStart));
        if (f.dependency != null) rows.put("Dependency", f.dependency.packageName + " " + f.dependency.installedVersion
                + (f.dependency.fixedVersion == null ? "" : " (fixed in " + f.dependency.fixedVersion + ")"));
        StringBuilder sb = new StringBuilder();
        rows.forEach((k, v) -> sb.append(k).append(": ").append(v).append('\n'));
        if (f.description != null) sb.append('\n').append(f.description).append('\n');
        if (f.stepsToReproduce != null) sb.append("\nSteps to reproduce:\n").append(f.stepsToReproduce).append('\n');
        if (f.impact != null) sb.append("\nImpact:\n").append(f.impact).append('\n');
        if (f.remediation != null) sb.append("\nHow to fix:\n").append(f.remediation).append('\n');
        if (!f.references.isEmpty()) sb.append("\nReferences:\n").append(String.join("\n", f.references)).append('\n');
        sb.append("\nOpen in SecureTest: ").append(app.selfBaseUrl()).append(props.normalizedPath()).append("/#/finding/").append(f.id).append('\n');
        String text = Redactor.redact(sb.toString());
        return text.length() > 30_000 ? text.substring(0, 30_000) : text;
    }

    private static String stripSlash(String s) {
        String t = s.trim();
        while (t.endsWith("/")) t = t.substring(0, t.length() - 1);
        return t;
    }

    private static String host(String url) {
        try {
            return URI.create(url).getHost();
        } catch (RuntimeException e) {
            return url;
        }
    }
}
