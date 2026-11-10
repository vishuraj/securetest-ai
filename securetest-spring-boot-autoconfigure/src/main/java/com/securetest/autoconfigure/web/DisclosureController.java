package com.securetest.autoconfigure.web;

import com.securetest.autoconfigure.disclosure.DisclosureService;
import com.securetest.autoconfigure.security.ApiException;
import com.securetest.autoconfigure.security.Authz;
import com.securetest.autoconfigure.security.Rbac.Permission;
import com.securetest.autoconfigure.security.RequestInfo;
import com.securetest.autoconfigure.security.SecureTestPrincipal;
import com.securetest.autoconfigure.service.AuditService;
import com.securetest.core.model.Severity;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

/**
 * Vulnerability disclosure: the public report form (no sign-in, no JavaScript) and the team's triage API.
 * The form exists only when securetest.disclosure.enabled=true.
 */
@RestController
@RequestMapping("${securetest.dashboard.path:/securetest}")
public class DisclosureController {

    private final DisclosureService disclosures;
    private final AuditService audit;

    public DisclosureController(DisclosureService disclosures, AuditService audit) {
        this.disclosures = disclosures;
        this.audit = audit;
    }

    // ------------------------------------------------------------------ public form

    @GetMapping(value = "/disclose", produces = MediaType.TEXT_HTML_VALUE)
    public ResponseEntity<String> form() {
        if (!disclosures.enabled()) return ResponseEntity.notFound().build();
        return ResponseEntity.ok().contentType(MediaType.TEXT_HTML).body(page("Report a security vulnerability", """
                <p>Thank you for helping keep this service safe. Please describe the issue so we can reproduce it. Only test
                accounts and data you own; do not access other people's data, degrade the service or use social engineering.</p>
                <form method="post">
                  <label>Title *<input name="title" required maxlength="200"></label>
                  <label>Affected URL or component<input name="asset" maxlength="500"></label>
                  <label>Description *<textarea name="description" required rows="5" maxlength="20000"></textarea></label>
                  <label>Steps to reproduce<textarea name="stepsToReproduce" rows="5" maxlength="20000"></textarea></label>
                  <label>Impact<textarea name="impact" rows="3" maxlength="5000"></textarea></label>
                  <label>Your name (optional)<input name="reporterName" maxlength="120"></label>
                  <label>Your e-mail, so we can follow up (optional)<input name="reporterEmail" type="email" maxlength="320"></label>
                  <label class="check"><input type="checkbox" name="publicCredit" value="true"> You may credit me by name</label>
                  <div class="hp" aria-hidden="true"><label>Website<input name="website" tabindex="-1" autocomplete="off"></label></div>
                  <button type="submit">Send report</button>
                </form>
                """));
    }

    @PostMapping(value = "/disclose", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE, produces = MediaType.TEXT_HTML_VALUE)
    public ResponseEntity<String> submit(@RequestBody MultiValueMap<String, String> form, RequestInfo info) {
        if (!disclosures.enabled()) return ResponseEntity.notFound().build();
        if (form.getFirst("website") != null && !form.getFirst("website").isBlank()) { // honeypot: bots fill every field
            return ResponseEntity.ok().contentType(MediaType.TEXT_HTML).body(page("Thank you", "<p>Your report was received.</p>"));
        }
        try {
            DisclosureService.Report r = disclosures.submit(new DisclosureService.Submission(form.getFirst("title"), form.getFirst("asset"),
                    form.getFirst("description"), form.getFirst("stepsToReproduce"), form.getFirst("impact"), form.getFirst("reporterName"),
                    form.getFirst("reporterEmail"), "true".equals(form.getFirst("publicCredit"))), info == null ? null : info.remoteAddress());
            audit.record("researcher", null, "disclosure.received", r.id, "OK", Map.of());
            return ResponseEntity.ok().contentType(MediaType.TEXT_HTML).body(page("Thank you",
                    "<p>Your report was received. Reference: <b>" + r.id + "</b>.</p><p>We review every report and will contact you if you left an e-mail address.</p>"));
        } catch (ApiException e) {
            return ResponseEntity.status(e.status()).contentType(MediaType.TEXT_HTML).body(page("Report not sent", "<p>" + esc(e.getMessage()) + "</p><p><a href=\"disclose\">Back</a></p>"));
        }
    }

    private static String page(String title, String body) {
        return "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
                + "<meta name=\"robots\" content=\"noindex\"><title>" + esc(title) + "</title><style>"
                + "body{font:15px/1.5 system-ui,sans-serif;max-width:640px;margin:40px auto;padding:0 16px;color:#1b1f24;background:#fff}"
                + "label{display:block;margin:12px 0;font-weight:600}input,textarea{display:block;width:100%;box-sizing:border-box;margin-top:4px;padding:8px;font:inherit;font-weight:400;border:1px solid #c5ccd6;border-radius:6px}"
                + ".check{font-weight:400}.check input{display:inline;width:auto;margin-right:6px}.hp{position:absolute;left:-10000px}"
                + "button{padding:10px 18px;font:inherit;font-weight:600;border:0;border-radius:6px;background:#2251cc;color:#fff;cursor:pointer}"
                + "@media(prefers-color-scheme:dark){body{background:#111418;color:#e7ebf0}input,textarea{background:#1a1f26;color:inherit;border-color:#3a4350}}"
                + "</style></head><body><h1>" + esc(title) + "</h1>" + body + "</body></html>";
    }

    private static String esc(String s) {
        return s == null ? "" : s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;");
    }

    // ------------------------------------------------------------------ triage (signed-in team)

    @GetMapping("/api/v1/disclosures")
    public Map<String, Object> list(SecureTestPrincipal principal) {
        Authz.require(principal, Permission.VIEW);
        return Map.of("enabled", disclosures.enabled(), "reports", disclosures.list());
    }

    @GetMapping("/api/v1/disclosures/{id}")
    public DisclosureService.Report get(@PathVariable String id, SecureTestPrincipal principal) {
        Authz.require(principal, Permission.VIEW);
        return disclosures.get(id);
    }

    public record Triage(String decision, String note, Severity severity, String moduleId) { }

    @PostMapping("/api/v1/disclosures/{id}/triage")
    public DisclosureService.Report triage(@PathVariable String id, @RequestBody Triage body, SecureTestPrincipal principal) {
        SecureTestPrincipal p = Authz.require(principal, Permission.REMEDIATE);
        DisclosureService.Report r = disclosures.triage(id, body.decision(), body.note(), body.severity(), body.moduleId(), p.name());
        audit.record(p, "disclosure.triaged", id, "OK", Map.of("decision", r.status, "finding", String.valueOf(r.findingId)));
        return r;
    }

    public static List<String> decisions() {
        return List.copyOf(DisclosureService.DECISIONS);
    }
}
