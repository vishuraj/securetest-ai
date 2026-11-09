package com.securetest.adapters.builtin;

import com.fasterxml.jackson.databind.JsonNode;
import com.securetest.adapters.support.ScanSupport;
import com.securetest.core.model.Enums.Confidence;
import com.securetest.core.model.Enums.FieldType;
import com.securetest.core.model.Finding;
import com.securetest.core.model.ModuleCatalog;
import com.securetest.core.model.Severity;
import com.securetest.core.spi.FieldSpec;
import com.securetest.core.spi.PreflightCheck;
import com.securetest.core.spi.ScanContext;
import com.securetest.core.spi.Scanner;
import com.securetest.core.spi.ScannerDescriptor;
import com.securetest.core.util.Redactor;

import java.io.BufferedReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Imports and correlates runtime security alerts from Falco, Wazuh or generic SIEM JSON exports (SRS 5.10).
 * Original source and timestamps are preserved; SecureTest does not claim to block attacks.
 */
public class RuntimeAlertScanner implements Scanner {

    public static final String ID = "runtime-alert-import";

    @Override
    public ScannerDescriptor descriptor() {
        return ScannerDescriptor.builder(ID, ModuleCatalog.ADVANCED_SECURITY, "Import runtime security alerts")
                .purpose("Imports alerts exported by Falco (JSON lines), Wazuh (alerts.json) or a generic SIEM export, maps them to this "
                        + "application and severity, and reports sensor health (when the last event was seen).")
                .access("Reads the alert file you specify. No connection to the sensors is made.")
                .field(FieldSpec.select("format", "Alert format", "falco", List.of("falco", "wazuh", "generic"), ""))
                .field(FieldSpec.required("file", "Alert file", FieldType.PATH, "", "JSON lines or a JSON array exported by the sensor."))
                .field(FieldSpec.optional("serviceFilter", "Correlate with service name", FieldType.TEXT, "",
                        "Only import alerts mentioning this container/pod/host/service (default: all)."))
                .field(FieldSpec.number("staleHours", "Sensor stale after (hours)", 24, 1, 720, ""))
                .field(FieldSpec.number("maxAlerts", "Maximum alerts to import", 2000, 1, 50000, ""))
                .build();
    }

    @Override
    public List<PreflightCheck> preflight(ScanContext ctx) {
        String f = ctx.option("file", "");
        return List.of(!f.isBlank() && Files.isRegularFile(Path.of(f)) ? PreflightCheck.ok("Alert file", f)
                : PreflightCheck.error("Alert file", "File not found: " + f));
    }

    @Override
    public void scan(ScanContext ctx) throws Exception {
        Path file = Path.of(ctx.option("file", ""));
        String format = ctx.option("format", "falco");
        String filter = ctx.option("serviceFilter", "").toLowerCase(Locale.ROOT);
        int max = ctx.intOption("maxAlerts", 2000, 1, 50000);
        List<JsonNode> events = new ArrayList<>();
        try (BufferedReader r = Files.newBufferedReader(file, StandardCharsets.UTF_8)) {
            String first = null;
            r.mark(1 << 20);
            int c;
            while ((c = r.read()) != -1) if (!Character.isWhitespace(c)) { first = String.valueOf((char) c); break; }
            r.reset();
            if ("[".equals(first)) {
                ScanSupport.JSON.readTree(r).forEach(events::add);
            } else {
                String line;
                while ((line = r.readLine()) != null && events.size() < max * 5) {
                    if (line.isBlank()) continue;
                    try { events.add(ScanSupport.JSON.readTree(line)); } catch (Exception ignored) { /* skip malformed */ }
                }
            }
        }
        Instant last = null;
        Map<String, Integer> byRule = new LinkedHashMap<>();
        int imported = 0;
        for (JsonNode e : events) {
            ctx.checkCancelled();
            if (imported >= max) break;
            if (!filter.isEmpty() && !e.toString().toLowerCase(Locale.ROOT).contains(filter)) continue;
            Finding f = switch (format) {
                case "wazuh" -> wazuh(e);
                case "generic" -> generic(e);
                default -> falco(e);
            };
            if (f == null) continue;
            byRule.merge(f.ruleId, 1, Integer::sum);
            String ts = f.attributes.get("sourceTimestamp");
            try {
                Instant t = Instant.parse(ts);
                if (last == null || t.isAfter(last)) last = t;
            } catch (Exception ignored) {
                // non ISO timestamp
            }
            f.attr("sourceFormat", format).attr("correlated", filter.isEmpty() ? "all" : filter);
            f.category = "Runtime alert";
            f.confidence = Confidence.MEDIUM;
            f.complianceTags.add("OWASP-A09");
            f.complianceTags.add("SOC2-CC7.2");
            f.complianceTags.add("ISO27001-A.8.16");
            f.complianceTags.add("PCI-10.4");
            ctx.report(f);
            imported++;
        }
        Map<String, Object> health = new LinkedHashMap<>();
        health.put("eventsRead", events.size());
        health.put("imported", imported);
        health.put("lastEvent", last == null ? null : last.toString());
        health.put("byRule", byRule);
        ctx.putResult("sensorHealth", health);
        int staleH = ctx.intOption("staleHours", 24, 1, 720);
        if (last == null || Duration.between(last, Instant.now()).toHours() > staleH) {
            ctx.report(Finding.of(ModuleCatalog.ADVANCED_SECURITY, ID, "SENSOR-STALE", "No recent runtime security events from " + format, Severity.LOW)
                    .description("The newest event is " + (last == null ? "unknown" : last) + ". A silent sensor may be misconfigured or down.")
                    .remediation("Verify the sensor is running, rules are loaded and events are forwarded.").asset(format)
                    .category("Detection health").confidence(Confidence.LOW).tags("SOC2-CC7.2", "ISO27001-A.8.16"));
        }
    }

    public static Finding falco(JsonNode e) {
        String rule = ScanSupport.text(e, "rule");
        if (rule == null) return null;
        String prio = ScanSupport.text(e, "priority");
        Severity s = Severity.parse(prio);
        JsonNode of = e.path("output_fields");
        String asset = firstNonNull(ScanSupport.text(of, "k8s.pod.name"), ScanSupport.text(of, "container.name"), ScanSupport.text(e, "hostname"), "host");
        return Finding.of(ModuleCatalog.ADVANCED_SECURITY, "falco", "FALCO-" + rule.replaceAll("\\W+", "-"), "Falco: " + rule, s)
                .rawSeverity(prio).asset(asset).description(Redactor.redact(ScanSupport.text(e, "output")))
                .evidence(Redactor.redact(ScanSupport.truncate(e.toPrettyString(), 3000)))
                .remediation("Investigate the process/container activity; tune the rule if this is expected behaviour.")
                .attr("sourceTimestamp", ScanSupport.text(e, "time"));
    }

    public static Finding wazuh(JsonNode e) {
        JsonNode rule = e.path("rule");
        if (rule.isMissingNode()) return null;
        int level = rule.path("level").asInt(0);
        Severity s = level >= 12 ? Severity.CRITICAL : level >= 8 ? Severity.HIGH : level >= 5 ? Severity.MEDIUM : level >= 3 ? Severity.LOW : Severity.INFO;
        Finding f = Finding.of(ModuleCatalog.ADVANCED_SECURITY, "wazuh", "WAZUH-" + rule.path("id").asText(), "Wazuh: " + rule.path("description").asText(), s)
                .rawSeverity("level " + level).asset(e.path("agent").path("name").asText("agent"))
                .description(Redactor.redact(ScanSupport.truncate(e.path("full_log").asText(""), 2000)))
                .evidence(Redactor.redact(ScanSupport.truncate(e.toPrettyString(), 3000)))
                .remediation("Follow the Wazuh rule guidance and MITRE technique references.")
                .attr("sourceTimestamp", ScanSupport.text(e, "timestamp"));
        rule.path("mitre").path("id").forEach(m -> f.references.add("https://attack.mitre.org/techniques/" + m.asText().replace('.', '/')));
        return f;
    }

    public static Finding generic(JsonNode e) {
        String title = firstNonNull(ScanSupport.text(e, "title"), ScanSupport.text(e, "name"), ScanSupport.text(e, "message"), null);
        if (title == null) return null;
        String sev = firstNonNull(ScanSupport.text(e, "severity"), ScanSupport.text(e, "level"), "medium", null);
        return Finding.of(ModuleCatalog.ADVANCED_SECURITY, firstNonNull(ScanSupport.text(e, "source"), "siem", null, null),
                        "SIEM-" + title.replaceAll("\\W+", "-").toUpperCase(Locale.ROOT), title, Severity.parse(sev))
                .rawSeverity(sev).asset(firstNonNull(ScanSupport.text(e, "asset"), ScanSupport.text(e, "host"), "unknown", null))
                .description(Redactor.redact(ScanSupport.text(e, "description")))
                .evidence(Redactor.redact(ScanSupport.truncate(e.toPrettyString(), 3000)))
                .attr("sourceTimestamp", firstNonNull(ScanSupport.text(e, "timestamp"), ScanSupport.text(e, "time"), null, null));
    }

    private static String firstNonNull(String a, String b, String c, String d) {
        return a != null ? a : b != null ? b : c != null ? c : d;
    }
}
