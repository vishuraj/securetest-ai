package com.securetest.controlplane.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.securetest.controlplane.security.ApiException;
import com.securetest.controlplane.service.TenantAccess.Scope;
import com.securetest.controlplane.store.AuditStore;
import com.securetest.controlplane.store.FindingStore;
import com.securetest.controlplane.store.InventoryStore;
import com.securetest.controlplane.store.ReportStore;
import com.securetest.controlplane.store.Rows;
import com.securetest.core.model.Finding;
import com.securetest.core.model.Severity;
import com.securetest.core.util.Hashing;
import com.securetest.reporting.CsvReportWriter;
import com.securetest.reporting.PdfReportWriter;
import com.securetest.reporting.ReportDocument;
import com.securetest.reporting.XlsxReportWriter;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/** Tenant-wide or per-application findings reports, rendered with {@code securetest-reporting}. */
@Service
public class ReportService {

    private static final int MAX_FINDINGS = 5_000;

    private final FindingStore findings;
    private final InventoryStore inventory;
    private final ReportStore reports;
    private final AuditStore audit;
    private final ObjectMapper mapper;

    public ReportService(FindingStore findings, InventoryStore inventory, ReportStore reports, AuditStore audit, ObjectMapper mapper) {
        this.findings = findings;
        this.inventory = inventory;
        this.reports = reports;
        this.audit = audit;
        this.mapper = mapper;
    }

    public Map<String, Object> generate(Scope scope, String format, String applicationId) {
        String fmt = format == null ? "PDF" : format.toUpperCase(Locale.ROOT);
        if (!List.of("PDF", "CSV", "XLSX").contains(fmt)) throw ApiException.badRequest("format must be PDF, CSV or XLSX");
        String appName = "All applications";
        if (applicationId != null) {
            appName = inventory.findApplication(scope.tenantId(), applicationId)
                    .map(InventoryStore.Application::name).orElseThrow(() -> ApiException.notFound("Application"));
        }
        List<Finding> list = new ArrayList<>();
        for (String json : findings.openPayloads(scope.tenantId(), applicationId, MAX_FINDINGS)) {
            try {
                list.add(mapper.readValue(json, Finding.class));
            } catch (Exception e) {
                // skip unreadable legacy rows
            }
        }
        String id = Rows.newId();
        ReportDocument d = new ReportDocument();
        d.reportId = id;
        d.type = "findings";
        d.title = "Open findings - " + appName;
        d.organization = scope.tenantSlug();
        d.owner = scope.actor();
        d.applicationName = appName;
        d.scope = "Control plane aggregate for tenant '" + scope.tenantSlug() + "'";
        d.findings = list;
        for (Finding f : list) d.severityCounts.merge(f.priority == null ? Severity.INFO : f.priority, 1, Integer::sum);
        d.executiveSummary = list.size() + " open finding(s) across " + (applicationId == null ? "all registered applications" : appName) + ".";
        d.limitations.add("Automated findings are advisory and may contain false positives or negatives.");
        if (list.size() >= MAX_FINDINGS) d.limitations.add("Report limited to the " + MAX_FINDINGS + " most recent findings.");

        byte[] content = switch (fmt) {
            case "CSV" -> new CsvReportWriter().write(d);
            case "XLSX" -> new XlsxReportWriter().write(d);
            default -> new PdfReportWriter().write(d);
        };
        String sha = Hashing.sha256(content);
        reports.insert(id, scope.tenantId(), applicationId, fmt, d.title, list.size(), sha, content, scope.actor());
        audit.append(scope.tenantId(), scope.actor(), "REPORT_GENERATED", "report:" + id, fmt + ", " + list.size() + " findings, sha256 " + sha);
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("id", id);
        out.put("format", fmt);
        out.put("title", d.title);
        out.put("findingsCount", list.size());
        out.put("sha256", sha);
        return out;
    }
}
