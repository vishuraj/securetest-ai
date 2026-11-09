package com.securetest.reporting;

import com.securetest.core.model.Finding;
import com.securetest.core.model.Severity;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import static org.assertj.core.api.Assertions.assertThat;

class ReportWritersTest {

    private static ReportDocument doc() {
        ReportDocument d = new ReportDocument();
        d.reportId = "R-TEST";
        d.title = "Security report";
        d.type = "security";
        d.applicationName = "demo";
        d.environment = "test";
        d.executiveSummary = "Two findings (one with password=secret123).";
        d.severityCounts.put(Severity.HIGH, 1);
        d.severityCounts.put(Severity.LOW, 1);
        for (int i = 0; i < 60; i++) {
            Finding f = Finding.of("vulnerability", "x", "R" + i, "Finding (" + i + ") with ünïcode & <xml>", i == 0 ? Severity.HIGH : Severity.LOW);
            f.id = "F-" + i;
            f.priority = f.sourceSeverity;
            f.description = "Long description ".repeat(20);
            f.remediation = "=cmd|' /C calc'!A0";
            d.findings.add(f);
        }
        d.addTable("Scan Metadata", List.of("Scan", "Status"), List.of(List.of("S-1", "COMPLETED")));
        d.limitations.add("Test");
        return d;
    }

    @Test
    void pdfIsWellFormed() {
        byte[] pdf = new PdfReportWriter().write(doc());
        String head = new String(pdf, 0, 8, StandardCharsets.ISO_8859_1);
        String tail = new String(pdf, pdf.length - 6, 6, StandardCharsets.ISO_8859_1);
        assertThat(head).startsWith("%PDF-1.4");
        assertThat(tail).contains("%%EOF");
        assertThat(new String(pdf, StandardCharsets.ISO_8859_1)).contains("/Type /Catalog").contains("startxref");
    }

    @Test
    void xlsxHasExpectedSheets() throws Exception {
        byte[] xlsx = new XlsxReportWriter().write(doc());
        List<String> entries = new ArrayList<>();
        String workbook = null;
        try (ZipInputStream z = new ZipInputStream(new ByteArrayInputStream(xlsx))) {
            ZipEntry e;
            while ((e = z.getNextEntry()) != null) {
                entries.add(e.getName());
                if (e.getName().equals("xl/workbook.xml")) workbook = new String(z.readAllBytes(), StandardCharsets.UTF_8);
            }
        }
        assertThat(entries).contains("[Content_Types].xml", "xl/workbook.xml", "xl/styles.xml", "xl/worksheets/sheet1.xml", "xl/worksheets/sheet3.xml");
        assertThat(workbook).contains("Executive Summary").contains("Findings").contains("Scan Metadata");
    }

    @Test
    void csvNeutralizesFormulas() {
        String csv = new String(new CsvReportWriter().write(doc()), StandardCharsets.UTF_8);
        assertThat(csv).contains("'=cmd");
        assertThat(CsvReportWriter.cell("a,b")).isEqualTo("\"a,b\"");
    }
}
