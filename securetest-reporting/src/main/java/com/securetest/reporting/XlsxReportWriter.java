package com.securetest.reporting;

import com.securetest.core.model.Finding;
import com.securetest.core.model.Severity;
import com.securetest.core.util.Redactor;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/**
 * Dependency-free Office Open XML (.xlsx) writer. Produces separate sheets for
 * Executive Summary, Findings, and every additional report table (SRS 8.2).
 */
public class XlsxReportWriter {

    private static final DateTimeFormatter TS = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss z");

    private record Sheet(String name, List<List<Object>> rows, int[] widths) { }

    public byte[] write(ReportDocument d) {
        List<Sheet> sheets = new ArrayList<>();
        sheets.add(summary(d));
        sheets.add(findings(d));
        for (ReportDocument.Table t : d.tables) {
            List<List<Object>> rows = new ArrayList<>();
            rows.add(new ArrayList<>(t.headers()));
            for (List<String> r : t.rows()) {
                List<Object> row = new ArrayList<>();
                for (String c : r) row.add(Redactor.redact(c));
                rows.add(row);
            }
            int[] widths = new int[t.headers().size()];
            java.util.Arrays.fill(widths, 24);
            sheets.add(new Sheet(t.title(), rows, widths));
        }
        return zip(uniqueNames(sheets));
    }

    private Sheet summary(ReportDocument d) {
        List<List<Object>> rows = new ArrayList<>();
        rows.add(List.of("Field", "Value"));
        rows.add(List.of("Report", nz(d.title)));
        rows.add(List.of("Report ID", nz(d.reportId)));
        rows.add(List.of("Type", nz(d.type)));
        rows.add(List.of("Application", nz(d.applicationName)));
        rows.add(List.of("Environment", nz(d.environment)));
        rows.add(List.of("Generated", TS.format(d.generatedAt.atZone(d.zone))));
        rows.add(List.of("Owner", nz(d.owner)));
        rows.add(List.of("Source revision", nz(d.revision)));
        rows.add(List.of("Data snapshot", nz(d.snapshotVersion)));
        rows.add(List.of("Classification", nz(d.classification)));
        rows.add(List.of("Scope", nz(d.scope)));
        rows.add(List.of("Summary", nz(d.executiveSummary)));
        for (Severity s : Severity.values()) rows.add(List.of("Findings - " + s.label(), d.severityCounts.getOrDefault(s, 0)));
        d.metadata.forEach((k, v) -> rows.add(List.of(k, nz(v))));
        for (String r : d.recommendations) rows.add(List.of("Recommendation", r));
        for (String l : d.limitations) rows.add(List.of("Limitation", l));
        return new Sheet("Executive Summary", rows, new int[] {28, 110});
    }

    private Sheet findings(ReportDocument d) {
        List<List<Object>> rows = new ArrayList<>();
        rows.add(List.of("ID", "Title", "Priority", "Source severity", "Confidence", "Status", "Module", "Source", "Rule",
                "File", "Line", "Asset", "Package", "Installed", "Fixed", "Advisory", "CVSS", "Owner", "First detected",
                "Last detected", "Description", "Remediation"));
        for (Finding f : d.findings) {
            List<Object> r = new ArrayList<>();
            r.add(nz(f.id));
            r.add(nz(f.title));
            r.add(f.priority == null ? "" : f.priority.label());
            r.add(f.sourceSeverity.label());
            r.add(String.valueOf(f.confidence));
            r.add(String.valueOf(f.status));
            r.add(nz(f.moduleId));
            r.add(nz(f.source));
            r.add(nz(f.ruleId));
            r.add(nz(f.filePath));
            r.add(f.lineStart == null ? "" : f.lineStart);
            r.add(nz(f.asset));
            r.add(f.dependency == null ? "" : nz(f.dependency.packageName));
            r.add(f.dependency == null ? "" : nz(f.dependency.installedVersion));
            r.add(f.dependency == null ? "" : nz(f.dependency.fixedVersion));
            r.add(f.dependency == null ? "" : String.join(", ", f.dependency.aliases.isEmpty() && f.dependency.advisoryId != null
                    ? List.of(f.dependency.advisoryId) : f.dependency.aliases));
            r.add(f.dependency == null || f.dependency.cvssScore == null ? "" : f.dependency.cvssScore);
            r.add(nz(f.owner));
            r.add(f.firstDetected == null ? "" : TS.format(f.firstDetected.atZone(d.zone)));
            r.add(f.lastDetected == null ? "" : TS.format(f.lastDetected.atZone(d.zone)));
            r.add(Redactor.redact(nz(f.description)));
            r.add(Redactor.redact(nz(f.remediation)));
            rows.add(r);
        }
        return new Sheet("Findings", rows, new int[] {14, 50, 12, 14, 11, 12, 15, 18, 22, 40, 7, 25, 32, 12, 12, 22, 7, 14, 20, 20, 60, 60});
    }

    private static List<Sheet> uniqueNames(List<Sheet> sheets) {
        Set<String> used = new LinkedHashSet<>();
        List<Sheet> out = new ArrayList<>();
        for (Sheet s : sheets) {
            String base = s.name().replaceAll("[\\[\\]:*?/\\\\]", " ");
            if (base.length() > 31) base = base.substring(0, 31);
            String name = base;
            int i = 2;
            while (!used.add(name.toLowerCase())) name = base.substring(0, Math.min(base.length(), 28)) + " " + i++;
            out.add(new Sheet(name, s.rows(), s.widths()));
        }
        return out;
    }

    // ------------------------------------------------------------------ OOXML package

    private byte[] zip(List<Sheet> sheets) {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try (ZipOutputStream z = new ZipOutputStream(bos)) {
            StringBuilder ct = new StringBuilder("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>"
                    + "<Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\">"
                    + "<Default Extension=\"rels\" ContentType=\"application/vnd.openxmlformats-package.relationships+xml\"/>"
                    + "<Default Extension=\"xml\" ContentType=\"application/xml\"/>"
                    + "<Override PartName=\"/xl/workbook.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml\"/>"
                    + "<Override PartName=\"/xl/styles.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml\"/>"
                    + "<Override PartName=\"/docProps/core.xml\" ContentType=\"application/vnd.openxmlformats-package.core-properties+xml\"/>");
            for (int i = 1; i <= sheets.size(); i++) {
                ct.append("<Override PartName=\"/xl/worksheets/sheet").append(i)
                  .append(".xml\" ContentType=\"application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml\"/>");
            }
            ct.append("</Types>");
            put(z, "[Content_Types].xml", ct.toString());
            put(z, "_rels/.rels", "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>"
                    + "<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">"
                    + "<Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument\" Target=\"xl/workbook.xml\"/>"
                    + "<Relationship Id=\"rId2\" Type=\"http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties\" Target=\"docProps/core.xml\"/>"
                    + "</Relationships>");
            put(z, "docProps/core.xml", "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>"
                    + "<cp:coreProperties xmlns:cp=\"http://schemas.openxmlformats.org/package/2006/metadata/core-properties\" "
                    + "xmlns:dc=\"http://purl.org/dc/elements/1.1/\"><dc:creator>SecureTest AI</dc:creator><dc:title>SecureTest report</dc:title></cp:coreProperties>");
            StringBuilder wb = new StringBuilder("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>"
                    + "<workbook xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\" "
                    + "xmlns:r=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships\"><sheets>");
            StringBuilder rels = new StringBuilder("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>"
                    + "<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">");
            for (int i = 1; i <= sheets.size(); i++) {
                wb.append("<sheet name=\"").append(xml(sheets.get(i - 1).name())).append("\" sheetId=\"").append(i)
                  .append("\" r:id=\"rId").append(i).append("\"/>");
                rels.append("<Relationship Id=\"rId").append(i)
                    .append("\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet\" Target=\"worksheets/sheet")
                    .append(i).append(".xml\"/>");
            }
            wb.append("</sheets></workbook>");
            rels.append("<Relationship Id=\"rId").append(sheets.size() + 1)
                .append("\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles\" Target=\"styles.xml\"/>")
                .append("</Relationships>");
            put(z, "xl/workbook.xml", wb.toString());
            put(z, "xl/_rels/workbook.xml.rels", rels.toString());
            put(z, "xl/styles.xml", STYLES);
            for (int i = 1; i <= sheets.size(); i++) put(z, "xl/worksheets/sheet" + i + ".xml", sheetXml(sheets.get(i - 1)));
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        return bos.toByteArray();
    }

    private static final String STYLES = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>"
            + "<styleSheet xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\">"
            + "<fonts count=\"2\"><font><sz val=\"10\"/><name val=\"Calibri\"/></font>"
            + "<font><b/><sz val=\"10\"/><color rgb=\"FFFFFFFF\"/><name val=\"Calibri\"/></font></fonts>"
            + "<fills count=\"3\"><fill><patternFill patternType=\"none\"/></fill><fill><patternFill patternType=\"gray125\"/></fill>"
            + "<fill><patternFill patternType=\"solid\"><fgColor rgb=\"FF1F2A55\"/><bgColor indexed=\"64\"/></patternFill></fill></fills>"
            + "<borders count=\"1\"><border><left/><right/><top/><bottom/><diagonal/></border></borders>"
            + "<cellStyleXfs count=\"1\"><xf numFmtId=\"0\" fontId=\"0\" fillId=\"0\" borderId=\"0\"/></cellStyleXfs>"
            + "<cellXfs count=\"3\"><xf numFmtId=\"0\" fontId=\"0\" fillId=\"0\" borderId=\"0\" xfId=\"0\"/>"
            + "<xf numFmtId=\"0\" fontId=\"1\" fillId=\"2\" borderId=\"0\" xfId=\"0\" applyFont=\"1\" applyFill=\"1\"/>"
            + "<xf numFmtId=\"0\" fontId=\"0\" fillId=\"0\" borderId=\"0\" xfId=\"0\" applyAlignment=\"1\"><alignment vertical=\"top\" wrapText=\"1\"/></xf>"
            + "</cellXfs><cellStyles count=\"1\"><cellStyle name=\"Normal\" xfId=\"0\" builtinId=\"0\"/></cellStyles></styleSheet>";

    private static String sheetXml(Sheet s) {
        StringBuilder sb = new StringBuilder("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>"
                + "<worksheet xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\">"
                + "<sheetViews><sheetView workbookViewId=\"0\"><pane ySplit=\"1\" topLeftCell=\"A2\" activePane=\"bottomLeft\" state=\"frozen\"/></sheetView></sheetViews>"
                + "<cols>");
        for (int c = 0; c < s.widths().length; c++) {
            sb.append("<col min=\"").append(c + 1).append("\" max=\"").append(c + 1).append("\" width=\"").append(s.widths()[c]).append("\" customWidth=\"1\"/>");
        }
        sb.append("</cols><sheetData>");
        int maxCols = 1;
        for (int r = 0; r < s.rows().size(); r++) {
            List<Object> row = s.rows().get(r);
            maxCols = Math.max(maxCols, row.size());
            sb.append("<row r=\"").append(r + 1).append("\">");
            for (int c = 0; c < row.size(); c++) {
                String ref = col(c) + (r + 1);
                Object v = row.get(c);
                int style = r == 0 ? 1 : 2;
                if (v instanceof Number n) {
                    sb.append("<c r=\"").append(ref).append("\" s=\"").append(style).append("\"><v>").append(n).append("</v></c>");
                } else {
                    String text = v == null ? "" : v.toString();
                    if (text.length() > 32000) text = text.substring(0, 32000);
                    sb.append("<c r=\"").append(ref).append("\" s=\"").append(style).append("\" t=\"inlineStr\"><is><t xml:space=\"preserve\">")
                      .append(xml(text)).append("</t></is></c>");
                }
            }
            sb.append("</row>");
        }
        sb.append("</sheetData>");
        if (s.rows().size() > 1) sb.append("<autoFilter ref=\"A1:").append(col(maxCols - 1)).append(s.rows().size()).append("\"/>");
        sb.append("</worksheet>");
        return sb.toString();
    }

    private static String col(int idx) {
        StringBuilder sb = new StringBuilder();
        int n = idx + 1;
        while (n > 0) {
            int rem = (n - 1) % 26;
            sb.insert(0, (char) ('A' + rem));
            n = (n - 1) / 26;
        }
        return sb.toString();
    }

    private static String xml(String s) {
        StringBuilder sb = new StringBuilder(s.length());
        for (char c : s.toCharArray()) {
            switch (c) {
                case '<' -> sb.append("&lt;");
                case '>' -> sb.append("&gt;");
                case '&' -> sb.append("&amp;");
                case '"' -> sb.append("&quot;");
                default -> {
                    if (c == '\t' || c == '\n' || c == '\r' || c >= 0x20) sb.append(c);
                }
            }
        }
        return sb.toString();
    }

    private static void put(ZipOutputStream z, String name, String content) throws IOException {
        z.putNextEntry(new ZipEntry(name));
        z.write(content.getBytes(StandardCharsets.UTF_8));
        z.closeEntry();
    }

    private static String nz(String s) { return s == null ? "" : s; }
}
