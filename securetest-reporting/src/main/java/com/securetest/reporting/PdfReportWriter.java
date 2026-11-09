package com.securetest.reporting;

import com.securetest.core.model.Finding;
import com.securetest.core.model.Severity;
import com.securetest.core.util.Redactor;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.zip.Deflater;

/**
 * Minimal, dependency-free PDF 1.4 writer: title page, scope, executive summary,
 * severity chart, detailed findings, recommendations, limitations, tool versions,
 * classification watermark and page numbers (SRS 8.2).
 */
public class PdfReportWriter {

    private static final float W = 595f;
    private static final float H = 842f;
    private static final float MARGIN = 50f;
    private static final DateTimeFormatter TS = DateTimeFormatter.ofPattern("dd MMM yyyy HH:mm z", Locale.ENGLISH);

    private final List<StringBuilder> pages = new ArrayList<>();
    private StringBuilder page;
    private float y;
    private ReportDocument doc;

    public byte[] write(ReportDocument d) {
        this.doc = d;
        pages.clear();
        titlePage();
        newPage();
        heading("1. Scope");
        paragraph(nz(d.scope, "Application " + nz(d.applicationName, "-") + ", environment " + nz(d.environment, "-") + "."), 10, false);
        keyValues();
        heading("2. Executive summary");
        paragraph(nz(d.executiveSummary, "No summary."), 10, false);
        severityChart();
        heading("3. Detailed findings");
        if (d.findings.isEmpty()) paragraph("No findings match the report filters.", 10, false);
        int n = 1;
        for (Finding f : d.findings) {
            findingBlock(n++, f);
        }
        int section = 4;
        for (ReportDocument.Table t : d.tables) {
            heading(section++ + ". " + t.title());
            table(t);
        }
        heading(section++ + ". Recommendations");
        if (d.recommendations.isEmpty()) paragraph("No additional recommendations.", 10, false);
        for (String r : d.recommendations) bullet(r);
        heading(section + ". Limitations");
        for (String l : d.limitations) bullet(l);
        bullet("Automated findings are advisory and may contain false positives or false negatives; human review is required.");
        bullet("Compliance mappings are technical evidence support, not legal certification.");
        return assemble();
    }

    // ------------------------------------------------------------------ layout

    private void titlePage() {
        newPage();
        rect(0, H - 260, W, 260, "0.09 0.16 0.33");
        text(MARGIN, H - 110, "F2", 28, doc.organization == null ? "SecureTest AI" : doc.organization, "1 1 1");
        text(MARGIN, H - 150, "F2", 20, nz(doc.title, "Report"), "1 1 1");
        text(MARGIN, H - 180, "F1", 12, nz(doc.applicationName, "") + "  |  " + nz(doc.environment, ""), "0.85 0.9 1");
        y = H - 320;
        String[][] rows = {
                {"Report ID", doc.reportId},
                {"Report type", doc.type},
                {"Generated", TS.format(doc.generatedAt.atZone(doc.zone))},
                {"Owner", doc.owner},
                {"Source revision", doc.revision},
                {"Data snapshot", doc.snapshotVersion},
                {"Classification", doc.classification},
        };
        for (String[] r : rows) {
            text(MARGIN, y, "F2", 11, r[0], "0.3 0.3 0.3");
            text(MARGIN + 140, y, "F1", 11, nz(r[1], "-"), "0 0 0");
            y -= 22;
        }
    }

    private void keyValues() {
        if (doc.metadata.isEmpty()) return;
        y -= 4;
        for (var e : doc.metadata.entrySet()) {
            ensure(16);
            text(MARGIN, y, "F2", 9, e.getKey(), "0.3 0.3 0.3");
            List<String> lines = wrap(nz(e.getValue(), "-"), 9, W - 2 * MARGIN - 170);
            for (String l : lines) {
                ensure(13);
                text(MARGIN + 170, y, "F1", 9, l, "0 0 0");
                y -= 12;
            }
        }
        y -= 6;
    }

    private void severityChart() {
        ensure(150);
        y -= 6;
        int max = 1;
        for (Severity s : Severity.values()) max = Math.max(max, doc.severityCounts.getOrDefault(s, 0));
        float barMax = W - 2 * MARGIN - 160;
        for (Severity s : Severity.values()) {
            int c = doc.severityCounts.getOrDefault(s, 0);
            text(MARGIN, y - 10, "F1", 10, s.label(), "0 0 0");
            float w = Math.max(c == 0 ? 0 : 3, barMax * c / max);
            rect(MARGIN + 110, y - 14, w, 14, color(s));
            text(MARGIN + 116 + w, y - 10, "F2", 10, String.valueOf(c), "0 0 0");
            y -= 22;
        }
        y -= 8;
    }

    private void findingBlock(int n, Finding f) {
        ensure(90);
        Severity p = f.priority != null ? f.priority : f.sourceSeverity;
        rect(MARGIN, y - 16, 4, 16, color(p));
        List<String> titleLines = wrap(n + ". " + nz(f.title, "Untitled"), 11, W - 2 * MARGIN - 12);
        for (String l : titleLines) {
            text(MARGIN + 10, y - 12, "F2", 11, l, "0 0 0");
            y -= 15;
        }
        y -= 2;
        String meta = "Priority " + (f.priority == null ? "-" : f.priority.label()) + "  |  Source severity " + f.sourceSeverity.label()
                + "  |  Confidence " + f.confidence + "  |  Status " + f.status + "  |  " + nz(f.source, "") + " / " + nz(f.ruleId, "");
        paragraph(meta, 8, false);
        if (f.filePath != null) paragraph("Location: " + f.filePath + (f.lineStart != null ? ":" + f.lineStart : ""), 9, false);
        if (f.asset != null) paragraph("Asset: " + f.asset, 9, false);
        if (f.dependency != null) {
            paragraph("Package: " + nz(f.dependency.packageName, "") + " " + nz(f.dependency.installedVersion, "")
                    + (f.dependency.fixedVersion != null ? "  ->  fixed in " + f.dependency.fixedVersion : "")
                    + (f.dependency.aliases.isEmpty() ? "" : "  |  " + String.join(", ", f.dependency.aliases))
                    + (f.dependency.cvssScore != null ? "  |  CVSS " + f.dependency.cvssScore : ""), 9, false);
        }
        if (f.description != null) paragraph(Redactor.redact(f.description), 9, false);
        if (f.remediation != null) paragraph("Recommended fix: " + Redactor.redact(f.remediation), 9, true);
        y -= 8;
    }

    private void table(ReportDocument.Table t) {
        int cols = t.headers().size();
        if (cols == 0) return;
        float colW = (W - 2 * MARGIN) / cols;
        ensure(40);
        rect(MARGIN, y - 15, W - 2 * MARGIN, 16, "0.9 0.92 0.96");
        for (int c = 0; c < cols; c++) text(MARGIN + 3 + c * colW, y - 11, "F2", 8, clip(t.headers().get(c), 8, colW - 6), "0 0 0");
        y -= 18;
        for (List<String> row : t.rows()) {
            ensure(14);
            for (int c = 0; c < cols && c < row.size(); c++) {
                text(MARGIN + 3 + c * colW, y - 9, "F1", 8, clip(Redactor.redact(nz(row.get(c), "")), 8, colW - 6), "0 0 0");
            }
            y -= 13;
        }
        y -= 8;
    }

    private void heading(String s) {
        ensure(50);
        y -= 10;
        text(MARGIN, y - 14, "F2", 14, s, "0.09 0.16 0.33");
        y -= 22;
        line(MARGIN, y + 2, W - MARGIN, y + 2);
        y -= 8;
    }

    private void bullet(String s) {
        List<String> lines = wrap(s, 10, W - 2 * MARGIN - 14);
        for (int i = 0; i < lines.size(); i++) {
            ensure(14);
            if (i == 0) text(MARGIN + 2, y - 10, "F1", 10, "•", "0 0 0");
            text(MARGIN + 14, y - 10, "F1", 10, lines.get(i), "0 0 0");
            y -= 13;
        }
        y -= 2;
    }

    private void paragraph(String s, float size, boolean bold) {
        for (String para : s.split("\n")) {
            for (String l : wrap(para, size, W - 2 * MARGIN - 10)) {
                ensure(size + 4);
                text(MARGIN + 10, y - size, bold ? "F2" : "F1", size, l, "0.1 0.1 0.1");
                y -= size + 3;
            }
        }
        y -= 3;
    }

    private void ensure(float needed) {
        if (y - needed < MARGIN + 20) newPage();
    }

    private void newPage() {
        page = new StringBuilder();
        pages.add(page);
        y = H - MARGIN;
    }

    // ------------------------------------------------------------------ primitives

    private void text(float x, float yy, String font, float size, String s, String rgb) {
        page.append(rgb).append(" rg BT /").append(font).append(' ').append(fmt(size)).append(" Tf ")
            .append(fmt(x)).append(' ').append(fmt(yy)).append(" Td (").append(escape(s)).append(") Tj ET\n");
    }

    private void rect(float x, float yy, float w, float h, String rgb) {
        page.append(rgb).append(" rg ").append(fmt(x)).append(' ').append(fmt(yy)).append(' ')
            .append(fmt(w)).append(' ').append(fmt(h)).append(" re f\n");
    }

    private void line(float x1, float y1, float x2, float y2) {
        page.append("0.75 0.78 0.85 RG 0.6 w ").append(fmt(x1)).append(' ').append(fmt(y1)).append(" m ")
            .append(fmt(x2)).append(' ').append(fmt(y2)).append(" l S\n");
    }

    private static String color(Severity s) {
        return switch (s) {
            case CRITICAL -> "0.6 0.05 0.1";
            case HIGH -> "0.85 0.25 0.15";
            case MEDIUM -> "0.95 0.6 0.1";
            case LOW -> "0.2 0.5 0.85";
            case INFO -> "0.55 0.58 0.62";
        };
    }

    // Helvetica average glyph width ~0.5em; good enough for wrapping.
    private static float width(String s, float size) {
        float w = 0;
        for (char c : s.toCharArray()) {
            w += (Character.isUpperCase(c) || c == 'm' || c == 'w') ? 0.68f : (c == ' ' || c == 'i' || c == 'l' || c == '.' || c == ',') ? 0.28f : 0.52f;
        }
        return w * size;
    }

    private static List<String> wrap(String s, float size, float maxWidth) {
        List<String> out = new ArrayList<>();
        StringBuilder cur = new StringBuilder();
        for (String word : s.replace('\t', ' ').split(" ")) {
            String candidate = cur.length() == 0 ? word : cur + " " + word;
            if (width(candidate, size) <= maxWidth) {
                cur.setLength(0);
                cur.append(candidate);
            } else {
                if (cur.length() > 0) out.add(cur.toString());
                String w = word;
                while (width(w, size) > maxWidth && w.length() > 1) {
                    int cut = Math.max(1, (int) (w.length() * maxWidth / width(w, size)) - 1);
                    out.add(w.substring(0, cut));
                    w = w.substring(cut);
                }
                cur.setLength(0);
                cur.append(w);
            }
        }
        if (cur.length() > 0 || out.isEmpty()) out.add(cur.toString());
        return out;
    }

    private static String clip(String s, float size, float maxWidth) {
        if (width(s, size) <= maxWidth) return s;
        String t = s;
        while (t.length() > 1 && width(t + "...", size) > maxWidth) t = t.substring(0, t.length() - 1);
        return t + "...";
    }

    private static String escape(String s) {
        StringBuilder sb = new StringBuilder();
        for (char c : s.toCharArray()) {
            switch (c) {
                case '\\', '(', ')' -> sb.append('\\').append(c);
                case '•' -> sb.append("\\225");
                case '→' -> sb.append("->");
                case '—', '–' -> sb.append('-');
                case '‘', '’' -> sb.append('\'');
                case '“', '”' -> sb.append('"');
                case '…' -> sb.append("...");
                default -> {
                    if (c < 32) sb.append(' ');
                    else if (c < 127) sb.append(c);
                    else if (c <= 255) sb.append(String.format("\\%03o", (int) c));
                    else sb.append('?');
                }
            }
        }
        return sb.toString();
    }

    private static String fmt(float f) {
        return String.format(Locale.ROOT, "%.2f", f);
    }

    private static String nz(String s, String def) { return s == null || s.isBlank() ? def : s; }

    // ------------------------------------------------------------------ file assembly

    private byte[] assemble() {
        int pageCount = pages.size();
        // decorate every page with footer + watermark
        for (int i = 0; i < pageCount; i++) {
            page = pages.get(i);
            String footer = nz(doc.classification, "") + "  |  " + nz(doc.reportId, "") + "  |  Page " + (i + 1) + " of " + pageCount;
            text(MARGIN, 25, "F1", 8, footer, "0.45 0.45 0.45");
            if (doc.classification != null && !doc.classification.isBlank()) {
                page.append("q 0.93 0.93 0.93 rg BT /F2 60 Tf 0.707 0.707 -0.707 0.707 150 250 Tm (")
                    .append(escape(doc.classification)).append(") Tj ET Q\n");
            }
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        List<Integer> offsets = new ArrayList<>();
        write(out, "%PDF-1.4\n%âãÏÓ\n");
        // object numbering: 1 catalog, 2 pages, 3 font F1, 4 font F2, 5 info, then per page: page obj + content obj
        int firstPage = 6;
        offsets.add(out.size());
        write(out, "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");
        offsets.add(out.size());
        StringBuilder kids = new StringBuilder();
        for (int i = 0; i < pageCount; i++) kids.append(firstPage + i * 2).append(" 0 R ");
        write(out, "2 0 obj\n<< /Type /Pages /Kids [" + kids + "] /Count " + pageCount + " >>\nendobj\n");
        offsets.add(out.size());
        write(out, "3 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>\nendobj\n");
        offsets.add(out.size());
        write(out, "4 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>\nendobj\n");
        offsets.add(out.size());
        write(out, "5 0 obj\n<< /Title (" + escape(nz(doc.title, "Report")) + ") /Producer (SecureTest AI) /Subject ("
                + escape(nz(doc.reportId, "")) + ") >>\nendobj\n");
        for (int i = 0; i < pageCount; i++) {
            int pageObj = firstPage + i * 2;
            offsets.add(out.size());
            write(out, pageObj + " 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> /Contents "
                    + (pageObj + 1) + " 0 R >>\nendobj\n");
            byte[] content = deflate(pages.get(i).toString().getBytes(StandardCharsets.ISO_8859_1));
            offsets.add(out.size());
            write(out, (pageObj + 1) + " 0 obj\n<< /Length " + content.length + " /Filter /FlateDecode >>\nstream\n");
            out.writeBytes(content);
            write(out, "\nendstream\nendobj\n");
        }
        int xref = out.size();
        int total = offsets.size() + 1;
        StringBuilder sb = new StringBuilder("xref\n0 " + total + "\n0000000000 65535 f \n");
        for (int off : offsets) sb.append(String.format("%010d 00000 n \n", off));
        sb.append("trailer\n<< /Size ").append(total).append(" /Root 1 0 R /Info 5 0 R >>\nstartxref\n").append(xref).append("\n%%EOF\n");
        write(out, sb.toString());
        return out.toByteArray();
    }

    private static void write(ByteArrayOutputStream out, String s) {
        out.writeBytes(s.getBytes(StandardCharsets.ISO_8859_1));
    }

    private static byte[] deflate(byte[] data) {
        Deflater d = new Deflater(Deflater.BEST_COMPRESSION);
        d.setInput(data);
        d.finish();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        while (!d.finished()) {
            int n = d.deflate(buf);
            out.write(buf, 0, n);
        }
        d.end();
        return out.toByteArray();
    }
}
