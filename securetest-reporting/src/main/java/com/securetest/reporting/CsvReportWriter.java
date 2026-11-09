package com.securetest.reporting;

import com.securetest.core.model.Finding;
import com.securetest.core.util.Redactor;

import java.nio.charset.StandardCharsets;
import java.util.List;

/** CSV export of findings with spreadsheet formula-injection protection. */
public class CsvReportWriter {

    public byte[] write(ReportDocument d) {
        StringBuilder sb = new StringBuilder("﻿");
        row(sb, List.of("id", "title", "priority", "source_severity", "confidence", "status", "module", "source", "rule",
                "file", "line", "asset", "package", "installed_version", "fixed_version", "advisory", "owner", "remediation"));
        for (Finding f : d.findings) {
            row(sb, List.of(nz(f.id), nz(f.title), f.priority == null ? "" : f.priority.name(), f.sourceSeverity.name(),
                    String.valueOf(f.confidence), String.valueOf(f.status), nz(f.moduleId), nz(f.source), nz(f.ruleId),
                    nz(f.filePath), f.lineStart == null ? "" : f.lineStart.toString(), nz(f.asset),
                    f.dependency == null ? "" : nz(f.dependency.packageName),
                    f.dependency == null ? "" : nz(f.dependency.installedVersion),
                    f.dependency == null ? "" : nz(f.dependency.fixedVersion),
                    f.dependency == null ? "" : String.join(" ", f.dependency.aliases),
                    nz(f.owner), Redactor.redact(nz(f.remediation))));
        }
        return sb.toString().getBytes(StandardCharsets.UTF_8);
    }

    private static void row(StringBuilder sb, List<String> cells) {
        for (int i = 0; i < cells.size(); i++) {
            if (i > 0) sb.append(',');
            sb.append(cell(cells.get(i)));
        }
        sb.append("\r\n");
    }

    static String cell(String v) {
        String s = v == null ? "" : v;
        if (!s.isEmpty() && "=+-@\t\r".indexOf(s.charAt(0)) >= 0) s = "'" + s; // CSV/formula injection guard
        if (s.contains(",") || s.contains("\"") || s.contains("\n") || s.contains("\r")) {
            s = "\"" + s.replace("\"", "\"\"") + "\"";
        }
        return s;
    }

    private static String nz(String s) { return s == null ? "" : s; }
}
