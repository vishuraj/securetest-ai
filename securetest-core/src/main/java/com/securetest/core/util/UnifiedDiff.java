package com.securetest.core.util;

import java.util.ArrayList;
import java.util.List;

/**
 * Line-based unified diff (git-apply compatible) using an LCS table. Large inputs fall back
 * to a positional comparison to bound memory.
 */
public final class UnifiedDiff {

    public enum Op { EQUAL, DELETE, INSERT }

    public record Line(Op op, String text, int oldLine, int newLine) { }

    private static final long MAX_CELLS = 4_000_000L;

    private UnifiedDiff() { }

    public static List<String> lines(String s) {
        if (s == null || s.isEmpty()) return new ArrayList<>();
        String[] parts = s.split("\r?\n", -1);
        List<String> out = new ArrayList<>(List.of(parts));
        if (s.endsWith("\n")) out.remove(out.size() - 1);
        return out;
    }

    public static List<Line> compute(String before, String after) {
        List<String> a = lines(before);
        List<String> b = lines(after);
        // trim common prefix / suffix first
        int pre = 0;
        while (pre < a.size() && pre < b.size() && a.get(pre).equals(b.get(pre))) pre++;
        int suf = 0;
        while (suf < a.size() - pre && suf < b.size() - pre
                && a.get(a.size() - 1 - suf).equals(b.get(b.size() - 1 - suf))) suf++;
        List<String> am = a.subList(pre, a.size() - suf);
        List<String> bm = b.subList(pre, b.size() - suf);

        List<Line> out = new ArrayList<>();
        for (int i = 0; i < pre; i++) out.add(new Line(Op.EQUAL, a.get(i), i + 1, i + 1));
        int oldNo = pre + 1;
        int newNo = pre + 1;
        if ((long) am.size() * bm.size() <= MAX_CELLS) {
            int n = am.size();
            int m = bm.size();
            int[][] lcs = new int[n + 1][m + 1];
            for (int i = n - 1; i >= 0; i--) {
                for (int j = m - 1; j >= 0; j--) {
                    lcs[i][j] = am.get(i).equals(bm.get(j)) ? lcs[i + 1][j + 1] + 1 : Math.max(lcs[i + 1][j], lcs[i][j + 1]);
                }
            }
            int i = 0;
            int j = 0;
            while (i < n || j < m) {
                if (i < n && j < m && am.get(i).equals(bm.get(j))) {
                    out.add(new Line(Op.EQUAL, am.get(i), oldNo++, newNo++)); i++; j++;
                } else if (i < n && (j == m || lcs[i + 1][j] >= lcs[i][j + 1])) {
                    out.add(new Line(Op.DELETE, am.get(i), oldNo++, -1)); i++; // conventional order: '-' before '+'
                } else {
                    out.add(new Line(Op.INSERT, bm.get(j), -1, newNo++)); j++;
                }
            }
        } else {
            int max = Math.max(am.size(), bm.size());
            for (int k = 0; k < max; k++) {
                String x = k < am.size() ? am.get(k) : null;
                String y = k < bm.size() ? bm.get(k) : null;
                if (x != null && x.equals(y)) {
                    out.add(new Line(Op.EQUAL, x, oldNo++, newNo++));
                } else {
                    if (x != null) out.add(new Line(Op.DELETE, x, oldNo++, -1));
                    if (y != null) out.add(new Line(Op.INSERT, y, -1, newNo++));
                }
            }
        }
        for (int k = 0; k < suf; k++) {
            out.add(new Line(Op.EQUAL, a.get(a.size() - suf + k), oldNo++, newNo++));
        }
        return out;
    }

    /** Produces a unified diff text for one file ({@code git apply} compatible). */
    public static String unified(String path, String before, String after, int context) {
        List<Line> diff = compute(before, after);
        StringBuilder sb = new StringBuilder();
        sb.append("diff --git a/").append(path).append(" b/").append(path).append('\n');
        sb.append("--- a/").append(path).append('\n');
        sb.append("+++ b/").append(path).append('\n');
        int idx = 0;
        while (idx < diff.size()) {
            // find next change
            int change = idx;
            while (change < diff.size() && diff.get(change).op() == Op.EQUAL) change++;
            if (change >= diff.size()) break;
            int start = Math.max(idx, change - context);
            // extend hunk while changes are within 2*context
            int end = change;
            int lastChange = change;
            while (end < diff.size()) {
                if (diff.get(end).op() != Op.EQUAL) lastChange = end;
                else if (end - lastChange > 2 * context) break;
                end++;
            }
            end = Math.min(diff.size(), lastChange + context + 1);
            int oldStart = -1;
            int newStart = -1;
            int oldCount = 0;
            int newCount = 0;
            StringBuilder body = new StringBuilder();
            for (int k = start; k < end; k++) {
                Line l = diff.get(k);
                switch (l.op()) {
                    case EQUAL -> {
                        if (oldStart < 0) oldStart = l.oldLine();
                        if (newStart < 0) newStart = l.newLine();
                        oldCount++; newCount++;
                        body.append(' ').append(l.text()).append('\n');
                    }
                    case DELETE -> {
                        if (oldStart < 0) oldStart = l.oldLine();
                        oldCount++;
                        body.append('-').append(l.text()).append('\n');
                    }
                    case INSERT -> {
                        if (newStart < 0) newStart = l.newLine();
                        newCount++;
                        body.append('+').append(l.text()).append('\n');
                    }
                }
            }
            if (oldStart < 0) oldStart = newStart > 0 ? newStart - 1 : 0;
            if (newStart < 0) newStart = oldStart > 0 ? oldStart - 1 : 0;
            if (oldCount == 0) oldStart = Math.max(0, oldStart);
            sb.append("@@ -").append(oldStart).append(',').append(oldCount)
              .append(" +").append(newStart).append(',').append(newCount).append(" @@\n");
            sb.append(body);
            idx = end;
        }
        return sb.toString();
    }

    public static int[] stats(String before, String after) {
        int add = 0;
        int del = 0;
        for (Line l : compute(before, after)) {
            if (l.op() == Op.INSERT) add++;
            if (l.op() == Op.DELETE) del++;
        }
        return new int[] {add, del};
    }
}
