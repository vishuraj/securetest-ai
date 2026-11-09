package com.securetest.core.util;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Simplified Maven version ordering (numeric segments, then qualifiers
 * alpha &lt; beta &lt; milestone &lt; rc &lt; snapshot &lt; release &lt; sp).
 */
public final class MavenVersion implements Comparable<MavenVersion> {

    private final String raw;
    private final List<Object> items = new ArrayList<>();

    public MavenVersion(String raw) {
        this.raw = raw == null ? "" : raw.trim();
        for (String part : this.raw.toLowerCase(Locale.ROOT).split("[.\\-_+]")) {
            if (part.isEmpty()) continue;
            // split digit/letter transitions: "1rc2" -> 1, rc, 2
            StringBuilder cur = new StringBuilder();
            Boolean digit = null;
            for (char c : part.toCharArray()) {
                boolean d = Character.isDigit(c);
                if (digit != null && d != digit) { add(cur.toString(), digit); cur.setLength(0); }
                cur.append(c);
                digit = d;
            }
            if (cur.length() > 0) add(cur.toString(), digit);
        }
        // strip trailing zeros / release markers so 1.0 == 1.0.0 == 1.0.0.RELEASE
        while (!items.isEmpty()) {
            Object last = items.get(items.size() - 1);
            if ((last instanceof Long l && l == 0) || (last instanceof String s && qualifierRank(s) == 5)) {
                items.remove(items.size() - 1);
            } else break;
        }
    }

    private void add(String token, boolean digit) {
        if (digit) {
            try { items.add(Long.parseLong(token)); } catch (NumberFormatException e) { items.add(Long.MAX_VALUE); }
        } else items.add(token);
    }

    private static int qualifierRank(String q) {
        return switch (q) {
            case "alpha", "a" -> 0;
            case "beta", "b" -> 1;
            case "milestone", "m" -> 2;
            case "rc", "cr" -> 3;
            case "snapshot" -> 4;
            case "", "ga", "final", "release" -> 5;
            case "sp" -> 6;
            default -> 7; // unknown qualifiers sort after release, lexically among themselves
        };
    }

    @Override
    public int compareTo(MavenVersion o) {
        int n = Math.max(items.size(), o.items.size());
        for (int i = 0; i < n; i++) {
            Object a = i < items.size() ? items.get(i) : null;
            Object b = i < o.items.size() ? o.items.get(i) : null;
            int c = compareItem(a, b);
            if (c != 0) return c;
        }
        return 0;
    }

    private static int compareItem(Object a, Object b) {
        if (a == null && b == null) return 0;
        // a missing item equals 0 against a number, or the "release" qualifier against a qualifier
        if (a == null) a = b instanceof Long ? (Object) 0L : "";
        if (b == null) b = a instanceof Long ? (Object) 0L : "";
        if (a instanceof Long x && b instanceof Long y) return Long.compare(x, y);
        if (a instanceof Long) return 1;   // 1.0.1 > 1.0-rc
        if (b instanceof Long) return -1;
        String s = (String) a;
        String t = (String) b;
        int c = Integer.compare(qualifierRank(s), qualifierRank(t));
        return c != 0 ? c : s.compareTo(t);
    }

    public static int compare(String a, String b) {
        return new MavenVersion(a).compareTo(new MavenVersion(b));
    }

    public static boolean isLower(String a, String b) { return compare(a, b) < 0; }

    /** Major version number, or -1. */
    public static int major(String v) {
        MavenVersion mv = new MavenVersion(v);
        return !mv.items.isEmpty() && mv.items.get(0) instanceof Long l ? l.intValue() : -1;
    }

    public static int minor(String v) {
        MavenVersion mv = new MavenVersion(v);
        return mv.items.size() > 1 && mv.items.get(1) instanceof Long l ? l.intValue() : 0;
    }

    @Override public String toString() { return raw; }
}
