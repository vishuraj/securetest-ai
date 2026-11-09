package com.securetest.core.util;

import java.util.HashMap;
import java.util.Map;

/** CVSS v3.x base score calculator (FIRST specification). */
public final class Cvss3 {
    private Cvss3() { }

    /** @return base score, or -1 when the vector cannot be parsed */
    public static double baseScore(String vector) {
        if (vector == null || !vector.startsWith("CVSS:3")) return -1;
        Map<String, String> m = new HashMap<>();
        for (String part : vector.split("/")) {
            String[] kv = part.split(":");
            if (kv.length == 2) m.put(kv[0], kv[1]);
        }
        try {
            double av = switch (m.get("AV")) { case "N" -> 0.85; case "A" -> 0.62; case "L" -> 0.55; case "P" -> 0.2; default -> throw new IllegalArgumentException(); };
            double ac = switch (m.get("AC")) { case "L" -> 0.77; case "H" -> 0.44; default -> throw new IllegalArgumentException(); };
            boolean changed = "C".equals(m.get("S"));
            double pr = switch (m.get("PR")) {
                case "N" -> 0.85;
                case "L" -> changed ? 0.68 : 0.62;
                case "H" -> changed ? 0.5 : 0.27;
                default -> throw new IllegalArgumentException();
            };
            double ui = switch (m.get("UI")) { case "N" -> 0.85; case "R" -> 0.62; default -> throw new IllegalArgumentException(); };
            double c = cia(m.get("C"));
            double i = cia(m.get("I"));
            double a = cia(m.get("A"));
            double iss = 1 - ((1 - c) * (1 - i) * (1 - a));
            double impact = changed ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15) : 6.42 * iss;
            double exploitability = 8.22 * av * ac * pr * ui;
            if (impact <= 0) return 0;
            double score = changed ? Math.min(1.08 * (impact + exploitability), 10) : Math.min(impact + exploitability, 10);
            return roundUp(score);
        } catch (RuntimeException e) {
            return -1;
        }
    }

    private static double cia(String v) {
        return switch (v) { case "H" -> 0.56; case "L" -> 0.22; case "N" -> 0; default -> throw new IllegalArgumentException(); };
    }

    private static double roundUp(double d) {
        long i = Math.round(d * 100000);
        if (i % 10000 == 0) return i / 100000.0;
        return (Math.floor(i / 10000.0) + 1) / 10.0;
    }
}
