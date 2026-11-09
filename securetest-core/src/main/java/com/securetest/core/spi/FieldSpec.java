package com.securetest.core.spi;

import com.securetest.core.model.Enums.FieldType;

import java.util.List;

/**
 * One input in the configuration modal. {@code section} is one of
 * "credentials", "required" or "optional" (SRS 6.2).
 */
public record FieldSpec(
        String key,
        String label,
        FieldType type,
        String section,
        boolean required,
        String defaultValue,
        String help,
        List<String> options,
        Integer min,
        Integer max) {

    public static FieldSpec required(String key, String label, FieldType type, String defaultValue, String help) {
        return new FieldSpec(key, label, type, "required", true, defaultValue, help, List.of(), null, null);
    }

    public static FieldSpec optional(String key, String label, FieldType type, String defaultValue, String help) {
        return new FieldSpec(key, label, type, "optional", false, defaultValue, help, List.of(), null, null);
    }

    public static FieldSpec number(String key, String label, int def, int min, int max, String help) {
        return new FieldSpec(key, label, FieldType.NUMBER, "optional", false, String.valueOf(def), help, List.of(), min, max);
    }

    public static FieldSpec select(String key, String label, String def, List<String> options, String help) {
        return new FieldSpec(key, label, FieldType.SELECT, "optional", false, def, help, options, null, null);
    }

    public static FieldSpec flag(String key, String label, boolean def, String help) {
        return new FieldSpec(key, label, FieldType.BOOLEAN, "optional", false, String.valueOf(def), help, List.of(), null, null);
    }

    /** A credential. Accepts a secret reference (env://, prop://, file://, secret://) or a value kept in memory only. */
    public static FieldSpec secret(String key, String label, boolean required, String help) {
        return new FieldSpec(key, label, FieldType.SECRET, "credentials", required, null, help, List.of(), null, null);
    }
}
