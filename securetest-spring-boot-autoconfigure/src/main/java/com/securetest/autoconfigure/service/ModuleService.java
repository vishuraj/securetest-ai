package com.securetest.autoconfigure.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.securetest.autoconfigure.SecureTestProperties;
import com.securetest.autoconfigure.security.ApiException;
import com.securetest.autoconfigure.support.LocalStore;
import com.securetest.core.model.ModuleCatalog;
import com.securetest.core.model.ModuleCatalog.ModuleInfo;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Feature toggles with policy precedence (FR-005, FR-010, SRS 6.1):
 * locked property (policy) &gt; runtime toggle set in the dashboard &gt; property default &gt; catalog default (OFF except health).
 */
public class ModuleService {

    public static class Toggle {
        public boolean enabled;
        public String updatedBy;
        public Instant updatedAt;
        public int version;
        public Map<String, String> settings = new LinkedHashMap<>();
    }

    private final SecureTestProperties props;
    private final LocalStore store;
    private final Map<String, Toggle> toggles;

    public ModuleService(SecureTestProperties props, LocalStore store) {
        this.props = props;
        this.store = store;
        this.toggles = new ConcurrentHashMap<>(store.load("modules", new TypeReference<Map<String, Toggle>>() { }, LinkedHashMap::new));
        store.register("modules", () -> new LinkedHashMap<>(toggles));
    }

    public boolean isEnabled(String moduleId) {
        ModuleInfo info = ModuleCatalog.find(moduleId).orElse(null);
        if (info == null) return false;
        SecureTestProperties.Module m = props.module(moduleId);
        if (m.isLocked()) return m.getEnabled() != null ? m.getEnabled() : info.defaultEnabled();
        Toggle t = toggles.get(moduleId);
        if (t != null) return t.enabled;
        return m.getEnabled() != null ? m.getEnabled() : info.defaultEnabled();
    }

    public boolean isLocked(String moduleId) {
        return props.module(moduleId).isLocked();
    }

    public String source(String moduleId) {
        if (isLocked(moduleId)) return "policy (locked)";
        if (toggles.containsKey(moduleId)) return "dashboard";
        return props.module(moduleId).getEnabled() != null ? "configuration" : "default";
    }

    public Toggle toggle(String moduleId) {
        return toggles.get(moduleId);
    }

    public Toggle set(String moduleId, Boolean enabled, Map<String, String> settings, String actor) {
        if (ModuleCatalog.find(moduleId).isEmpty()) throw ApiException.notFound("Module " + moduleId);
        if (enabled != null && isLocked(moduleId) && enabled != isEnabled(moduleId)) {
            throw ApiException.forbidden("Module '" + moduleId + "' is locked by policy (securetest.modules." + moduleId + ".locked=true).");
        }
        Toggle t = toggles.computeIfAbsent(moduleId, k -> {
            Toggle n = new Toggle();
            n.enabled = isEnabled(moduleId);
            return n;
        });
        if (enabled != null) t.enabled = enabled;
        if (settings != null) {
            settings.forEach((k, v) -> {
                if (k.matches("[\\w.-]{1,64}") && (v == null || v.length() <= 2000)) {
                    if (v == null) t.settings.remove(k); else t.settings.put(k, v);
                }
            });
        }
        t.updatedBy = actor;
        t.updatedAt = Instant.now();
        t.version++;
        store.markDirty("modules");
        return t;
    }

    public Map<String, String> settings(String moduleId) {
        Toggle t = toggles.get(moduleId);
        return t == null ? Map.of() : t.settings;
    }
}
