package com.securetest.autoconfigure.service;

import com.securetest.autoconfigure.SecureTestProperties;
import com.securetest.autoconfigure.support.AppContext;
import com.securetest.core.model.Enums.JobStatus;
import com.securetest.core.model.Enums.ModuleState;
import com.securetest.core.model.ModuleCatalog;
import com.securetest.core.model.ModuleCatalog.ModuleInfo;
import com.securetest.core.model.ScanJob;
import com.securetest.core.model.Severity;
import com.securetest.core.spi.ScannerDescriptor;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/** Per-module state and the release gate, shared by the dashboard API and the "All services" summary. */
public class StatusService {

    private final SecureTestProperties props;
    private final AppContext app;
    private final ModuleService modules;
    private final ScannerRegistry registry;
    private final JobService jobs;
    private final FindingService findings;

    public StatusService(SecureTestProperties props, AppContext app, ModuleService modules, ScannerRegistry registry, JobService jobs,
                         FindingService findings) {
        this.props = props;
        this.app = app;
        this.modules = modules;
        this.registry = registry;
        this.jobs = jobs;
        this.findings = findings;
    }

    public List<Map<String, Object>> moduleViews() {
        return ModuleCatalog.MODULES.stream().map(this::moduleView).toList();
    }

    public Map<String, Object> moduleView(ModuleInfo info) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("id", info.id());
        m.put("name", info.name());
        m.put("summary", info.summary());
        m.put("help", info.help());
        m.put("enabled", modules.isEnabled(info.id()));
        m.put("locked", modules.isLocked(info.id()));
        m.put("toggleSource", modules.source(info.id()));
        m.put("state", state(info.id()));
        m.put("scanners", registry.descriptors(info.id()).stream().map(ScannerDescriptor::getId).toList());
        Optional<ScanJob> last = jobs.latestForModule(info.id());
        m.put("lastRun", last.orElse(null));
        m.put("lastSuccess", lastEnded(info.id(), JobStatus.COMPLETED));
        m.put("lastFailure", lastEnded(info.id(), JobStatus.FAILED));
        m.put("openFindings", findings.openCounts(info.id()));
        m.put("settings", modules.settings(info.id()));
        return m;
    }

    /** Compact module status for the cross-service view. */
    public List<Map<String, Object>> moduleStatus() {
        List<Map<String, Object>> out = new ArrayList<>();
        for (ModuleInfo info : ModuleCatalog.MODULES) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("id", info.id());
            m.put("name", info.name());
            m.put("enabled", modules.isEnabled(info.id()));
            m.put("state", state(info.id()));
            m.put("open", findings.openCounts(info.id()));
            m.put("lastSuccess", lastEnded(info.id(), JobStatus.COMPLETED));
            out.add(m);
        }
        return out;
    }

    public ModuleState state(String id) {
        if (!modules.isEnabled(id)) return ModuleState.DISABLED;
        if (Set.of(ModuleCatalog.MIGRATION).contains(id) && app.sourceRoot().isEmpty()) return ModuleState.NOT_CONFIGURED;
        List<ScanJob> mine = jobs.all().stream().filter(j -> id.equals(j.moduleId)).toList();
        if (mine.stream().anyMatch(j -> j.status == JobStatus.RUNNING)) return ModuleState.RUNNING;
        if (mine.stream().anyMatch(j -> j.status == JobStatus.QUEUED || j.status == JobStatus.AWAITING_APPROVAL)) return ModuleState.QUEUED;
        Map<Severity, Integer> open = findings.openCounts(id);
        if (open.getOrDefault(Severity.CRITICAL, 0) + open.getOrDefault(Severity.HIGH, 0) > 0) return ModuleState.NEEDS_ATTENTION;
        Optional<ScanJob> last = mine.stream().max(Comparator.comparing(j -> j.createdAt));
        if (last.isPresent() && last.get().status == JobStatus.FAILED) return ModuleState.FAILED;
        if (last.isPresent() && last.get().status == JobStatus.COMPLETED) return ModuleState.COMPLETED;
        return ModuleState.READY;
    }

    /** CI/CD release gate: PASS/FAIL against policy thresholds. */
    public Map<String, Object> gate() {
        Map<Severity, Integer> open = findings.openCounts(null);
        int crit = open.getOrDefault(Severity.CRITICAL, 0);
        int high = open.getOrDefault(Severity.HIGH, 0);
        List<String> reasons = new ArrayList<>();
        if (crit > props.getPolicy().getMaxCritical()) reasons.add(crit + " open critical finding(s) (max " + props.getPolicy().getMaxCritical() + ")");
        Severity failOn = Severity.valueOf(props.getPolicy().getFailOn());
        if (failOn.rank() <= Severity.HIGH.rank() && high > props.getPolicy().getMaxHigh()) reasons.add(high + " open high finding(s) (max " + props.getPolicy().getMaxHigh() + ")");
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("status", reasons.isEmpty() ? "PASS" : "FAIL");
        m.put("reasons", reasons);
        m.put("open", open);
        m.put("evaluatedAt", Instant.now());
        return m;
    }

    private Instant lastEnded(String moduleId, JobStatus status) {
        return jobs.all().stream().filter(j -> moduleId.equals(j.moduleId) && j.status == status)
                .map(j -> j.endedAt).filter(java.util.Objects::nonNull).max(Comparator.naturalOrder()).orElse(null);
    }
}
