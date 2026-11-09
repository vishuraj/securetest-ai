package com.securetest.core.spi;

import com.securetest.core.model.Finding;

import java.io.IOException;
import java.nio.file.Path;
import java.util.List;
import java.util.Optional;

/**
 * Deterministic, rule-based remediation (SRS 7.3, 9.2 "local/no-AI mode").
 * A provider proposes full new file contents; the change-set engine computes the diff,
 * snapshots originals and handles apply / undo.
 */
public interface FixProvider {

    boolean supports(Finding finding);

    Optional<ProposedFix> propose(Finding finding, Path sourceRoot) throws IOException;

    /** @param securitySensitive security/auth/crypto changes always need an approver (SRS 9.2). */
    record ProposedFix(String title, String explanation, List<FileEdit> edits, boolean securitySensitive, String provenance) { }

    /** @param path path relative to the source root */
    record FileEdit(String path, String newContent) { }
}
