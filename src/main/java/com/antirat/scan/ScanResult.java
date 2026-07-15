package com.antirat.scan;

import com.antirat.model.RiskLevel;

import java.nio.file.Path;
import java.util.List;
import java.util.Set;

public record ScanResult(
        Path source,
        String sha256,
        String modId,
        String modName,
        int score,
        RiskLevel riskLevel,
        boolean highConfidence,
        boolean quarantineRecommended,
        Set<String> requiredModIds,
        Set<Capability> deniedCapabilities,
        List<String> evidence,
        int classCount,
        int nestedArchiveCount
) {
    public ScanResult {
        requiredModIds = Set.copyOf(requiredModIds);
        deniedCapabilities = Set.copyOf(deniedCapabilities);
        evidence = List.copyOf(evidence);
        score = Math.max(0, Math.min(100, score));
    }

    public String sourceLabel() {
        if (modName != null && !modName.isBlank()) return modName;
        if (source != null && source.getFileName() != null) return source.getFileName().toString();
        return modId == null || modId.isBlank() ? "unknown mod" : modId;
    }
}
