package com.antirat.model;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

public record ThreatEvent(
        String id,
        ThreatType type,
        RiskLevel riskLevel,
        String title,
        String summary,
        String sourceId,
        String sourceLabel,
        String sourcePath,
        String target,
        boolean blocked,
        int accuracy,
        String tip,
        List<String> evidence,
        Instant timestamp
) {
    public ThreatEvent {
        evidence = evidence == null ? List.of() : List.copyOf(evidence);
        timestamp = timestamp == null ? Instant.now() : timestamp;
        sourceId = blankDefault(sourceId, "unknown");
        sourceLabel = blankDefault(sourceLabel, sourceId);
        sourcePath = sourcePath == null ? "" : sourcePath;
        target = target == null ? "" : target;
        accuracy = Math.max(0, Math.min(100, accuracy));
    }

    public static ThreatEvent create(
            ThreatType type,
            RiskLevel riskLevel,
            String title,
            String summary,
            String sourceId,
            String sourceLabel,
            String sourcePath,
            String target,
            boolean blocked,
            int accuracy,
            String tip,
            List<String> evidence
    ) {
        String id = UUID.randomUUID().toString().replace("-", "").substring(0, 12);
        return new ThreatEvent(id, type, riskLevel, title, summary, sourceId, sourceLabel,
                sourcePath, target, blocked, accuracy, tip, evidence, Instant.now());
    }

    private static String blankDefault(String value, String fallback) {
        return value == null || value.isBlank() ? fallback : value;
    }
}
