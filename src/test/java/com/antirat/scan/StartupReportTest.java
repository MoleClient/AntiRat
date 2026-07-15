package com.antirat.scan;

import com.antirat.model.RiskLevel;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class StartupReportTest {
    @TempDir
    Path gameDirectory;

    @Test
    void pendingReportSurvivesAndMovesToHistoryAfterDelivery() throws Exception {
        StartupReport.Entry entry = new StartupReport.Entry(ScanStatus.QUARANTINED,
                "/game/mods/bad.jar", "/game/.antirat/quarantine/bad.jar.disabled",
                "a".repeat(64), "bad", "Bad Mod", 98, RiskLevel.CRITICAL,
                Set.of(Capability.MINECRAFT_SESSION, Capability.UNTRUSTED_NETWORK),
                List.of("credential source", "exfiltration sink"), Instant.parse("2026-07-14T12:00:00Z"), "moved");

        StartupReport.mergePending(gameDirectory, List.of(entry), "test");
        StartupReport.Report loaded = StartupReport.readPending(gameDirectory);

        assertEquals(1, loaded.entries().size());
        assertEquals(entry.sha256(), loaded.entries().getFirst().sha256());
        assertEquals(entry.deniedCapabilities(), loaded.entries().getFirst().deniedCapabilities());

        StartupReport.markPendingDelivered(gameDirectory);
        assertFalse(Files.exists(StartupReport.pendingPath(gameDirectory)));
        try (var history = Files.list(gameDirectory.resolve(".antirat/history"))) {
            assertTrue(history.anyMatch(path -> path.getFileName().toString().startsWith("delivered-")));
        }
    }
}
