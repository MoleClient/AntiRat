package com.antirat.bootstrap;

import com.antirat.model.RiskLevel;
import com.antirat.scan.Capability;
import com.antirat.scan.ScanResult;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Path;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class StartupCoordinatorTest {
    @TempDir
    Path temporaryDirectory;

    @Test
    void incompleteInspectionProducesANonAllowlistableFailClosedVerdict() {
        ScanResult result = StartupCoordinator.failedInspection(
                temporaryDirectory.resolve("Unreadable Payload.jar"), new IOException("inert fixture"));

        assertTrue(result.highConfidence());
        assertTrue(result.quarantineRecommended());
        assertEquals(100, result.score());
        assertEquals(RiskLevel.CRITICAL, result.riskLevel());
        assertEquals(Set.copyOf(java.util.EnumSet.allOf(Capability.class)), result.deniedCapabilities());
        assertTrue(result.evidence().stream().anyMatch(value -> value.startsWith("Fail-closed")));
    }
}
