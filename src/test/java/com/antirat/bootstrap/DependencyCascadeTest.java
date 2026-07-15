package com.antirat.bootstrap;

import com.antirat.model.RiskLevel;
import com.antirat.scan.ScanResult;
import org.junit.jupiter.api.Test;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;

class DependencyCascadeTest {
    @Test
    void disablesTransitiveHardDependentsOfQuarantinedThreat() {
        ScanResult threat = result("rat", Set.of());
        ScanResult directDependent = result("addon", Set.of("rat"));
        ScanResult transitiveDependent = result("addon_ui", Set.of("addon"));

        Map<Path, String> cascade = StartupCoordinator.dependentQuarantines(
                List.of(transitiveDependent, directDependent, threat),
                Set.of(threat.source()), new java.util.HashSet<>(Set.of("rat")));

        assertEquals("rat", cascade.get(directDependent.source()));
        assertEquals("addon", cascade.get(transitiveDependent.source()));
    }

    private static ScanResult result(String id, Set<String> dependencies) {
        return new ScanResult(Path.of("/game/mods/" + id + ".jar"), "a".repeat(64), id, id,
                0, RiskLevel.INFO, false, false, dependencies, Set.of(), List.of(), 1, 0);
    }
}
