package com.antirat;

import com.antirat.model.RiskLevel;
import com.antirat.model.ThreatEvent;
import com.antirat.model.ThreatType;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class RuntimeDecisionEngineTest {
    @Test
    void oneAmbiguousUnsafeSignalCannotQuarantineAReadableMod() {
        RuntimeDecisionEngine engine = new RuntimeDecisionEngine();

        assertEquals(RuntimeDecisionEngine.Decision.OBSERVE,
                engine.evaluate(event(ThreatType.DYNAMIC_CODE_EXECUTION), false));
    }

    @Test
    void credentialSourceAndEgressCorrelateIntoQuarantine() {
        RuntimeDecisionEngine engine = new RuntimeDecisionEngine();

        assertEquals(RuntimeDecisionEngine.Decision.OBSERVE,
                engine.evaluate(event(ThreatType.SESSION_TOKEN_ACCESS), false));
        assertEquals(RuntimeDecisionEngine.Decision.QUARANTINE,
                engine.evaluate(event(ThreatType.NETWORK_REQUEST), false));
    }

    @Test
    void staticHighConfidenceStillAllowsImmediateContainment() {
        RuntimeDecisionEngine engine = new RuntimeDecisionEngine();

        assertEquals(RuntimeDecisionEngine.Decision.QUARANTINE,
                engine.evaluate(event(ThreatType.DYNAMIC_CODE_EXECUTION), true));
    }

    private static ThreatEvent event(ThreatType type) {
        return ThreatEvent.create(type, RiskLevel.CRITICAL, "blocked", "test", "fixture-mod",
                "Fixture Mod", "", "test", true, 99, "test", List.of());
    }
}
