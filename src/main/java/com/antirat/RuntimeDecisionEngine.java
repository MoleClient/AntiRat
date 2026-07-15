package com.antirat;

import com.antirat.model.RiskLevel;
import com.antirat.model.ThreatEvent;
import com.antirat.model.ThreatType;

import java.util.EnumSet;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/** Correlates independent runtime signals so one ambiguous low-level API cannot quarantine a mod. */
final class RuntimeDecisionEngine {
    enum Decision {
        OBSERVE,
        LOCKDOWN,
        QUARANTINE
    }

    private static final EnumSet<ThreatType> CREDENTIAL_SOURCES = EnumSet.of(
            ThreatType.SESSION_TOKEN_ACCESS,
            ThreatType.DISCORD_CREDENTIAL_ACCESS,
            ThreatType.SENSITIVE_FILE_ACCESS,
            ThreatType.COOKIE_ACCESS
    );
    private static final EnumSet<ThreatType> EGRESS = EnumSet.of(
            ThreatType.NETWORK_REQUEST,
            ThreatType.PROCESS_EXECUTION
    );

    private final Map<String, EnumSet<ThreatType>> signals = new ConcurrentHashMap<>();

    Decision evaluate(ThreatEvent event, boolean staticallyConfirmed) {
        if (event == null || !event.blocked() || !event.riskLevel().atLeast(RiskLevel.HIGH)
                || event.sourceId().equals("unknown") || event.sourceId().equals(AntiRatRuntime.MOD_ID)
                || !runtimeSecurityType(event.type())) {
            return Decision.OBSERVE;
        }

        EnumSet<ThreatType> observed = signals.computeIfAbsent(event.sourceId(), ignored ->
                EnumSet.noneOf(ThreatType.class));
        synchronized (observed) {
            observed.add(event.type());
            if (staticallyConfirmed) return Decision.QUARANTINE;

            boolean credential = observed.stream().anyMatch(CREDENTIAL_SOURCES::contains);
            boolean egress = observed.stream().anyMatch(EGRESS::contains);
            if (credential && egress) return Decision.QUARANTINE;

            long credentialKinds = observed.stream().filter(CREDENTIAL_SOURCES::contains).count();
            if (credentialKinds >= 2) return Decision.LOCKDOWN;

            // Multiple independent escape behaviors are substantially stronger evidence than one
            // legitimate renderer or performance mod invoking a low-level API.
            if (observed.contains(ThreatType.DYNAMIC_CODE_EXECUTION) && egress && observed.size() >= 3) {
                return Decision.QUARANTINE;
            }
            return Decision.OBSERVE;
        }
    }

    private static boolean runtimeSecurityType(ThreatType type) {
        return switch (type) {
            case SESSION_TOKEN_ACCESS, DISCORD_CREDENTIAL_ACCESS, SENSITIVE_FILE_ACCESS,
                    NETWORK_REQUEST, COOKIE_ACCESS, PROCESS_EXECUTION, DYNAMIC_CODE_EXECUTION -> true;
            default -> false;
        };
    }
}
