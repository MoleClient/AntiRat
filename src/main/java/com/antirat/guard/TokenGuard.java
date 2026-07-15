package com.antirat.guard;

import com.antirat.AntiRatRuntime;
import com.antirat.model.RiskLevel;
import com.antirat.model.ThreatEvent;
import com.antirat.model.ThreatType;
import com.antirat.scan.Capability;
import com.antirat.scan.ModIdentity;
import com.antirat.scan.ModIndex;
import com.antirat.scan.ScanRegistry;
import com.antirat.scan.ScanResult;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

public final class TokenGuard {
    private static final long REPORT_SUPPRESS_MS = 30_000L;
    private static final Map<String, Long> LAST_REPORT = new ConcurrentHashMap<>();

    private TokenGuard() {
    }

    public static boolean shouldDenySessionToken() {
        return shouldDenySessionToken(null);
    }

    public static boolean shouldDenySessionToken(Class<?> credentialCarrier) {
        // Minecraft/Authlib must be able to consume its own credential for Realms, profile-key,
        // and multiplayer join requests. Direct/reflected mod callers do not pass this boundary.
        ModIndex.CredentialEntryPoint entryPoint = ModIndex.credentialEntryPoint(credentialCarrier);
        if (entryPoint.trusted()) return false;

        ModIndex.CallerContext context = ModIndex.findCredentialCaller();
        if (context.sources().isEmpty()) {
            if (context.trustedPlatformOnly()) return false;
            AntiRatRuntime.LOGGER.warn("Credential consumer could not be trusted: {}", entryPoint.className());
            reportDenied(ModIdentity.UNKNOWN, "Session-token access came from code that could not be attributed to a trusted platform or scanned mod.",
                    91, List.of("Immediate credential consumer: " + entryPoint.className(),
                            "Unattributed application frame was present", "Fail-closed credential decision"));
            return true;
        }

        for (ModIdentity source : context.sources()) {
            Optional<java.nio.file.Path> origin = ModIndex.primaryOrigin(source.id());
            ScanRegistry.Verification verification = origin
                    .map(path -> ScanRegistry.verifyCurrent(source.id(), path, AntiRatRuntime.config()))
                    .orElseGet(() -> ScanRegistry.Verification.failedForCaller(
                            "No inspectable source JAR was available for the calling mod"));
            if (!verification.verified()) {
                reportDenied(source, verification.failure(), 94,
                        List.of("Caller attribution succeeded", "Source integrity could not be revalidated"));
                return true;
            }

            ScanResult result = verification.result();
            // A hash allowlist permits execution after review; it does not silently grant credential capability.
            boolean explicitOverride = AntiRatRuntime.config().isCredentialHashAllowed(result.sha256());
            boolean denied = AntiRatRuntime.runtimeLockedDown(source.id()) || (!explicitOverride && (result.quarantineRecommended()
                    || result.deniedCapabilities().contains(Capability.MINECRAFT_SESSION)
                    || (result.highConfidence() && result.riskLevel().atLeast(RiskLevel.HIGH))
                    || AntiRatRuntime.capabilityDenied(source.id(), Capability.MINECRAFT_SESSION)));
            if (!denied) continue;

            List<String> evidence = new java.util.ArrayList<>();
            evidence.add("The full call chain was attributed; helper libraries cannot launder the request");
            evidence.add(verification.rescanned()
                    ? "The source JAR changed and was rescanned before credential release"
                    : "The source JAR still matches its cached deep-scan file identity");
            evidence.addAll(result.evidence().stream().limit(4).toList());
            reportDenied(source, "A mod without a safe credential verdict called Minecraft's session-token accessor.",
                    Math.max(96, result.score()), evidence);
            return true;
        }
        return false;
    }

    private static void reportDenied(ModIdentity source, String summary, int accuracy, List<String> evidence) {
        long now = System.currentTimeMillis();
        Long previous = LAST_REPORT.put(source.id(), now);
        if (previous == null || now - previous > REPORT_SUPPRESS_MS) {
            AntiRatRuntime.report(ThreatEvent.create(ThreatType.SESSION_TOKEN_ACCESS, RiskLevel.CRITICAL,
                    "Session token access prevented",
                    summary,
                    source.id(), source.name(), "", "Minecraft session", true, accuracy,
                    "Remove the source mod; AntiRat returned no usable session token.",
                    appendNoCapture(evidence)));
        }
    }

    private static List<String> appendNoCapture(List<String> evidence) {
        java.util.ArrayList<String> result = new java.util.ArrayList<>(evidence);
        result.add("Access-token value was never logged or stored");
        return List.copyOf(result);
    }
}
