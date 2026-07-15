package com.antirat;

import com.antirat.config.AntiRatConfig;
import com.antirat.bootstrap.RuntimeContainment;
import com.antirat.model.RiskLevel;
import com.antirat.model.ThreatEvent;
import com.antirat.model.ThreatType;
import com.antirat.scan.Capability;
import com.antirat.scan.ModIndex;
import com.antirat.scan.ScanStatus;
import com.antirat.scan.StartupReport;
import net.fabricmc.loader.api.FabricLoader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicBoolean;

public final class AntiRatRuntime {
    public static final String MOD_ID = "a-";
    public static final Logger LOGGER = LoggerFactory.getLogger("AntiRat");
    private static final int MAX_HISTORY = 512;
    private static final AtomicBoolean INITIALIZED = new AtomicBoolean();
    private static final AtomicBoolean PENDING_ACKNOWLEDGED = new AtomicBoolean();
    private static final ConcurrentLinkedQueue<ThreatEvent> CLIENT_EVENTS = new ConcurrentLinkedQueue<>();
    private static final Map<String, ThreatEvent> EVENTS_BY_ID = new ConcurrentHashMap<>();
    private static final Map<String, RiskLevel> MOD_RISK = new ConcurrentHashMap<>();
    private static final Map<String, Set<Capability>> DENIED_CAPABILITIES = new ConcurrentHashMap<>();
    private static final Set<String> RUNTIME_LOCKED_MODS = ConcurrentHashMap.newKeySet();
    private static final RuntimeDecisionEngine RUNTIME_DECISIONS = new RuntimeDecisionEngine();
    private static volatile AntiRatConfig config = AntiRatConfig.defaults();
    private static volatile Path gameDir;

    private AntiRatRuntime() {
    }

    public static void initializeClient() {
        if (!INITIALIZED.compareAndSet(false, true)) return;
        gameDir = FabricLoader.getInstance().getGameDir().toAbsolutePath().normalize();
        config = AntiRatConfig.load(gameDir);
        ModIndex.initialize();

        try {
            loadReport(StartupReport.readLatest(gameDir), false);
            StartupReport.Report pending = StartupReport.readPending(gameDir);
            int delivered = loadReport(pending, true);
            if (!pending.entries().isEmpty() && delivered == 0) {
                // Every entry was superseded or cleared by the current policy. Archive it now so
                // stale false-positive notices cannot replay every time the player joins a world.
                acknowledgePendingStartupNotice();
            }
        } catch (IOException exception) {
            report(ThreatEvent.create(ThreatType.PROTECTION_STATUS, RiskLevel.HIGH,
                    "Startup report could not be verified",
                    "AntiRat could not read its persisted scan report, so the previous startup result is unavailable.",
                    MOD_ID, "AntiRat", "", "startup report", false, 100,
                    "Check that the game directory is writable and inspect .antirat for damaged files.",
                    List.of(exception.getClass().getSimpleName())));
        }

        if (!Boolean.getBoolean("antirat.startup.scan.complete")) {
            report(ThreatEvent.create(ThreatType.PROTECTION_STATUS, RiskLevel.HIGH,
                    "Earliest startup scan was not established",
                    "AntiRat loaded, but its early mixin/preLaunch scan did not complete in this process.",
                    MOD_ID, "AntiRat", "", "Fabric startup", false, 100,
                    "Keep only one AntiRat jar installed and verify that mixins are enabled.",
                    List.of("No early-scan completion marker was present")));
        }
    }

    public static AntiRatConfig config() {
        return config;
    }

    public static void report(ThreatEvent event) {
        EVENTS_BY_ID.put(event.id(), event);
        CLIENT_EVENTS.add(event);
        if (EVENTS_BY_ID.size() > MAX_HISTORY) {
            EVENTS_BY_ID.keySet().stream().limit(EVENTS_BY_ID.size() - MAX_HISTORY).forEach(EVENTS_BY_ID::remove);
        }
        LOGGER.warn("{} [{}] source={} target={} blocked={}", event.title(), event.riskLevel().label(),
                event.sourceId(), event.target(), event.blocked());
        RuntimeDecisionEngine.Decision decision = RUNTIME_DECISIONS.evaluate(event, staticallyConfirmed(event.sourceId()));
        if (decision == RuntimeDecisionEngine.Decision.LOCKDOWN
                || decision == RuntimeDecisionEngine.Decision.QUARANTINE) {
            lockdownMod(event.sourceId());
        }
        if (decision == RuntimeDecisionEngine.Decision.QUARANTINE) {
            RuntimeContainment.request(event.sourceId(), event.sourceLabel(), event.type().label());
        }
    }

    public static List<ThreatEvent> drainClientEvents() {
        List<ThreatEvent> events = new ArrayList<>();
        ThreatEvent event;
        while ((event = CLIENT_EVENTS.poll()) != null) events.add(event);
        return List.copyOf(events);
    }

    public static ThreatEvent eventById(String id) {
        return id == null ? null : EVENTS_BY_ID.get(id);
    }

    public static RiskLevel riskForMod(String modId) {
        if (modId == null) return RiskLevel.INFO;
        return MOD_RISK.getOrDefault(modId, RiskLevel.INFO);
    }

    public static boolean capabilityDenied(String modId, Capability capability) {
        if (modId == null) return false;
        if (RUNTIME_LOCKED_MODS.contains(modId)) return true;
        return DENIED_CAPABILITIES.getOrDefault(modId, Set.of()).contains(capability);
    }

    public static boolean runtimeLockedDown(String modId) {
        return modId != null && RUNTIME_LOCKED_MODS.contains(modId);
    }

    public static void lockdownMod(String modId) {
        if (modId == null || modId.isBlank() || modId.equals("unknown") || modId.equals(MOD_ID)) return;
        RUNTIME_LOCKED_MODS.add(modId);
        MOD_RISK.put(modId, RiskLevel.CRITICAL);
        DENIED_CAPABILITIES.put(modId, Set.copyOf(EnumSet.allOf(Capability.class)));
    }

    public static void acknowledgePendingStartupNotice() {
        if (gameDir == null || !PENDING_ACKNOWLEDGED.compareAndSet(false, true)) return;
        try {
            StartupReport.markPendingDelivered(gameDir);
        } catch (IOException exception) {
            LOGGER.warn("Could not archive delivered AntiRat startup report", exception);
            PENDING_ACKNOWLEDGED.set(false);
        }
    }

    private static int loadReport(StartupReport.Report report, boolean pending) {
        int reported = 0;
        for (StartupReport.Entry entry : report.entries()) {
            if (entry.status() == ScanStatus.ALLOWLISTED || entry.status() == ScanStatus.CLEAN) continue;
            if (pending && stalePendingEntry(entry)) {
                LOGGER.info("Retired stale pending quarantine notice for {}", entry.modId());
                continue;
            }
            MOD_RISK.merge(entry.modId(), entry.riskLevel(), AntiRatRuntime::higherRisk);
            DENIED_CAPABILITIES.merge(entry.modId(), entry.deniedCapabilities(), AntiRatRuntime::mergeCapabilities);
            if (pending) {
                reportPendingEntry(entry);
                reported++;
            } else if (entry.status() == ScanStatus.WARNED) {
                reportWarningEntry(entry);
                reported++;
            }
        }
        return reported;
    }

    private static boolean stalePendingEntry(StartupReport.Entry entry) {
        if (entry.status() != ScanStatus.QUARANTINED
                && entry.status() != ScanStatus.DEPENDENCY_QUARANTINED) return false;

        // Reinstalling/upgrading the same mod ID supersedes an older quarantined artifact. The
        // active binary has its own current startup verdict and the historical one must not be
        // presented as though it happened again during this launch.
        Path active = ModIndex.primaryOrigin(entry.modId()).orElse(null);
        if (active != null && Files.isRegularFile(active)) return true;

        // Static startup quarantines can be safely rescored under the current detector. Runtime
        // behavioral quarantines are deliberately not cleared by a later static-only scan.
        if (entry.status() != ScanStatus.QUARANTINED
                || !entry.message().equals("Moved out of the Fabric mods path before normal mod initialization")) {
            return false;
        }
        try {
            Path quarantine = Path.of(entry.quarantinePath()).toAbsolutePath().normalize();
            Path quarantineRoot = gameDir.resolve(".antirat").resolve("quarantine").toAbsolutePath().normalize();
            if (!quarantine.startsWith(quarantineRoot) || !Files.isRegularFile(quarantine)) return false;
            com.antirat.scan.ScanResult current = new com.antirat.scan.JarScanner(config).scan(quarantine);
            return config.isHashAllowed(current.sha256()) || !current.quarantineRecommended();
        } catch (IOException | RuntimeException ignored) {
            return false;
        }
    }

    private static void reportPendingEntry(StartupReport.Entry entry) {
        boolean direct = entry.status() == ScanStatus.QUARANTINED;
        boolean dependent = entry.status() == ScanStatus.DEPENDENCY_QUARANTINED;
        boolean quarantined = direct || dependent;
        ThreatType type = direct ? ThreatType.MOD_QUARANTINED
                : dependent ? ThreatType.MOD_DEPENDENCY_DISABLED : ThreatType.QUARANTINE_FAILURE;
        String title = direct ? "Threat prevented and quarantined"
                : dependent ? "Dependent mod disabled for clean launch" : "Threat detected; quarantine failed";
        String summary = direct
                ? "AntiRat moved this jar out of the Fabric mods path before normal mod initialization and denied its guarded capabilities in the original process."
                : dependent
                ? "AntiRat disabled this jar because it declared a hard dependency on a quarantined threat."
                : "AntiRat detected a high-confidence malicious behavior chain but could not verify quarantine.";
        List<String> evidence = new ArrayList<>(entry.evidence());
        evidence.add("SHA-256: " + abbreviatedHash(entry.sha256()));
        if (!entry.message().isBlank()) evidence.add(entry.message());
        RiskLevel displayedRisk = dependent && !entry.riskLevel().atLeast(RiskLevel.MEDIUM)
                ? RiskLevel.MEDIUM : entry.riskLevel();
        report(ThreatEvent.create(type, displayedRisk, title, summary, entry.modId(), entry.modName(),
                entry.originalPath(), quarantined ? entry.quarantinePath() : entry.originalPath(), quarantined,
                dependent ? Math.max(75, entry.score()) : entry.score(), quarantined
                        ? direct
                        ? "The original jar is disabled under .antirat/quarantine; do not restore it unless independently verified."
                        : "Restore this jar only after replacing/removing its quarantined dependency and reviewing both files."
                        : "Close the game and remove the named jar because containment could not be guaranteed.", evidence));
    }

    private static void reportWarningEntry(StartupReport.Entry entry) {
        if (!entry.riskLevel().atLeast(RiskLevel.HIGH)) {
            LOGGER.debug("Startup observation retained without client alert: source={} risk={} score={}",
                    entry.modId(), entry.riskLevel().label(), entry.score());
            return;
        }
        report(ThreatEvent.create(ThreatType.STARTUP_SCAN, entry.riskLevel(), "Suspicious mod behavior flagged",
                "The startup scan found risk indicators, but not the composite confidence required for automatic quarantine.",
                entry.modId(), entry.modName(), entry.originalPath(), "startup scan", false, entry.score(),
                "Review the evidence and obtain the mod from a trusted, verifiable source.", entry.evidence()));
    }

    private static RiskLevel higherRisk(RiskLevel left, RiskLevel right) {
        return left.atLeast(right) ? left : right;
    }

    private static Set<Capability> mergeCapabilities(Set<Capability> left, Set<Capability> right) {
        EnumSet<Capability> result = EnumSet.noneOf(Capability.class);
        result.addAll(left);
        result.addAll(right);
        return Set.copyOf(result);
    }

    private static String abbreviatedHash(String hash) {
        if (hash == null || hash.isBlank()) return "unavailable";
        return hash.length() <= 20 ? hash : hash.substring(0, 20) + "...";
    }

    private static boolean staticallyConfirmed(String modId) {
        com.antirat.scan.ScanResult result = com.antirat.scan.ScanRegistry.startupResult(modId);
        if (result == null || config.isHashAllowed(result.sha256())) return false;
        return result.quarantineRecommended()
                || (result.highConfidence() && result.riskLevel().atLeast(RiskLevel.HIGH));
    }
}
