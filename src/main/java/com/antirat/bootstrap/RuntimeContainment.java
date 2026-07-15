package com.antirat.bootstrap;

import com.antirat.AntiRatRuntime;
import com.antirat.model.RiskLevel;
import com.antirat.model.ThreatEvent;
import com.antirat.model.ThreatType;
import com.antirat.scan.ScanRegistry;
import com.antirat.scan.ScanResult;
import com.antirat.scan.ScanStatus;
import com.antirat.scan.StartupReport;
import net.fabricmc.loader.api.FabricLoader;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/** Moves a runtime-confirmed offender out of mods while its loaded code is held in deny-all mode. */
public final class RuntimeContainment {
    private static final Set<String> REQUESTED = ConcurrentHashMap.newKeySet();
    private static final ExecutorService WORKER = Executors.newSingleThreadExecutor(runnable -> {
        Thread thread = new Thread(runnable, "AntiRat runtime quarantine");
        thread.setDaemon(true);
        return thread;
    });

    private RuntimeContainment() {
    }

    public static void request(String modId, String modName, String trigger) {
        if (modId == null || modId.isBlank() || modId.equals("unknown") || modId.equals(AntiRatRuntime.MOD_ID)
                || !REQUESTED.add(modId)) return;
        WORKER.execute(() -> quarantine(modId, modName, trigger));
    }

    private static void quarantine(String modId, String modName, String trigger) {
        ScanResult result = ScanRegistry.startupResult(modId);
        if (result == null || result.source() == null || !Files.isRegularFile(result.source())) return;
        Path gameDir;
        try {
            gameDir = FabricLoader.getInstance().getGameDir().toAbsolutePath().normalize();
        } catch (RuntimeException unavailable) {
            return;
        }

        StartupReport.Entry entry = QuarantineManager.quarantine(gameDir, result, ScanStatus.QUARANTINED,
                "Moved out of mods after a blocked runtime action; loaded code locked down until process exit");
        try {
            StartupReport.mergePending(gameDir, List.of(entry), "runtime-containment");
        } catch (IOException exception) {
            AntiRatRuntime.LOGGER.warn("Could not persist runtime quarantine report for {}", modId,
                    exception);
        }

        boolean moved = entry.status() == ScanStatus.QUARANTINED;
        List<String> evidence = new ArrayList<>();
        evidence.add("The triggering action was blocked before the protected operation completed");
        evidence.add("All guarded capabilities for this mod are denied for the rest of this process");
        evidence.add("Runtime trigger category: " + (trigger == null || trigger.isBlank() ? "security barrier" : trigger));
        evidence.addAll(result.evidence().stream().limit(3).toList());
        if (!entry.message().isBlank()) evidence.add(entry.message());

        AntiRatRuntime.report(ThreatEvent.create(
                moved ? ThreatType.MOD_QUARANTINED : ThreatType.QUARANTINE_FAILURE,
                RiskLevel.CRITICAL,
                moved ? "Runtime threat contained and quarantined" : "Runtime threat blocked; quarantine failed",
                moved
                        ? "AntiRat blocked the attempted action and moved the original JAR out of the mods folder. Its already-loaded code remains locked down until the game exits."
                        : "AntiRat blocked the attempted action and locked down the mod, but could not move its original JAR.",
                modId,
                modName,
                entry.originalPath(),
                moved ? entry.quarantinePath() : entry.originalPath(),
                moved,
                Math.max(97, result.score()),
                moved
                        ? "The next normal launch will omit this mod; do not restore it without independent review."
                        : "Close the game after saving and remove the named JAR before the next launch.",
                evidence
        ));
    }
}
