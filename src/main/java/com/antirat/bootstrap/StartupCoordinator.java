package com.antirat.bootstrap;

import com.antirat.AntiRatRuntime;
import com.antirat.config.AntiRatConfig;
import com.antirat.model.RiskLevel;
import com.antirat.scan.Capability;
import com.antirat.scan.JarScanner;
import com.antirat.scan.ScanResult;
import com.antirat.scan.ScanRegistry;
import com.antirat.scan.ScanStatus;
import com.antirat.scan.StartupReport;
import com.antirat.guard.NetworkGuard;
import net.fabricmc.loader.api.FabricLoader;
import net.fabricmc.loader.api.ModContainer;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.ExecutionException;
import java.util.stream.Stream;

public final class StartupCoordinator {
    private static final String MOD_ID = "a-";
    private static final AtomicBoolean RAN = new AtomicBoolean();

    private StartupCoordinator() {
    }

    public static void runOnce(String phase) {
        if (!RAN.compareAndSet(false, true)) return;
        Path gameDir = FabricLoader.getInstance().getGameDir().toAbsolutePath().normalize();
        Path modsDir = gameDir.resolve("mods");
        AntiRatConfig config = AntiRatConfig.load(gameDir);
        JarScanner scanner = new JarScanner(config);
        Set<Path> ownPaths = ownPaths();
        Path agentJar = ownPaths.stream()
                .filter(Files::isRegularFile)
                .filter(path -> path.getFileName().toString().toLowerCase(java.util.Locale.ROOT).endsWith(".jar"))
                .findFirst().orElse(null);
        List<ScanResult> scanResults = new ArrayList<>();
        List<StartupReport.Entry> latest = new ArrayList<>();
        List<StartupReport.Entry> pending = new ArrayList<>();
        Set<Path> failedInspections = new HashSet<>();
        boolean quarantinedAny = false;
        boolean quarantineFailed = false;

        List<Path> jars = discoverJars(modsDir).stream()
                .filter(jar -> !isOwnJar(jar, ownPaths)).toList();
        for (Inspection inspection : inspectInParallel(jars, scanner)) {
            ScanResult result = inspection.result();
            scanResults.add(result);
            ScanRegistry.record(result);
            if (inspection.failure() != null) {
                failedInspections.add(result.source());
                System.err.println("[AntiRat] Fail-closed inspection verdict for " + inspection.source().getFileName()
                        + ": " + inspection.failure().getClass().getSimpleName());
            }
        }

        Set<Path> directThreats = new HashSet<>();
        Set<String> removedModIds = new HashSet<>();
        for (ScanResult result : scanResults) {
            if (failedInspections.contains(result.source())
                    || (!config.isHashAllowed(result.sha256()) && result.quarantineRecommended())) {
                directThreats.add(result.source());
                removedModIds.add(result.modId());
            }
        }
        Map<Path, String> dependentQuarantines = dependentQuarantines(scanResults, directThreats, removedModIds);
        boolean loaderSuppressed = directThreats.isEmpty()
                || FabricQuarantineBridge.suppressBeforeEntrypointRegistration(removedModIds);

        for (ScanResult result : scanResults) {
            ScanStatus status;
            StartupReport.Entry entry;
            if (directThreats.contains(result.source())) {
                // Lock the source before attempting filesystem containment. If moving the JAR or
                // scheduling a replacement process fails, every guarded capability stays denied.
                AntiRatRuntime.lockdownMod(result.modId());
                entry = loaderSuppressed
                        ? QuarantineManager.quarantine(gameDir, result)
                        : StartupReport.Entry.fromScan(result, ScanStatus.QUARANTINE_FAILED, null,
                        "Fabric entrypoint suppression was unavailable; the source was left in place under runtime lockdown");
                status = entry.status();
                quarantinedAny |= status == ScanStatus.QUARANTINED;
                quarantineFailed |= status == ScanStatus.QUARANTINE_FAILED;
                pending.add(entry);
            } else if (loaderSuppressed && dependentQuarantines.containsKey(result.source())) {
                String dependency = dependentQuarantines.get(result.source());
                entry = QuarantineManager.quarantine(gameDir, result, ScanStatus.DEPENDENCY_QUARANTINED,
                        "Disabled for the clean relaunch because it requires quarantined mod " + dependency);
                status = entry.status();
                quarantinedAny |= status == ScanStatus.DEPENDENCY_QUARANTINED;
                quarantineFailed |= status == ScanStatus.QUARANTINE_FAILED;
                pending.add(entry);
            } else if (config.isHashAllowed(result.sha256())) {
                status = ScanStatus.ALLOWLISTED;
                entry = StartupReport.Entry.fromScan(result, status, null, "Exact local hash allowlist match");
            } else if (result.score() >= config.warningThreshold()) {
                status = ScanStatus.WARNED;
                entry = StartupReport.Entry.fromScan(result, status, null,
                        "Reported without quarantine because the high-confidence threshold was not met");
            } else {
                status = ScanStatus.CLEAN;
                entry = StartupReport.Entry.fromScan(result, status, null, "No high-risk behavior chain detected");
            }
            if (status != ScanStatus.CLEAN) latest.add(entry);
        }

        try {
            StartupReport.writeLatest(gameDir, latest, phase);
            if (!pending.isEmpty()) StartupReport.mergePending(gameDir, pending, phase);
        } catch (IOException exception) {
            throw new IllegalStateException("AntiRat could not persist its startup security report", exception);
        }

        System.setProperty("antirat.startup.scan.complete", "true");
        if (quarantineFailed) {
            System.err.println("[AntiRat] A high-confidence threat could not be moved; continuing with its guarded capabilities locked down.");
        }
        if (quarantinedAny) {
            // Fabric has already discovered this source, so its classes may remain reachable from
            // an open loader handle even after the file is moved. Keep the attributed source in
            // deny-all mode for this process and let Minecraft continue without an in-game restart.
            System.err.println("[AntiRat] Threat quarantined before normal mod initialization; continuing with its source locked down. The next launch will omit it.");
        }
        // Establish the process-wide guard before any later mod language adapter or initializer can make requests.
        NetworkGuard.ensureInstalled();
        if (!AgentBootstrap.active() && agentJar != null && !AgentBootstrap.tryDynamicAttach(agentJar)) {
            System.err.println("[AntiRat] Dynamic runtime guard attachment was unavailable; relaunching once with the bundled agent.");
            if (AutomaticRelaunch.startCleanChild(gameDir, agentJar)) {
                AutomaticRelaunch.terminateForChild();
            }
            System.err.println("[AntiRat] Runtime agent relaunch could not be scheduled; continuing with mixin and JVM-global guards.");
        }
        if (AgentBootstrap.active()) {
            // Bridge to the system-loader agent and explicitly trust this Fabric/Knot code origin before
            // broad delayed-helper coverage is enabled or any already-loaded class is retransformed.
            AgentBootstrap.activateRuntimeProtection(StartupCoordinator.class.getProtectionDomain());
        }
        if (AgentBootstrap.requiresPremainRelaunch()) {
            System.err.println("[AntiRat] An already-loaded class could not be instrumented after dynamic attachment; relaunching under the bundled agent.");
            if (agentJar != null && AutomaticRelaunch.startCleanChild(gameDir, agentJar)) {
                AutomaticRelaunch.terminateForChild();
            }
            System.err.println("[AntiRat] Premain relaunch could not be scheduled; existing lockdown and available guards remain active.");
        }
        if (!AgentBootstrap.active() && agentJar == null && FabricLoader.getInstance().isDevelopmentEnvironment()) {
            System.err.println("[AntiRat] Development run has no agent JAR; call-site runtime enforcement is not active.");
        }
        AutomaticRelaunch.signalReadyIfRelaunched(gameDir);
    }

    static Map<Path, String> dependentQuarantines(
            List<ScanResult> results,
            Set<Path> directThreats,
            Set<String> removedModIds
    ) {
        Map<Path, String> dependent = new HashMap<>();
        boolean changed;
        do {
            changed = false;
            for (ScanResult result : results) {
                if (directThreats.contains(result.source()) || dependent.containsKey(result.source())) continue;
                String missing = result.requiredModIds().stream().filter(removedModIds::contains).findFirst().orElse(null);
                if (missing == null) continue;
                dependent.put(result.source(), missing);
                changed |= removedModIds.add(result.modId());
            }
        } while (changed);
        return Map.copyOf(dependent);
    }

    static ScanResult failedInspection(Path source, Throwable failure) {
        Path normalized = source.toAbsolutePath().normalize();
        String filename = normalized.getFileName() == null ? "uninspectable-mod" : normalized.getFileName().toString();
        String stem = filename.replaceFirst("(?i)\\.jar$", "").toLowerCase(java.util.Locale.ROOT)
                .replaceAll("[^a-z0-9_-]", "_");
        if (stem.isBlank() || !Character.isLetter(stem.charAt(0))) stem = "uninspectable_" + stem;
        if (stem.length() > 63) stem = stem.substring(0, 63);
        String diagnosticHash = pathDiagnosticHash(normalized, failure);
        return new ScanResult(normalized, diagnosticHash, stem, filename, 100, RiskLevel.CRITICAL,
                true, true, Set.of(), java.util.EnumSet.allOf(Capability.class),
                List.of("Fail-closed: AntiRat could not complete inspection of this executable archive",
                        "Inspection failure type: " + failure.getClass().getSimpleName(),
                        "The recorded identifier is diagnostic because content hashing could not be trusted"),
                0, 0);
    }

    private static List<Inspection> inspectInParallel(List<Path> jars, JarScanner scanner) {
        if (jars.isEmpty()) return List.of();
        int workers = Math.max(1, Math.min(4,
                Math.min(jars.size(), Runtime.getRuntime().availableProcessors())));
        ExecutorService executor = Executors.newFixedThreadPool(workers, runnable -> {
            Thread thread = new Thread(runnable, "AntiRat bounded startup scanner");
            thread.setDaemon(true);
            return thread;
        });
        try {
            List<Future<Inspection>> futures = new ArrayList<>(jars.size());
            for (Path jar : jars) {
                futures.add(executor.submit(() -> {
                    try {
                        return new Inspection(jar, scanner.scan(jar), null);
                    } catch (IOException | RuntimeException failure) {
                        return new Inspection(jar, failedInspection(jar, failure), failure);
                    }
                }));
            }
            List<Inspection> results = new ArrayList<>(jars.size());
            for (int index = 0; index < futures.size(); index++) {
                try {
                    results.add(futures.get(index).get());
                } catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                    Path jar = jars.get(index);
                    results.add(new Inspection(jar, failedInspection(jar, interrupted), interrupted));
                    for (int remaining = index + 1; remaining < jars.size(); remaining++) {
                        Path uninspected = jars.get(remaining);
                        results.add(new Inspection(uninspected, failedInspection(uninspected, interrupted), interrupted));
                    }
                    break;
                } catch (ExecutionException failure) {
                    Path jar = jars.get(index);
                    Throwable cause = failure.getCause() == null ? failure : failure.getCause();
                    results.add(new Inspection(jar, failedInspection(jar, cause), cause));
                }
            }
            return List.copyOf(results);
        } finally {
            executor.shutdownNow();
        }
    }

    private static String pathDiagnosticHash(Path source, Throwable failure) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(source.toString().getBytes(StandardCharsets.UTF_8));
            digest.update((byte) 0);
            digest.update(failure.getClass().getName().getBytes(StandardCharsets.UTF_8));
            byte[] bytes = digest.digest();
            StringBuilder hex = new StringBuilder(64);
            for (byte value : bytes) hex.append(String.format(java.util.Locale.ROOT, "%02x", value & 0xff));
            return hex.toString();
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 unavailable", impossible);
        }
    }

    private static List<Path> discoverJars(Path modsDir) {
        if (!Files.isDirectory(modsDir)) return List.of();
        try (Stream<Path> paths = Files.walk(modsDir, 4)) {
            return paths.filter(Files::isRegularFile)
                    .filter(path -> path.getFileName().toString().toLowerCase(java.util.Locale.ROOT).endsWith(".jar"))
                    .sorted(Comparator.comparing(path -> path.toAbsolutePath().normalize().toString()))
                    .toList();
        } catch (IOException | RuntimeException exception) {
            throw new IllegalStateException("AntiRat could not enumerate the mods directory", exception);
        }
    }

    private static Set<Path> ownPaths() {
        Set<Path> paths = new HashSet<>();
        FabricLoader.getInstance().getModContainer(MOD_ID)
                .map(ModContainer::getOrigin)
                .ifPresent(origin -> origin.getPaths().forEach(path -> paths.add(realOrNormalized(path))));
        return Set.copyOf(paths);
    }

    private static boolean isOwnJar(Path candidate, Set<Path> ownPaths) {
        return ownPaths.contains(realOrNormalized(candidate));
    }

    private static Path realOrNormalized(Path path) {
        try {
            return path.toRealPath();
        } catch (IOException ignored) {
            return path.toAbsolutePath().normalize();
        }
    }

    private record Inspection(Path source, ScanResult result, Throwable failure) {
    }
}
