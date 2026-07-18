package com.antirat.bootstrap;

import com.antirat.client.AntiRatClient;
import com.antirat.client.UiColor;
import com.antirat.AntiRatRuntime;
import com.antirat.config.AntiRatConfig;
import com.antirat.model.RiskLevel;
import com.antirat.model.ThreatEvent;
import com.antirat.model.ThreatType;
import com.antirat.scan.JarScanner;
import com.antirat.scan.ModIndex;
import com.antirat.scan.ScanResult;
import com.antirat.scan.ScanStatus;
import com.antirat.scan.StartupReport;
import com.mojang.brigadier.CommandDispatcher;
import com.mojang.brigadier.arguments.StringArgumentType;
import com.mojang.brigadier.builder.LiteralArgumentBuilder;
import com.mojang.brigadier.builder.RequiredArgumentBuilder;
import net.fabricmc.loader.api.FabricLoader;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/** Local-only quarantine management commands intercepted before they can reach a server. */
public final class AntiRatCommands {
    private static final DateTimeFormatter DISPLAY_TIME = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")
            .withZone(ZoneId.systemDefault());
    private static final ExecutorService WORKER = Executors.newSingleThreadExecutor(runnable -> {
        Thread thread = new Thread(runnable, "AntiRat command worker");
        thread.setDaemon(true);
        return thread;
    });

    private AntiRatCommands() {
    }

    /** Returns true only for commands owned and consumed by AntiRat. */
    public static boolean handle(String command) {
        if (command == null) return false;
        String normalized = command.strip();
        if (!normalized.equalsIgnoreCase("antirat")
                && !normalized.toLowerCase(Locale.ROOT).startsWith("antirat ")) return false;

        String[] parts = normalized.split("\\s+");
        if (parts.length == 1 || parts[1].equalsIgnoreCase("help")) {
            help();
            return true;
        }
        switch (parts[1].toLowerCase(Locale.ROOT)) {
            case "list" -> WORKER.execute(AntiRatCommands::listQuarantined);
            case "placeholder" -> placeholder();
            case "show", "see" -> {
                if (parts.length < 3) error("Usage: /antirat show <event-id>");
                else AntiRatClient.openEvent(parts[2]);
            }
            case "info" -> {
                if (parts.length < 3) error("Usage: /antirat info <mod-id>");
                else WORKER.execute(() -> info(parts[2]));
            }
            case "scan" -> {
                if (parts.length < 3) error("Usage: /antirat scan <mod-id>");
                else WORKER.execute(() -> scan(parts[2]));
            }
            case "quarantine" -> {
                if (parts.length < 3) error("Usage: /antirat quarantine <mod-id>");
                else WORKER.execute(() -> quarantine(parts[2]));
            }
            case "unquarantine" -> {
                if (parts.length < 3) error("Usage: /antirat unquarantine <mod-id> [confirm]");
                else {
                    boolean confirmed = parts.length >= 4 && parts[3].equalsIgnoreCase("confirm");
                    WORKER.execute(() -> unquarantine(parts[2], confirmed));
                }
            }
            default -> error("Unknown AntiRat command. Use /antirat help");
        }
        return true;
    }

    /** Adds AntiRat to Minecraft's client command tree so syntax highlighting and tab completion work. */
    public static <S> void registerSuggestions(CommandDispatcher<S> dispatcher) {
        if (dispatcher == null) return;
        LiteralArgumentBuilder<S> root = literal("antirat");
        root.then(literal("help"));
        root.then(literal("list"));
        root.then(literal("placeholder"));
        root.then(AntiRatCommands.<S>literal("show").then(RequiredArgumentBuilder
                .<S, String>argument("event-id", StringArgumentType.word())
                .executes(context -> 0)));
        root.then(AntiRatCommands.<S>literal("see").then(RequiredArgumentBuilder
                .<S, String>argument("event-id", StringArgumentType.word())
                .executes(context -> 0)));
        root.then(modArgument("info"));
        root.then(modArgument("scan"));
        root.then(modArgument("quarantine"));

        RequiredArgumentBuilder<S, String> restoreId = RequiredArgumentBuilder
                .<S, String>argument("mod-id", StringArgumentType.word())
                .suggests((context, builder) -> {
                    for (QuarantineManager.Artifact artifact : QuarantineManager.list(gameDir())) {
                        builder.suggest(artifact.modId());
                    }
                    return builder.buildFuture();
                }).executes(context -> 0);
        restoreId.then(literal("confirm"));
        root.then(AntiRatCommands.<S>literal("unquarantine").then(restoreId));
        dispatcher.register(root);
    }

    private static <S> LiteralArgumentBuilder<S> literal(String value) {
        return LiteralArgumentBuilder.<S>literal(value).executes(context -> 0);
    }

    private static <S> LiteralArgumentBuilder<S> modArgument(String command) {
        RequiredArgumentBuilder<S, String> modId = RequiredArgumentBuilder
                .<S, String>argument("mod-id", StringArgumentType.word())
                .suggests((context, builder) -> {
                    FabricLoader.getInstance().getAllMods().stream()
                            .map(container -> container.getMetadata().getId()).sorted().distinct()
                            .forEach(builder::suggest);
                    return builder.buildFuture();
                }).executes(context -> 0);
        return AntiRatCommands.<S>literal(command).then(modId);
    }

    private static void help() {
        message("AntiRat local commands (never sent to the server):", UiColor.AQUA);
        message("/antirat list", UiColor.GRAY);
        message("/antirat placeholder", UiColor.GRAY);
        message("/antirat show <event-id>", UiColor.GRAY);
        message("/antirat info <mod-id>", UiColor.GRAY);
        message("/antirat scan <mod-id>", UiColor.GRAY);
        message("/antirat quarantine <mod-id>", UiColor.GRAY);
        message("/antirat unquarantine <mod-id> [confirm]", UiColor.GRAY);
    }

    private static void placeholder() {
        ThreatEvent preview = ThreatEvent.create(ThreatType.PROTECTION_STATUS, RiskLevel.INFO,
                "AntiRat placeholder",
                "This is a harmless preview of the AntiRat details popup; no mod was blocked or quarantined.",
                AntiRatRuntime.MOD_ID, "AntiRat", "", "UI preview", false, 100,
                "Press Escape to close this placeholder.",
                List.of("Local /antirat placeholder command", "No security decision was made"));
        AntiRatClient.openPreview(preview);
    }

    private static void scan(String modId) {
        String id = modId.toLowerCase(Locale.ROOT);
        Path source = ModIndex.primaryOrigin(id).orElse(null);
        if (source == null || !Files.isRegularFile(source)) {
            error("No active mods-folder JAR was found for " + modId);
            return;
        }
        try {
            ScanResult result = new JarScanner(AntiRatRuntime.config()).scan(source);
            UiColor verdictColor = result.quarantineRecommended() ? UiColor.RED
                    : result.riskLevel().atLeast(RiskLevel.HIGH) ? UiColor.YELLOW : UiColor.GREEN;
            message("Scan: " + result.modName() + " (" + result.modId() + ")", UiColor.AQUA);
            message("Risk " + result.riskLevel().label() + " | score " + result.score()
                    + " | quarantine " + (result.quarantineRecommended() ? "recommended" : "no"), verdictColor);
            if (result.evidence().isEmpty()) {
                message("No notable static indicators.", UiColor.GRAY);
            } else {
                for (String evidence : result.evidence().stream().limit(6).toList()) {
                    message("- " + evidence, UiColor.GRAY);
                }
            }
            if (result.quarantineRecommended()) {
                message("Use /antirat quarantine " + result.modId() + " to move it out of mods.", UiColor.RED);
            } else {
                message("Read-only scan complete; no files were changed.", UiColor.DARK_GRAY);
            }
        } catch (Exception failure) {
            error("Could not scan " + modId + ": " + safeMessage(failure));
        }
    }

    private static void listQuarantined() {
        List<QuarantineManager.Artifact> artifacts = QuarantineManager.list(gameDir());
        if (artifacts.isEmpty()) {
            message("No mods are currently quarantined.", UiColor.GREEN);
            return;
        }
        message("Quarantined mods (" + artifacts.size() + "):", UiColor.GOLD);
        for (QuarantineManager.Artifact artifact : artifacts.stream().limit(25).toList()) {
            message("- " + artifact.modId() + " | " + artifact.modName() + " | score " + artifact.score()
                    + " | " + DISPLAY_TIME.format(artifact.timestamp()), UiColor.GRAY);
        }
        if (artifacts.size() > 25) message("Showing the newest 25 entries.", UiColor.DARK_GRAY);
    }

    private static void info(String modId) {
        QuarantineManager.Artifact artifact = findArtifact(modId);
        if (artifact == null) {
            error("No quarantined artifact was found for " + modId);
            return;
        }
        message(artifact.modName() + " (" + artifact.modId() + ")", UiColor.GOLD);
        message("Score: " + artifact.score() + " | SHA-256: " + abbreviated(artifact.sha256()), UiColor.GRAY);
        message("Quarantined: " + DISPLAY_TIME.format(artifact.timestamp()), UiColor.GRAY);
        message("Original file: " + fileName(artifact.originalPath()), UiColor.GRAY);
        if (artifact.score() >= AntiRatConfig.DEFAULT_QUARANTINE_THRESHOLD) {
            message("High-confidence entry: unquarantine requires the final 'confirm' argument.", UiColor.RED);
        }
    }

    private static void quarantine(String modId) {
        String id = modId.toLowerCase(Locale.ROOT);
        if (id.equals(AntiRatRuntime.MOD_ID) || id.equals("minecraft") || id.equals("java")
                || id.equals("fabricloader")) {
            error("AntiRat cannot quarantine protected infrastructure mod " + modId);
            return;
        }
        Path gameDir = gameDir();
        Path source = ModIndex.primaryOrigin(id).orElse(null);
        if (source == null || !Files.isRegularFile(source)) {
            error("No regular mods-folder JAR was found for " + modId);
            return;
        }
        Path mods = gameDir.resolve("mods").toAbsolutePath().normalize();
        source = source.toAbsolutePath().normalize();
        if (!source.startsWith(mods) || !mods.equals(source.getParent())) {
            error("Only top-level JARs in this profile's mods folder can be quarantined");
            return;
        }
        try {
            ScanResult result = new JarScanner(AntiRatRuntime.config()).scan(source);
            StartupReport.Entry entry = QuarantineManager.quarantine(gameDir, result, ScanStatus.QUARANTINED,
                    "Manually quarantined with /antirat; no restart was requested");
            StartupReport.mergePending(gameDir, List.of(entry), "manual-command");
            boolean pendingRemoval = entry.status() == ScanStatus.QUARANTINE_PENDING;
            if (entry.status() != ScanStatus.QUARANTINED && !pendingRemoval) {
                error("Could not quarantine " + modId + ": " + entry.message());
                return;
            }
            AntiRatRuntime.report(ThreatEvent.create(ThreatType.MOD_QUARANTINED, RiskLevel.INFO,
                    "Mod manually quarantined",
                    pendingRemoval
                            ? "The selected JAR is locked by the running game; its capabilities are denied and verified removal is scheduled for process exit."
                            : "The selected JAR was moved out of mods. Already-loaded classes remain active until Minecraft closes.",
                    result.modId(), result.modName(), entry.originalPath(), entry.quarantinePath(), true,
                    100, "The mod will be absent on the next launch. Use /antirat unquarantine " + result.modId()
                            + " to restore it.", List.of("Manual local command", "No restart was initiated")));
            message((pendingRemoval ? "Contained " : "Quarantined ") + result.modId()
                            + (pendingRemoval ? "; its locked JAR will be removed after Minecraft closes."
                            : ". It remains loaded until you normally close Minecraft."),
                    UiColor.GOLD);
        } catch (Exception failure) {
            error("Could not quarantine " + modId + ": " + safeMessage(failure));
        }
    }

    private static void unquarantine(String modId, boolean confirmed) {
        Path activeOrigin = ModIndex.primaryOrigin(modId.toLowerCase(Locale.ROOT)).orElse(null);
        if (activeOrigin != null && Files.isRegularFile(activeOrigin)) {
            error(modId + " already has an active JAR in mods; remove that version before restoring an older quarantine");
            return;
        }
        QuarantineManager.RestoreResult result = QuarantineManager.restore(gameDir(), modId, confirmed);
        switch (result.status()) {
            case RESTORED -> message(result.message(), UiColor.GREEN);
            case CONFIRMATION_REQUIRED -> {
                message(result.message(), UiColor.RED);
                message("/antirat unquarantine " + modId + " confirm", UiColor.YELLOW);
            }
            case FAILED -> error(result.message());
        }
    }

    private static QuarantineManager.Artifact findArtifact(String modId) {
        return QuarantineManager.list(gameDir()).stream()
                .filter(artifact -> artifact.modId().equalsIgnoreCase(modId)).findFirst().orElse(null);
    }

    private static Path gameDir() {
        return FabricLoader.getInstance().getGameDir().toAbsolutePath().normalize();
    }

    private static String abbreviated(String hash) {
        return hash == null || hash.length() <= 20 ? String.valueOf(hash) : hash.substring(0, 20) + "...";
    }

    private static String fileName(String path) {
        try {
            Path value = Path.of(path);
            return value.getFileName() == null ? path : value.getFileName().toString();
        } catch (RuntimeException ignored) {
            return path;
        }
    }

    private static String safeMessage(Throwable failure) {
        String value = failure.getMessage();
        return failure.getClass().getSimpleName() + (value == null || value.isBlank() ? "" : ": " + value);
    }

    private static void error(String value) {
        message(value, UiColor.RED);
    }

    private static void message(String value, UiColor color) {
        AntiRatClient.postSystemMessage(value, color);
    }
}
