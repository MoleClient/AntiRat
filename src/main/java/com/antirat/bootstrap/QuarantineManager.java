package com.antirat.bootstrap;

import com.antirat.scan.ScanResult;
import com.antirat.scan.ScanStatus;
import com.antirat.scan.StartupReport;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Properties;
import java.util.stream.Stream;

final class QuarantineManager {
    private static final DateTimeFormatter DIRECTORY_TIME = DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss")
            .withZone(ZoneOffset.UTC);

    private QuarantineManager() {
    }

    static StartupReport.Entry quarantine(Path gameDir, ScanResult result) {
        return quarantine(gameDir, result, ScanStatus.QUARANTINED,
                "Moved out of the Fabric mods path before normal mod initialization");
    }

    static StartupReport.Entry quarantine(Path gameDir, ScanResult result, ScanStatus successStatus, String successMessage) {
        if (successStatus != ScanStatus.QUARANTINED && successStatus != ScanStatus.DEPENDENCY_QUARANTINED) {
            throw new IllegalArgumentException("invalid quarantine success status");
        }
        Path source = result.source();
        Path destination = null;
        try {
            Path directory = gameDir.resolve(".antirat").resolve("quarantine")
                    .resolve(DIRECTORY_TIME.format(Instant.now()));
            Files.createDirectories(directory);
            String fileName = sanitize(source.getFileName().toString());
            destination = uniqueDestination(directory, result.sha256().substring(0, 16) + "-" + fileName + ".disabled");
            move(source, destination);
            if (Files.exists(source) || !Files.isRegularFile(destination)) {
                throw new IOException("post-move quarantine verification failed");
            }
            writeSidecar(destination, result);
            return StartupReport.Entry.fromScan(result, successStatus, destination, successMessage);
        } catch (IOException | RuntimeException exception) {
            return StartupReport.Entry.fromScan(result, ScanStatus.QUARANTINE_FAILED, destination,
                    exception.getClass().getSimpleName() + ": " + safeMessage(exception.getMessage()));
        }
    }

    static List<Artifact> list(Path gameDir) {
        Path root = gameDir.resolve(".antirat").resolve("quarantine").toAbsolutePath().normalize();
        if (!Files.isDirectory(root)) return List.of();
        List<Artifact> artifacts = new ArrayList<>();
        try (Stream<Path> paths = Files.walk(root, 4)) {
            for (Path disabled : paths.filter(Files::isRegularFile)
                    .filter(path -> path.getFileName().toString().contains(".jar.disabled")).toList()) {
                Path sidecar = disabled.resolveSibling(disabled.getFileName() + ".properties");
                Artifact artifact = readArtifact(root, disabled, sidecar);
                if (artifact != null) artifacts.add(artifact);
            }
        } catch (IOException | RuntimeException ignored) {
            return List.copyOf(artifacts);
        }
        artifacts.sort(Comparator.comparing(Artifact::timestamp).reversed());
        return List.copyOf(artifacts);
    }

    static RestoreResult restore(Path gameDir, String modId, boolean confirmed) {
        if (modId == null || modId.isBlank()) return RestoreResult.failed("A mod id is required");
        List<Artifact> matches = list(gameDir).stream()
                .filter(artifact -> artifact.modId().equalsIgnoreCase(modId)).toList();
        if (matches.isEmpty()) return RestoreResult.failed("No quarantined artifact was found for " + modId);
        Artifact artifact = matches.getFirst();
        if (artifact.score() >= com.antirat.config.AntiRatConfig.DEFAULT_QUARANTINE_THRESHOLD && !confirmed) {
            return RestoreResult.confirmationRequired("High-confidence quarantine: repeat with 'confirm' to restore "
                    + artifact.modId());
        }

        Path mods = gameDir.resolve("mods").toAbsolutePath().normalize();
        Path original;
        try {
            original = Path.of(artifact.originalPath()).toAbsolutePath().normalize();
        } catch (RuntimeException invalid) {
            return RestoreResult.failed("Stored original path is invalid");
        }
        if (!original.startsWith(mods) || !mods.equals(original.getParent())) {
            return RestoreResult.failed("Stored destination is outside the profile's mods directory");
        }
        if (Files.exists(original)) return RestoreResult.failed("A file already exists at " + original.getFileName());
        try {
            String currentHash = sha256(artifact.disabledPath());
            if (!currentHash.equalsIgnoreCase(artifact.sha256())) {
                return RestoreResult.failed("Quarantined JAR hash no longer matches its recorded SHA-256");
            }
            Files.createDirectories(mods);
            move(artifact.disabledPath(), original);
            if (!Files.isRegularFile(original) || Files.exists(artifact.disabledPath())) {
                throw new IOException("post-restore verification failed");
            }
            Files.deleteIfExists(artifact.sidecarPath());
            StartupReport.removePendingByHash(gameDir, artifact.sha256());
            return RestoreResult.restored(original, "Restored " + artifact.modId()
                    + "; it will load on the next normal launch");
        } catch (IOException | RuntimeException failure) {
            return RestoreResult.failed(failure.getClass().getSimpleName() + ": " + safeMessage(failure.getMessage()));
        }
    }

    private static void move(Path source, Path destination) throws IOException {
        try {
            Files.move(source, destination, StandardCopyOption.ATOMIC_MOVE);
        } catch (AtomicMoveNotSupportedException ignored) {
            Files.move(source, destination);
        }
    }

    private static void writeSidecar(Path quarantined, ScanResult result) throws IOException {
        Properties properties = new Properties();
        properties.setProperty("originalPath", result.source().toString());
        properties.setProperty("sha256", result.sha256());
        properties.setProperty("modId", result.modId());
        properties.setProperty("modName", result.modName());
        properties.setProperty("score", Integer.toString(result.score()));
        properties.setProperty("timestamp", Instant.now().toString());
        Path sidecar = quarantined.resolveSibling(quarantined.getFileName() + ".properties");
        try (OutputStream output = Files.newOutputStream(sidecar)) {
            properties.store(output, "AntiRat quarantine metadata - do not rename to .jar");
        }
    }

    private static Artifact readArtifact(Path root, Path disabled, Path sidecar) {
        try {
            Path normalized = disabled.toAbsolutePath().normalize();
            if (!normalized.startsWith(root) || Files.isSymbolicLink(normalized)
                    || Files.isSymbolicLink(sidecar) || !Files.isRegularFile(sidecar)) {
                return null;
            }
            Properties properties = new Properties();
            try (InputStream input = Files.newInputStream(sidecar)) {
                properties.load(input);
            }
            String sha256 = properties.getProperty("sha256", "").trim().toLowerCase(java.util.Locale.ROOT);
            if (!sha256.matches("[0-9a-f]{64}")) return null;
            return new Artifact(normalized, sidecar.toAbsolutePath().normalize(),
                    properties.getProperty("originalPath", ""), sha256,
                    properties.getProperty("modId", "unknown"),
                    properties.getProperty("modName", properties.getProperty("modId", "unknown")),
                    parseInt(properties.getProperty("score")), parseInstant(properties.getProperty("timestamp")));
        } catch (IOException | RuntimeException ignored) {
            return null;
        }
    }

    private static String sha256(Path path) throws IOException {
        try {
            java.security.MessageDigest digest = java.security.MessageDigest.getInstance("SHA-256");
            try (InputStream input = Files.newInputStream(path)) {
                byte[] buffer = new byte[64 * 1024];
                int read;
                while ((read = input.read(buffer)) >= 0) {
                    if (read > 0) digest.update(buffer, 0, read);
                }
            }
            return java.util.HexFormat.of().formatHex(digest.digest());
        } catch (java.security.NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 is unavailable", impossible);
        }
    }

    private static int parseInt(String value) {
        try {
            return Math.max(0, Math.min(100, Integer.parseInt(value == null ? "" : value.trim())));
        } catch (NumberFormatException ignored) {
            return 0;
        }
    }

    private static Instant parseInstant(String value) {
        try {
            return Instant.parse(value);
        } catch (RuntimeException ignored) {
            return Instant.EPOCH;
        }
    }

    private static Path uniqueDestination(Path directory, String fileName) {
        Path candidate = directory.resolve(fileName);
        int suffix = 1;
        while (Files.exists(candidate)) {
            candidate = directory.resolve(fileName + '.' + suffix++);
        }
        return candidate;
    }

    private static String sanitize(String value) {
        String sanitized = value.replaceAll("[^A-Za-z0-9._-]", "_");
        return sanitized.length() <= 120 ? sanitized : sanitized.substring(sanitized.length() - 120);
    }

    private static String safeMessage(String value) {
        if (value == null || value.isBlank()) return "unspecified I/O failure";
        return value.length() <= 240 ? value : value.substring(0, 240);
    }

    record Artifact(
            Path disabledPath,
            Path sidecarPath,
            String originalPath,
            String sha256,
            String modId,
            String modName,
            int score,
            Instant timestamp
    ) {
    }

    record RestoreResult(Status status, Path restoredPath, String message) {
        enum Status { RESTORED, CONFIRMATION_REQUIRED, FAILED }

        static RestoreResult restored(Path path, String message) {
            return new RestoreResult(Status.RESTORED, path, message);
        }

        static RestoreResult confirmationRequired(String message) {
            return new RestoreResult(Status.CONFIRMATION_REQUIRED, null, message);
        }

        static RestoreResult failed(String message) {
            return new RestoreResult(Status.FAILED, null, message);
        }
    }
}
