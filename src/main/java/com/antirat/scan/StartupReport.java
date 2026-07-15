package com.antirat.scan;

import com.antirat.model.RiskLevel;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

public final class StartupReport {
    private static final String FORMAT_VERSION = "2";
    private static final String DIRECTORY = ".antirat";
    private static final String PENDING_FILE = "pending.properties";
    private static final String LATEST_FILE = "latest.properties";

    private StartupReport() {
    }

    public static Path pendingPath(Path gameDir) {
        return gameDir.resolve(DIRECTORY).resolve(PENDING_FILE);
    }

    public static Path latestPath(Path gameDir) {
        return gameDir.resolve(DIRECTORY).resolve(LATEST_FILE);
    }

    public static void writeLatest(Path gameDir, List<Entry> entries, String phase) throws IOException {
        writeAtomic(latestPath(gameDir), entries, phase);
    }

    public static void mergePending(Path gameDir, List<Entry> additions, String phase) throws IOException {
        Path path = pendingPath(gameDir);
        List<Entry> combined = new ArrayList<>();
        if (Files.isRegularFile(path)) combined.addAll(read(path).entries());

        Map<String, Entry> deduplicated = new LinkedHashMap<>();
        for (Entry entry : combined) deduplicated.put(entry.deduplicationKey(), entry);
        for (Entry entry : additions) deduplicated.put(entry.deduplicationKey(), entry);
        writeAtomic(path, new ArrayList<>(deduplicated.values()), phase);
    }

    public static Report readPending(Path gameDir) throws IOException {
        return read(pendingPath(gameDir));
    }

    public static Report readLatest(Path gameDir) throws IOException {
        return read(latestPath(gameDir));
    }

    public static Report read(Path path) throws IOException {
        if (!Files.isRegularFile(path)) return new Report("", Instant.EPOCH, List.of());
        Properties properties = new Properties();
        try (InputStream input = Files.newInputStream(path)) {
            properties.load(input);
        }
        if (!FORMAT_VERSION.equals(properties.getProperty("format"))) {
            throw new IOException("unsupported AntiRat report format");
        }

        int count = parseInt(properties.getProperty("entry.count"), 0);
        if (count < 0 || count > 10_000) throw new IOException("invalid AntiRat report entry count");
        List<Entry> entries = new ArrayList<>(count);
        for (int index = 0; index < count; index++) {
            String prefix = "entry." + index + ".";
            ScanStatus status = enumValue(ScanStatus.class, properties.getProperty(prefix + "status"), ScanStatus.WARNED);
            RiskLevel risk = enumValue(RiskLevel.class, properties.getProperty(prefix + "risk"), RiskLevel.INFO);
            Set<Capability> capabilities = parseCapabilities(properties.getProperty(prefix + "capabilities", ""));
            int evidenceCount = Math.min(100, Math.max(0, parseInt(properties.getProperty(prefix + "evidence.count"), 0)));
            List<String> evidence = new ArrayList<>(evidenceCount);
            for (int evidenceIndex = 0; evidenceIndex < evidenceCount; evidenceIndex++) {
                evidence.add(properties.getProperty(prefix + "evidence." + evidenceIndex, ""));
            }
            entries.add(new Entry(
                    status,
                    properties.getProperty(prefix + "originalPath", ""),
                    properties.getProperty(prefix + "quarantinePath", ""),
                    properties.getProperty(prefix + "sha256", ""),
                    properties.getProperty(prefix + "modId", "unknown"),
                    properties.getProperty(prefix + "modName", "unknown mod"),
                    parseInt(properties.getProperty(prefix + "score"), 0),
                    risk,
                    capabilities,
                    evidence,
                    parseInstant(properties.getProperty(prefix + "timestamp")),
                    properties.getProperty(prefix + "message", "")
            ));
        }
        return new Report(properties.getProperty("phase", ""), parseInstant(properties.getProperty("createdAt")), entries);
    }

    public static void markPendingDelivered(Path gameDir) throws IOException {
        Path pending = pendingPath(gameDir);
        if (!Files.isRegularFile(pending)) return;
        Path history = gameDir.resolve(DIRECTORY).resolve("history");
        Files.createDirectories(history);
        String timestamp = DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss-SSS")
                .withZone(java.time.ZoneOffset.UTC).format(Instant.now());
        Path destination = history.resolve("delivered-" + timestamp + ".properties");
        moveAtomicOrReplace(pending, destination);
    }

    public static void removePendingByHash(Path gameDir, String sha256) throws IOException {
        Path pending = pendingPath(gameDir);
        if (!Files.isRegularFile(pending) || sha256 == null || sha256.isBlank()) return;
        Report report = read(pending);
        List<Entry> retained = report.entries().stream()
                .filter(entry -> !entry.sha256().equalsIgnoreCase(sha256)).toList();
        if (retained.isEmpty()) Files.deleteIfExists(pending);
        else writeAtomic(pending, retained, "quarantine-restored");
    }

    private static void writeAtomic(Path path, List<Entry> entries, String phase) throws IOException {
        Files.createDirectories(path.getParent());
        Properties properties = new Properties();
        properties.setProperty("format", FORMAT_VERSION);
        properties.setProperty("createdAt", Instant.now().toString());
        properties.setProperty("phase", phase == null ? "" : phase);
        properties.setProperty("entry.count", Integer.toString(entries.size()));
        for (int index = 0; index < entries.size(); index++) {
            Entry entry = entries.get(index);
            String prefix = "entry." + index + ".";
            properties.setProperty(prefix + "status", entry.status().name());
            properties.setProperty(prefix + "originalPath", entry.originalPath());
            properties.setProperty(prefix + "quarantinePath", entry.quarantinePath());
            properties.setProperty(prefix + "sha256", entry.sha256());
            properties.setProperty(prefix + "modId", entry.modId());
            properties.setProperty(prefix + "modName", entry.modName());
            properties.setProperty(prefix + "score", Integer.toString(entry.score()));
            properties.setProperty(prefix + "risk", entry.riskLevel().name());
            properties.setProperty(prefix + "capabilities", joinCapabilities(entry.deniedCapabilities()));
            properties.setProperty(prefix + "timestamp", entry.timestamp().toString());
            properties.setProperty(prefix + "message", entry.message());
            properties.setProperty(prefix + "evidence.count", Integer.toString(entry.evidence().size()));
            for (int evidenceIndex = 0; evidenceIndex < entry.evidence().size(); evidenceIndex++) {
                properties.setProperty(prefix + "evidence." + evidenceIndex, entry.evidence().get(evidenceIndex));
            }
        }

        Path temporary = Files.createTempFile(path.getParent(), path.getFileName().toString(), ".tmp");
        boolean moved = false;
        try {
            try (OutputStream output = Files.newOutputStream(temporary)) {
                properties.store(output, "AntiRat startup report - contains no captured credentials");
            }
            moveAtomicOrReplace(temporary, path);
            moved = true;
        } finally {
            if (!moved) Files.deleteIfExists(temporary);
        }
    }

    private static void moveAtomicOrReplace(Path source, Path destination) throws IOException {
        try {
            Files.move(source, destination, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        } catch (AtomicMoveNotSupportedException ignored) {
            Files.move(source, destination, StandardCopyOption.REPLACE_EXISTING);
        }
    }

    private static String joinCapabilities(Set<Capability> capabilities) {
        return capabilities.stream().map(Enum::name).sorted().collect(java.util.stream.Collectors.joining(","));
    }

    private static Set<Capability> parseCapabilities(String value) {
        EnumSet<Capability> result = EnumSet.noneOf(Capability.class);
        for (String part : value.split(",")) {
            if (part.isBlank()) continue;
            try {
                result.add(Capability.valueOf(part.trim()));
            } catch (IllegalArgumentException ignored) {
            }
        }
        return Set.copyOf(result);
    }

    private static int parseInt(String value, int fallback) {
        try {
            return Integer.parseInt(value == null ? "" : value.trim());
        } catch (NumberFormatException ignored) {
            return fallback;
        }
    }

    private static Instant parseInstant(String value) {
        try {
            return Instant.parse(value);
        } catch (RuntimeException ignored) {
            return Instant.EPOCH;
        }
    }

    private static <E extends Enum<E>> E enumValue(Class<E> type, String value, E fallback) {
        try {
            return Enum.valueOf(type, value == null ? "" : value);
        } catch (IllegalArgumentException ignored) {
            return fallback;
        }
    }

    public record Report(String phase, Instant createdAt, List<Entry> entries) {
        public Report {
            entries = List.copyOf(entries);
        }
    }

    public record Entry(
            ScanStatus status,
            String originalPath,
            String quarantinePath,
            String sha256,
            String modId,
            String modName,
            int score,
            RiskLevel riskLevel,
            Set<Capability> deniedCapabilities,
            List<String> evidence,
            Instant timestamp,
            String message
    ) {
        public Entry {
            originalPath = safe(originalPath);
            quarantinePath = safe(quarantinePath);
            sha256 = safe(sha256);
            modId = safeDefault(modId, "unknown");
            modName = safeDefault(modName, modId);
            deniedCapabilities = Set.copyOf(deniedCapabilities);
            evidence = List.copyOf(evidence);
            timestamp = timestamp == null ? Instant.now() : timestamp;
            message = safe(message);
            score = Math.max(0, Math.min(100, score));
        }

        public static Entry fromScan(ScanResult result, ScanStatus status, Path quarantinePath, String message) {
            return new Entry(status, result.source().toString(), quarantinePath == null ? "" : quarantinePath.toString(),
                    result.sha256(), result.modId(), result.modName(), result.score(), result.riskLevel(),
                    result.deniedCapabilities(), result.evidence(), Instant.now(), message);
        }

        String deduplicationKey() {
            return originalPath + '|' + sha256;
        }

        private static String safe(String value) {
            return value == null ? "" : value;
        }

        private static String safeDefault(String value, String fallback) {
            return value == null || value.isBlank() ? fallback : value;
        }
    }
}
