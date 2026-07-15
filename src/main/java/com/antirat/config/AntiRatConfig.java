package com.antirat.config;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Locale;
import java.util.Properties;
import java.util.Set;

public record AntiRatConfig(
        int quarantineThreshold,
        int warningThreshold,
        long maxJarBytes,
        long maxEntryBytes,
        long maxExpandedBytes,
        int maxEntries,
        int maxNestedDepth,
        Set<String> allowedSha256,
        Set<String> credentialAllowedSha256
) {
    public static final int DEFAULT_QUARANTINE_THRESHOLD = 86;
    public static final int DEFAULT_WARNING_THRESHOLD = 35;

    public AntiRatConfig {
        quarantineThreshold = bounded(quarantineThreshold, 70, 100, DEFAULT_QUARANTINE_THRESHOLD);
        warningThreshold = bounded(warningThreshold, 1, quarantineThreshold, DEFAULT_WARNING_THRESHOLD);
        maxJarBytes = bounded(maxJarBytes, 1L << 20, 1L << 30, 256L << 20);
        maxEntryBytes = bounded(maxEntryBytes, 64L << 10, 128L << 20, 12L << 20);
        maxExpandedBytes = bounded(maxExpandedBytes, maxEntryBytes, 2L << 30, 512L << 20);
        maxEntries = bounded(maxEntries, 100, 100_000, 30_000);
        maxNestedDepth = bounded(maxNestedDepth, 0, 4, 2);
        allowedSha256 = normalizedHashes(allowedSha256);
        credentialAllowedSha256 = normalizedHashes(credentialAllowedSha256);
    }

    public static AntiRatConfig defaults() {
        return new AntiRatConfig(DEFAULT_QUARANTINE_THRESHOLD, DEFAULT_WARNING_THRESHOLD,
                256L << 20, 12L << 20, 512L << 20, 30_000, 2, Set.of(), Set.of());
    }

    public static AntiRatConfig load(Path gameDir) {
        AntiRatConfig defaults = defaults();
        Path path = gameDir.resolve("config").resolve("antirat.properties");
        if (!Files.isRegularFile(path)) return defaults;

        Properties properties = new Properties();
        try (InputStream input = Files.newInputStream(path)) {
            properties.load(input);
        } catch (IOException | IllegalArgumentException ignored) {
            return defaults;
        }

        return new AntiRatConfig(
                integer(properties, "quarantine.threshold", defaults.quarantineThreshold),
                integer(properties, "warning.threshold", defaults.warningThreshold),
                longValue(properties, "scan.maxJarBytes", defaults.maxJarBytes),
                longValue(properties, "scan.maxEntryBytes", defaults.maxEntryBytes),
                longValue(properties, "scan.maxExpandedBytes", defaults.maxExpandedBytes),
                integer(properties, "scan.maxEntries", defaults.maxEntries),
                integer(properties, "scan.maxNestedDepth", defaults.maxNestedDepth),
                csv(properties.getProperty("allow.sha256", "")),
                csv(properties.getProperty("allow.credentialSha256", ""))
        );
    }

    public boolean isHashAllowed(String sha256) {
        return sha256 != null && allowedSha256.contains(sha256.toLowerCase(Locale.ROOT));
    }

    public boolean isCredentialHashAllowed(String sha256) {
        return sha256 != null && credentialAllowedSha256.contains(sha256.toLowerCase(Locale.ROOT));
    }

    private static int integer(Properties properties, String key, int fallback) {
        try {
            return Integer.parseInt(properties.getProperty(key, Integer.toString(fallback)).trim());
        } catch (NumberFormatException ignored) {
            return fallback;
        }
    }

    private static long longValue(Properties properties, String key, long fallback) {
        try {
            return Long.parseLong(properties.getProperty(key, Long.toString(fallback)).trim());
        } catch (NumberFormatException ignored) {
            return fallback;
        }
    }

    private static Set<String> csv(String value) {
        if (value == null || value.isBlank()) return Collections.emptySet();
        return new HashSet<>(Arrays.asList(value.split("\\s*,\\s*")));
    }

    private static Set<String> normalizedHashes(Set<String> values) {
        Set<String> normalized = new HashSet<>();
        for (String value : values) {
            String candidate = value.trim().toLowerCase(Locale.ROOT);
            if (candidate.matches("[0-9a-f]{64}")) normalized.add(candidate);
        }
        return Set.copyOf(normalized);
    }

    private static int bounded(int value, int min, int max, int fallback) {
        return value < min || value > max ? fallback : value;
    }

    private static long bounded(long value, long min, long max, long fallback) {
        return value < min || value > max ? fallback : value;
    }
}
