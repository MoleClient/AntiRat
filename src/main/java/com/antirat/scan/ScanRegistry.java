package com.antirat.scan;

import com.antirat.config.AntiRatConfig;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/** Keeps the complete startup verdicts in memory so runtime credential checks reuse the deep scan. */
public final class ScanRegistry {
    private static final Map<String, Snapshot> BY_MOD_ID = new ConcurrentHashMap<>();

    private ScanRegistry() {
    }

    public static void record(ScanResult result) {
        if (result == null || result.modId() == null) return;
        BY_MOD_ID.put(result.modId(), snapshot(result));
    }

    static void recordAs(String attributedId, ScanResult result) {
        if (attributedId == null || attributedId.isBlank() || result == null) return;
        BY_MOD_ID.put(attributedId, snapshot(result));
    }

    public static Verification verifyCurrent(String modId, Path origin, AntiRatConfig config) {
        if (modId == null || origin == null || !Files.isRegularFile(origin)) {
            return Verification.failed("No inspectable source JAR was available for the calling mod");
        }
        Path normalized = origin.toAbsolutePath().normalize();
        Snapshot existing = BY_MOD_ID.get(modId);
        try {
            // Metadata alone is not a security identity: hostile code can rewrite a file in place,
            // preserve its size, restore its mtime, and retain the same inode/file key. Hash every
            // credential release and reuse the expensive deep verdict only on exact content match.
            if (existing != null && existing.path().equals(normalized)
                    && existing.result().sha256().equals(JarScanner.sha256(normalized))) {
                BY_MOD_ID.put(modId, snapshot(existing.result()));
                return Verification.verified(existing.result(), false);
            }
            ScanResult rescanned = new JarScanner(config).scan(normalized);
            Snapshot refreshed = snapshot(rescanned);
            BY_MOD_ID.put(modId, refreshed);
            return Verification.verified(rescanned, true);
        } catch (IOException | RuntimeException exception) {
            return Verification.failed("Runtime verification failed: " + exception.getClass().getSimpleName());
        }
    }

    public static ScanResult startupResult(String modId) {
        Snapshot snapshot = modId == null ? null : BY_MOD_ID.get(modId);
        return snapshot == null ? null : snapshot.result();
    }

    private static Snapshot snapshot(ScanResult result) {
        Path path = result.source().toAbsolutePath().normalize();
        return new Snapshot(result, path);
    }

    private record Snapshot(ScanResult result, Path path) {
    }

    public record Verification(boolean verified, boolean rescanned, ScanResult result, String failure) {
        private static Verification verified(ScanResult result, boolean rescanned) {
            return new Verification(true, rescanned, result, "");
        }

        private static Verification failed(String failure) {
            return new Verification(false, false, null, failure);
        }

        public static Verification failedForCaller(String failure) {
            return failed(failure);
        }
    }
}
