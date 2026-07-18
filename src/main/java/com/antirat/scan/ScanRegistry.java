package com.antirat.scan;

import com.antirat.config.AntiRatConfig;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/** Keeps the complete startup verdicts in memory so runtime credential checks reuse the deep scan. */
public final class ScanRegistry {
    private static final long VERIFIED_CACHE_NANOS = java.util.concurrent.TimeUnit.SECONDS.toNanos(5);
    private static final Map<String, Snapshot> BY_MOD_ID = new ConcurrentHashMap<>();

    private ScanRegistry() {
    }

    public static void record(ScanResult result) {
        if (result == null || result.modId() == null) return;
        BY_MOD_ID.put(result.modId(), snapshot(result, 0L));
    }

    static void recordAs(String attributedId, ScanResult result) {
        if (attributedId == null || attributedId.isBlank() || result == null) return;
        BY_MOD_ID.put(attributedId, snapshot(result, 0L));
    }

    public static Verification verifyCurrent(String modId, Path origin, AntiRatConfig config) {
        if (modId == null || origin == null || !Files.isRegularFile(origin)) {
            return Verification.failed("No inspectable source JAR was available for the calling mod");
        }
        Path normalized = origin.toAbsolutePath().normalize();
        Snapshot existing = BY_MOD_ID.get(modId);
        try {
            BasicFileAttributes attributes = Files.readAttributes(normalized, BasicFileAttributes.class);
            long now = System.nanoTime();
            if (existing != null && existing.path().equals(normalized)
                    && existing.size() == attributes.size()
                    && existing.lastModifiedMillis() == attributes.lastModifiedTime().toMillis()
                    && existing.verifiedAtNanos() != 0L
                    && now - existing.verifiedAtNanos() <= VERIFIED_CACHE_NANOS) {
                return Verification.verified(existing.result(), false, true);
            }
            // A full content hash remains the identity boundary. Cache only a recent successful
            // comparison so a mod polling the accessor every frame cannot hash a multi-megabyte
            // JAR hundreds of times per second. Loaded bytecode cannot change merely by rewriting
            // its source JAR, and newly defined helpers are covered by the runtime transformer.
            if (existing != null && existing.path().equals(normalized)
                    && existing.result().sha256().equals(JarScanner.sha256(normalized))) {
                BY_MOD_ID.put(modId, snapshot(existing.result(), now));
                return Verification.verified(existing.result(), false, false);
            }
            ScanResult rescanned = new JarScanner(config).scan(normalized);
            Snapshot refreshed = snapshot(rescanned, now);
            BY_MOD_ID.put(modId, refreshed);
            return Verification.verified(rescanned, true, false);
        } catch (IOException | RuntimeException exception) {
            return Verification.failed("Runtime verification failed: " + exception.getClass().getSimpleName());
        }
    }

    public static ScanResult startupResult(String modId) {
        Snapshot snapshot = modId == null ? null : BY_MOD_ID.get(modId);
        return snapshot == null ? null : snapshot.result();
    }

    private static Snapshot snapshot(ScanResult result, long verifiedAtNanos) {
        Path path = result.source().toAbsolutePath().normalize();
        try {
            BasicFileAttributes attributes = Files.readAttributes(path, BasicFileAttributes.class);
            return new Snapshot(result, path, attributes.size(), attributes.lastModifiedTime().toMillis(),
                    verifiedAtNanos);
        } catch (IOException failure) {
            return new Snapshot(result, path, -1L, -1L, verifiedAtNanos);
        }
    }

    private record Snapshot(ScanResult result, Path path, long size, long lastModifiedMillis, long verifiedAtNanos) {
    }

    public record Verification(boolean verified, boolean rescanned, boolean cached, ScanResult result, String failure) {
        private static Verification verified(ScanResult result, boolean rescanned, boolean cached) {
            return new Verification(true, rescanned, cached, result, "");
        }

        private static Verification failed(String failure) {
            return new Verification(false, false, false, null, failure);
        }

        public static Verification failedForCaller(String failure) {
            return failed(failure);
        }
    }
}
