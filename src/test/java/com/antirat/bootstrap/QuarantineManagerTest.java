package com.antirat.bootstrap;

import com.antirat.config.AntiRatConfig;
import com.antirat.scan.JarScanner;
import com.antirat.scan.ScanResult;
import com.antirat.scan.ScanStatus;
import com.antirat.scan.StartupReport;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class QuarantineManagerTest {
    @TempDir
    Path gameDirectory;

    @Test
    void atomicallyRemovesThreatFromModsAndCreatesDisabledArtifact() throws Exception {
        Path mods = Files.createDirectories(gameDirectory.resolve("mods"));
        Path jar = mods.resolve("bad.jar");
        try (JarOutputStream output = new JarOutputStream(Files.newOutputStream(jar))) {
            write(output, "fabric.mod.json", "{\"id\":\"bad\",\"name\":\"Bad\"}");
            write(output, "payload.txt", "https://discord.com/api/webhooks/1/secret java/net/URL");
        }
        ScanResult result = new JarScanner(AntiRatConfig.defaults()).scan(jar);

        StartupReport.Entry entry = QuarantineManager.quarantine(gameDirectory, result);

        assertEquals(ScanStatus.QUARANTINED, entry.status());
        assertFalse(Files.exists(jar));
        Path disabled = Path.of(entry.quarantinePath());
        assertTrue(Files.isRegularFile(disabled));
        assertTrue(disabled.getFileName().toString().endsWith(".disabled"));
        assertTrue(Files.isRegularFile(disabled.resolveSibling(disabled.getFileName() + ".properties")));
    }

    @Test
    void lockedWindowsStyleJarGetsVerifiedCopyAndDeferredRemoval() throws Exception {
        Path mods = Files.createDirectories(gameDirectory.resolve("mods"));
        Path jar = mods.resolve("locked-bad.jar");
        try (JarOutputStream output = new JarOutputStream(Files.newOutputStream(jar))) {
            write(output, "fabric.mod.json", "{\"id\":\"lockedbad\",\"name\":\"Locked Bad\"}");
            write(output, "payload.txt", "https://discord.com/api/webhooks/1/secret java/net/URL");
        }
        ScanResult result = new JarScanner(AntiRatConfig.defaults()).scan(jar);

        StartupReport.Entry entry = QuarantineManager.quarantineDeferredForTest(gameDirectory, result);

        assertEquals(ScanStatus.QUARANTINE_PENDING, entry.status());
        assertTrue(Files.isRegularFile(jar));
        assertTrue(Files.isRegularFile(Path.of(entry.quarantinePath())));
        assertTrue(entry.message().contains("scheduled for removal"));
    }

    @Test
    void restoresAnUnmodifiedLowScoreArtifactWithoutOverwritingMods() throws Exception {
        Path mods = Files.createDirectories(gameDirectory.resolve("mods"));
        Path jar = mods.resolve("ordinary.jar");
        try (JarOutputStream output = new JarOutputStream(Files.newOutputStream(jar))) {
            write(output, "fabric.mod.json", "{\"schemaVersion\":1,\"id\":\"ordinary\",\"name\":\"Ordinary\",\"version\":\"1\"}");
            write(output, "ordinary.txt", "ordinary rendering helper");
        }
        ScanResult result = new JarScanner(AntiRatConfig.defaults()).scan(jar);
        StartupReport.Entry entry = QuarantineManager.quarantine(gameDirectory, result);

        QuarantineManager.RestoreResult restored = QuarantineManager.restore(gameDirectory, "ordinary", false);

        assertEquals(QuarantineManager.RestoreResult.Status.RESTORED, restored.status());
        assertTrue(Files.isRegularFile(jar));
        assertFalse(Files.exists(Path.of(entry.quarantinePath())));
        assertTrue(QuarantineManager.list(gameDirectory).isEmpty());
    }

    @Test
    void refusesToRestoreWhenTheDestinationAlreadyExists() throws Exception {
        Path mods = Files.createDirectories(gameDirectory.resolve("mods"));
        Path jar = mods.resolve("ordinary.jar");
        try (JarOutputStream output = new JarOutputStream(Files.newOutputStream(jar))) {
            write(output, "fabric.mod.json", "{\"schemaVersion\":1,\"id\":\"ordinary\",\"name\":\"Ordinary\",\"version\":\"1\"}");
        }
        ScanResult result = new JarScanner(AntiRatConfig.defaults()).scan(jar);
        QuarantineManager.quarantine(gameDirectory, result);
        Files.writeString(jar, "do not overwrite");

        QuarantineManager.RestoreResult restored = QuarantineManager.restore(gameDirectory, "ordinary", false);

        assertEquals(QuarantineManager.RestoreResult.Status.FAILED, restored.status());
        assertEquals("do not overwrite", Files.readString(jar));
        assertEquals(1, QuarantineManager.list(gameDirectory).size());
    }

    @Test
    void highConfidenceArtifactRequiresExplicitConfirmation() throws Exception {
        Path mods = Files.createDirectories(gameDirectory.resolve("mods"));
        Path jar = mods.resolve("stealer.jar");
        try (JarOutputStream output = new JarOutputStream(Files.newOutputStream(jar))) {
            write(output, "fabric.mod.json", "{\"schemaVersion\":1,\"id\":\"stealer\",\"name\":\"Stealer\",\"version\":\"1\"}");
            write(output, "payload.txt", "net/minecraft/client/session/Session getAccessToken "
                    + "java/net/URL https://discord.com/api/webhooks/123/secret");
        }
        ScanResult result = new JarScanner(AntiRatConfig.defaults()).scan(jar);
        assertTrue(result.score() >= AntiRatConfig.DEFAULT_QUARANTINE_THRESHOLD);
        QuarantineManager.quarantine(gameDirectory, result);

        QuarantineManager.RestoreResult first = QuarantineManager.restore(gameDirectory, "stealer", false);
        QuarantineManager.RestoreResult confirmed = QuarantineManager.restore(gameDirectory, "stealer", true);

        assertEquals(QuarantineManager.RestoreResult.Status.CONFIRMATION_REQUIRED, first.status());
        assertEquals(QuarantineManager.RestoreResult.Status.RESTORED, confirmed.status());
        assertTrue(Files.isRegularFile(jar));
    }

    private static void write(JarOutputStream output, String name, String value) throws Exception {
        output.putNextEntry(new JarEntry(name));
        output.write(value.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        output.closeEntry();
    }
}
