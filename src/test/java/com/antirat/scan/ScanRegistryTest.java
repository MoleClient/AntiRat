package com.antirat.scan;

import com.antirat.config.AntiRatConfig;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ScanRegistryTest {
    @TempDir
    Path temporaryDirectory;

    @Test
    void contentHashForcesRescanEvenWhenSizeTimestampAndFileKeyArePreserved() throws Exception {
        Path source = temporaryDirectory.resolve("mutable.jar");
        Path replacement = temporaryDirectory.resolve("replacement.jar");
        createJar(source, "benign-a");
        createJar(replacement, "benign-b");
        assertEquals(Files.size(source), Files.size(replacement));

        ScanResult first = new JarScanner(AntiRatConfig.defaults()).scan(source);
        ScanRegistry.record(first);
        FileTime originalTimestamp = Files.getLastModifiedTime(source);

        Files.write(source, Files.readAllBytes(replacement));
        Files.setLastModifiedTime(source, originalTimestamp);
        ScanRegistry.Verification verification = ScanRegistry.verifyCurrent(
                first.modId(), source, AntiRatConfig.defaults());

        assertTrue(verification.verified());
        assertTrue(verification.rescanned());
        assertNotEquals(first.sha256(), verification.result().sha256());
    }

    @Test
    void repeatedCredentialChecksReuseRecentFullHashVerification() throws Exception {
        Path source = temporaryDirectory.resolve("polled.jar");
        createJar(source, "benign-polled-token-api");
        ScanResult first = new JarScanner(AntiRatConfig.defaults()).scan(source);
        ScanRegistry.record(first);

        ScanRegistry.Verification initial = ScanRegistry.verifyCurrent(
                first.modId(), source, AntiRatConfig.defaults());
        assertTrue(initial.verified());
        assertTrue(!initial.cached());

        for (int index = 0; index < 10_000; index++) {
            ScanRegistry.Verification repeated = ScanRegistry.verifyCurrent(
                    first.modId(), source, AntiRatConfig.defaults());
            assertTrue(repeated.verified());
            assertTrue(repeated.cached());
        }
    }

    private static void createJar(Path path, String payload) throws Exception {
        try (JarOutputStream output = new JarOutputStream(Files.newOutputStream(path))) {
            write(output, "fabric.mod.json",
                    "{\"schemaVersion\":1,\"id\":\"mutable_fixture\",\"version\":\"1\"}");
            write(output, "payload.txt", payload);
        }
    }

    private static void write(JarOutputStream output, String name, String value) throws Exception {
        JarEntry entry = new JarEntry(name);
        entry.setTime(0L);
        output.putNextEntry(entry);
        output.write(value.getBytes(StandardCharsets.UTF_8));
        output.closeEntry();
    }
}
