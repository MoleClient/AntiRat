package com.antirat.bootstrap;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.HexFormat;

/** JDK-only helper that removes a Windows-locked mod after the game process releases its JAR. */
public final class DeferredQuarantineHelper {
    private DeferredQuarantineHelper() {
    }

    static boolean schedule(Path source, String expectedSha256) {
        try {
            URI location = DeferredQuarantineHelper.class.getProtectionDomain().getCodeSource().getLocation().toURI();
            if (!"file".equalsIgnoreCase(location.getScheme())) return false;
            Path codeSource = Path.of(location).toAbsolutePath().normalize();
            String executable = System.getProperty("os.name", "").toLowerCase(java.util.Locale.ROOT)
                    .contains("win") ? "java.exe" : "java";
            Path java = Path.of(System.getProperty("java.home"), "bin", executable);
            new ProcessBuilder(java.toString(), "-cp", codeSource.toString(),
                    DeferredQuarantineHelper.class.getName(),
                    Long.toString(ProcessHandle.current().pid()), source.toAbsolutePath().normalize().toString(),
                    expectedSha256).redirectError(ProcessBuilder.Redirect.DISCARD)
                    .redirectOutput(ProcessBuilder.Redirect.DISCARD).start();
            return true;
        } catch (Exception failure) {
            return false;
        }
    }

    public static void main(String[] arguments) {
        if (arguments.length != 3) return;
        try {
            long parentPid = Long.parseLong(arguments[0]);
            Path source = Path.of(arguments[1]).toAbsolutePath().normalize();
            String expected = arguments[2].toLowerCase(java.util.Locale.ROOT);
            if (!expected.matches("[0-9a-f]{64}")) return;
            ProcessHandle parent = ProcessHandle.of(parentPid).orElse(null);
            while (parent != null && parent.isAlive()) Thread.sleep(50L);
            for (int attempt = 0; attempt < 600; attempt++) {
                if (!Files.exists(source)) return;
                if (!Files.isRegularFile(source) || !sha256(source).equals(expected)) return;
                try {
                    Files.delete(source);
                    return;
                } catch (IOException locked) {
                    Thread.sleep(50L);
                }
            }
        } catch (Exception ignored) {
            // The verified quarantine copy remains available even if the OS never releases source.
        }
    }

    private static String sha256(Path path) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        try (InputStream input = Files.newInputStream(path)) {
            byte[] buffer = new byte[64 * 1024];
            int read;
            while ((read = input.read(buffer)) >= 0) if (read > 0) digest.update(buffer, 0, read);
        }
        return HexFormat.of().formatHex(digest.digest());
    }
}
