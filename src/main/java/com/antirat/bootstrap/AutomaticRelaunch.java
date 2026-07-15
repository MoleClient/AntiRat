package com.antirat.bootstrap;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

final class AutomaticRelaunch {
    private static final String DEPTH_ENV = "ANTIRAT_RELAUNCH_DEPTH";
    private static final String NONCE_ENV = "ANTIRAT_RELAUNCH_NONCE";
    static final String PLAN_ENV = "ANTIRAT_RELAUNCH_PLAN";

    private AutomaticRelaunch() {
    }

    static boolean startCleanChild(Path gameDir) {
        return startCleanChild(gameDir, null);
    }

    static boolean startCleanChild(Path gameDir, Path agentJar) {
        int depth = parseDepth(System.getenv(DEPTH_ENV));
        if (depth >= 2) return false;

        ProcessHandle.Info info = ProcessHandle.current().info();
        String command = info.command().orElseGet(AutomaticRelaunch::javaExecutable);
        String[] arguments = info.arguments().orElse(null);
        if (arguments == null || arguments.length == 0) return false;

        List<String> childCommand = new ArrayList<>(arguments.length + 1);
        childCommand.add(command);
        if (agentJar != null && Files.isRegularFile(agentJar) && !containsAgentArgument(arguments)) {
            childCommand.add("-javaagent:" + agentJar.toAbsolutePath().normalize());
        }
        childCommand.addAll(Arrays.asList(arguments));
        if (agentJar == null || !Files.isRegularFile(agentJar)) return false;

        // Launch a tiny JDK-only helper, not the replacement game directly. Modrinth/Theseus can
        // reject a second overlapping game JVM while the original process is still alive. The
        // helper waits for this JVM to exit and only then replays the exact opaque launch command.
        List<String> helperCommand = List.of(
                javaExecutable(), "-cp", agentJar.toAbsolutePath().normalize().toString(),
                RelaunchHelper.class.getName(), Long.toString(ProcessHandle.current().pid())
        );
        ProcessBuilder builder = new ProcessBuilder(helperCommand);
        String nonce = UUID.randomUUID().toString().replace("-", "");
        Path readyFile = readyFile(gameDir, nonce);
        builder.directory(new File(System.getProperty("user.dir", gameDir.toString())));
        builder.environment().put(DEPTH_ENV, Integer.toString(depth + 1));
        builder.environment().put(NONCE_ENV, nonce);
        builder.environment().put("ANTIRAT_PENDING_NOTICE", "1");
        builder.environment().put(PLAN_ENV, encodeCommand(childCommand));
        builder.inheritIO();
        try {
            Files.createDirectories(readyFile.getParent());
            Files.deleteIfExists(readyFile);
            Process helper = builder.start();
            return helper.isAlive();
        } catch (IOException | SecurityException exception) {
            System.err.println("[AntiRat] Could not schedule delayed clean relaunch: "
                    + exception.getClass().getSimpleName() + ": " + exception.getMessage());
            return false;
        }
    }

    static void signalReadyIfRelaunched(Path gameDir) {
        String nonce = System.getenv(NONCE_ENV);
        if (nonce == null || !nonce.matches("[0-9a-f]{32}")) return;
        Path ready = readyFile(gameDir, nonce);
        try {
            Files.createDirectories(ready.getParent());
            Files.writeString(ready, "ready\n");
        } catch (IOException ignored) {
        }
    }

    static void terminateForChild() {
        Runtime.getRuntime().halt(0);
    }

    static List<String> currentCommandForTest(String command, String[] arguments) {
        List<String> result = new ArrayList<>();
        result.add(command);
        result.addAll(Arrays.asList(arguments));
        return List.copyOf(result);
    }

    static List<String> protectedCommandForTest(String command, String[] arguments, Path agentJar) {
        List<String> result = new ArrayList<>();
        result.add(command);
        if (agentJar != null && !containsAgentArgument(arguments)) {
            result.add("-javaagent:" + agentJar.toAbsolutePath().normalize());
        }
        result.addAll(Arrays.asList(arguments));
        return List.copyOf(result);
    }

    static String encodeCommandForTest(List<String> command) {
        return encodeCommand(command);
    }

    static List<String> decodeCommandForTest(String encoded) throws IOException {
        return decodeCommand(encoded);
    }

    private static String encodeCommand(List<String> command) {
        try {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            try (DataOutputStream output = new DataOutputStream(bytes)) {
                output.writeInt(command.size());
                for (String element : command) output.writeUTF(element == null ? "" : element);
            }
            return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes.toByteArray());
        } catch (IOException impossible) {
            throw new IllegalStateException("Could not encode relaunch command", impossible);
        }
    }

    static List<String> decodeCommand(String encoded) throws IOException {
        if (encoded == null || encoded.isBlank()) throw new IOException("missing relaunch plan");
        byte[] bytes;
        try {
            bytes = Base64.getUrlDecoder().decode(encoded);
        } catch (IllegalArgumentException invalid) {
            throw new IOException("invalid relaunch plan encoding", invalid);
        }
        try (DataInputStream input = new DataInputStream(new ByteArrayInputStream(bytes))) {
            int count = input.readInt();
            if (count < 2 || count > 16_384) throw new IOException("invalid relaunch argument count");
            List<String> command = new ArrayList<>(count);
            for (int index = 0; index < count; index++) command.add(input.readUTF());
            if (input.available() != 0) throw new IOException("trailing relaunch plan data");
            return List.copyOf(command);
        }
    }

    private static boolean containsAgentArgument(String[] arguments) {
        for (String argument : arguments) {
            if (argument != null && argument.startsWith("-javaagent:") && argument.contains("antirat")) return true;
        }
        return false;
    }

    private static int parseDepth(String value) {
        try {
            return Math.max(0, Integer.parseInt(value == null ? "0" : value));
        } catch (NumberFormatException ignored) {
            return 0;
        }
    }

    private static String javaExecutable() {
        String executable = System.getProperty("os.name", "").toLowerCase().contains("win") ? "java.exe" : "java";
        return Path.of(System.getProperty("java.home"), "bin", executable).toString();
    }

    private static Path readyFile(Path gameDir, String nonce) {
        return gameDir.resolve(".antirat").resolve("relaunch").resolve(nonce + ".ready");
    }
}
