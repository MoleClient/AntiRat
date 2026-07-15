package com.antirat.bootstrap;

import com.antirat.agent.AntiRatAgent;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.ProtectionDomain;
import java.util.concurrent.TimeUnit;

final class AgentBootstrap {
    private static final long ATTACH_TIMEOUT_SECONDS = 12L;

    private AgentBootstrap() {
    }

    static boolean active() {
        return Boolean.getBoolean(AntiRatAgent.ACTIVE_PROPERTY);
    }

    /**
     * Invokes the installed agent's system-class-loader copy while supplying the exact Fabric
     * runtime origin. Fabric may also have a separate Knot copy of these classes.
     */
    static void activateRuntimeProtection(ProtectionDomain fabricRuntimeOrigin) {
        invokeInstalledAgent("activateRuntimeProtection", new Class<?>[]{ProtectionDomain.class},
                new Object[]{fabricRuntimeOrigin});
    }

    static boolean requiresPremainRelaunch() {
        if (!active()) return false;
        Object result = invokeInstalledAgent("requiresPremainRelaunch", new Class<?>[0], new Object[0]);
        return Boolean.TRUE.equals(result);
    }

    private static Object invokeInstalledAgent(String method, Class<?>[] parameterTypes, Object[] arguments) {
        try {
            Class<?> installedAgent = Class.forName(AntiRatAgent.class.getName(), true,
                    ClassLoader.getSystemClassLoader());
            return installedAgent.getMethod(method, parameterTypes).invoke(null, arguments);
        } catch (ClassNotFoundException | NoSuchMethodException | IllegalAccessException
                 | InvocationTargetException | LinkageError failure) {
            throw new IllegalStateException("AntiRat could not communicate with its installed runtime agent", failure);
        }
    }

    static boolean tryDynamicAttach(Path agentJar) {
        if (active()) return true;
        if (agentJar == null || !Files.isRegularFile(agentJar)) return false;
        String java = ProcessHandle.current().info().command().orElseGet(AgentBootstrap::javaExecutable);
        ProcessBuilder builder = new ProcessBuilder(
                java,
                "--add-modules", "jdk.attach",
                "-cp", agentJar.toAbsolutePath().normalize().toString(),
                "com.antirat.agent.AgentAttacher",
                Long.toString(ProcessHandle.current().pid()),
                agentJar.toAbsolutePath().normalize().toString()
        );
        builder.redirectErrorStream(true);
        builder.redirectOutput(ProcessBuilder.Redirect.DISCARD);
        try {
            Process process = builder.start();
            if (!process.waitFor(ATTACH_TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
                process.destroyForcibly();
                return false;
            }
            if (process.exitValue() != 0) return false;
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(2L);
            while (System.nanoTime() < deadline) {
                if (active()) return true;
                Thread.sleep(20L);
            }
            return active();
        } catch (IOException | InterruptedException | SecurityException exception) {
            if (exception instanceof InterruptedException) Thread.currentThread().interrupt();
            return false;
        }
    }

    private static String javaExecutable() {
        String binary = System.getProperty("os.name", "").toLowerCase(java.util.Locale.ROOT).contains("win")
                ? "java.exe" : "java";
        return Path.of(System.getProperty("java.home"), "bin", binary).toString();
    }
}
