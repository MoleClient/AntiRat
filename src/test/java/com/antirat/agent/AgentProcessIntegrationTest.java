package com.antirat.agent;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AgentProcessIntegrationTest {
    @TempDir
    Path temporaryDirectory;

    @Test
    void premainTransformsAndExecutesARealChildJvm() throws Exception {
        Path agent = Path.of(System.getProperty("antirat.test.agentJar"));
        assertTrue(Files.isRegularFile(agent), "test agent JAR was not built");
        Path input = temporaryDirectory.resolve("ordinary.txt");
        Files.writeString(input, "agent-runtime-ok", StandardCharsets.UTF_8);

        String java = Path.of(System.getProperty("java.home"), "bin",
                System.getProperty("os.name", "").toLowerCase().contains("win") ? "java.exe" : "java").toString();
        List<String> command = new ArrayList<>();
        command.add(java);
        command.add("-javaagent:" + agent.toAbsolutePath().normalize());
        command.add("-Dantirat.agent.runtimeReady=true");
        command.add("-Dantirat.agent.transformAll=true");
        command.add("-cp");
        command.add(System.getProperty("java.class.path"));
        command.add("fixture.runtime.AgentRuntimeProbe");
        command.add(input.toString());

        Process process = new ProcessBuilder(command).redirectErrorStream(true).start();
        boolean finished = process.waitFor(20, TimeUnit.SECONDS);
        if (!finished) process.destroyForcibly();
        String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);

        assertTrue(finished, "agent child JVM timed out");
        assertEquals(0, process.exitValue(), output);
    }
}
