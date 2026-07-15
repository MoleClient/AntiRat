package com.antirat.bootstrap;

import org.junit.jupiter.api.Test;

import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class AutomaticRelaunchTest {
    @Test
    void preservesJvmAndGameArgumentsAsOpaqueElements() {
        String[] arguments = {"-Xmx2G", "-cp", "/tmp/a path/game.jar", "example.Main", "--accessToken", "opaque-value"};

        List<String> command = AutomaticRelaunch.currentCommandForTest("/java", arguments);

        assertEquals("/java", command.getFirst());
        assertEquals(List.of(arguments), command.subList(1, command.size()));
    }

    @Test
    void prependsBundledAgentWithoutChangingLauncherArguments() {
        String[] arguments = {"-Xmx2G", "example.Main", "--gameDir", "/tmp/game"};
        Path agent = Path.of("/tmp/antirat runtime.jar");

        List<String> command = AutomaticRelaunch.protectedCommandForTest("/java", arguments, agent);

        assertEquals("/java", command.get(0));
        assertEquals("-javaagent:" + agent.toAbsolutePath().normalize(), command.get(1));
        assertEquals(List.of(arguments), command.subList(2, command.size()));
    }

    @Test
    void relaunchPlanRoundTripsOpaqueModrinthArguments() throws Exception {
        List<String> command = List.of(
                "/Applications/Java Runtime/bin/java",
                "-Dfabric.gameVersion=1.21.11",
                "-cp", "/tmp/Profile With Spaces/libraries/*",
                "com.modrinth.theseus.MinecraftLaunch",
                "--username", "Player Name",
                "--accessToken", "opaque-do-not-interpret"
        );

        String encoded = AutomaticRelaunch.encodeCommandForTest(command);

        assertEquals(command, AutomaticRelaunch.decodeCommandForTest(encoded));
    }
}
