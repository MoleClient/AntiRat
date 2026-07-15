package fixture.runtime;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

/** Standalone subprocess target used to prove premain transformation and transformed execution. */
public final class AgentRuntimeProbe {
    private AgentRuntimeProbe() {
    }

    public static void main(String[] arguments) throws Exception {
        System.setProperty("antirat.runtime.probe", "true");
        System.setProperty("antirat.agent.runtimeReady", "true");
        byte[] content = Files.readAllBytes(Path.of(arguments[0]));
        boolean okay = Boolean.getBoolean("antirat.agent.active")
                && Boolean.getBoolean("antirat.runtime.probe.hit")
                && new String(content, StandardCharsets.UTF_8).equals("agent-runtime-ok");
        if (!okay) throw new AssertionError("agent runtime enforcement probe did not execute");
    }
}
