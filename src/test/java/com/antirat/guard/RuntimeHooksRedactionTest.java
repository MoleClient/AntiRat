package com.antirat.guard;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RuntimeHooksRedactionTest {
    @Test
    void redactsSeparatedAndEqualsStyleLauncherSecrets() {
        String[] original = {"--username", "Player", "--accessToken", "real-session-value",
                "--client_token=real-client-value", "--gameDir", "/safe/game"};

        String[] redacted = RuntimeHooks.redactArguments(original);

        assertArrayEquals(new String[]{"--username", "Player", "--accessToken", "<redacted>",
                "--client_token=<redacted>", "--gameDir", "/safe/game"}, redacted);
        assertArrayEquals(new String[]{"--username", "Player", "--accessToken", "real-session-value",
                "--client_token=real-client-value", "--gameDir", "/safe/game"}, original);
    }

    @Test
    void commandLineRedactionDoesNotAlterOrdinaryArguments() {
        String command = "java Game --accessToken super-secret --width 1280 --client_token=also-secret";
        String redacted = RuntimeHooks.redactCommandLine(command);

        assertFalse(redacted.contains("super-secret"));
        assertFalse(redacted.contains("also-secret"));
        assertTrue(redacted.contains("--width 1280"));
    }
}
