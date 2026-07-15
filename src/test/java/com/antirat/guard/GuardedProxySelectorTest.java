package com.antirat.guard;

import org.junit.jupiter.api.Test;

import java.net.URI;

import static org.junit.jupiter.api.Assertions.assertEquals;

class GuardedProxySelectorTest {
    @Test
    void redactsWebhookPathAndQueryFromEventTarget() {
        String value = GuardedProxySelector.sanitizeTarget(
                URI.create("https://discord.com/api/webhooks/123/super-secret?token=also-secret"));

        assertEquals("https://discord.com/<redacted-path>?<redacted>", value);
    }
}
