package com.antirat.guard;

import com.antirat.scan.ModIdentity;
import org.junit.jupiter.api.Test;

import java.net.URI;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SensitiveNetworkPolicyTest {
    @Test
    void blocksDiscordWebhookWithoutTrustingCaller() {
        NetworkDecision decision = SensitiveNetworkPolicy.classify(
                URI.create("https://discord.com/api/webhooks/123456/secret-value"), ModIdentity.UNKNOWN);

        assertTrue(decision.block());
    }

    @Test
    void blocksTokenMarkerToUntrustedHostButAllowsOfficialService() {
        NetworkDecision untrusted = SensitiveNetworkPolicy.classify(
                URI.create("https://collector.example/upload?access_token=secret"), ModIdentity.UNKNOWN);
        NetworkDecision official = SensitiveNetworkPolicy.classify(
                URI.create("https://api.minecraftservices.com/auth?access_token=secret"), ModIdentity.UNKNOWN);

        assertTrue(untrusted.block());
        assertFalse(official.block());
    }

    @Test
    void doesNotTreatSuffixSpoofAsDiscordDomain() {
        NetworkDecision decision = SensitiveNetworkPolicy.classify(
                URI.create("https://discord.com.attacker.example/api/webhooks/123/value"), ModIdentity.UNKNOWN);

        assertFalse(decision.block());
    }

    @Test
    void blocksVersionedAndPercentEncodedDiscordWebhookPaths() {
        NetworkDecision versioned = SensitiveNetworkPolicy.classify(
                URI.create("https://canary.discord.com/api/v10/webhooks/123/value"), ModIdentity.UNKNOWN);
        NetworkDecision encoded = SensitiveNetworkPolicy.classify(
                URI.create("https://discord.com/api/%2577%2565%2562%2568%256f%256f%256b%2573/123/value"),
                ModIdentity.UNKNOWN);

        assertTrue(versioned.block());
        assertTrue(encoded.block());
    }

    @Test
    void canonicalizesTrailingDotWithoutAllowingDomainSpoofing() {
        NetworkDecision webhook = SensitiveNetworkPolicy.classify(
                URI.create("https://discord.com./api/webhooks/123/value"), ModIdentity.UNKNOWN);
        NetworkDecision spoof = SensitiveNetworkPolicy.classify(
                URI.create("https://minecraft.net.attacker.example/access_token/value"), ModIdentity.UNKNOWN);

        assertTrue(webhook.block());
        assertTrue(spoof.block());
    }
}
