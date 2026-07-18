package com.antirat.guard;

import com.antirat.AntiRatRuntime;
import com.antirat.model.RiskLevel;
import com.antirat.scan.Capability;
import com.antirat.scan.ModIdentity;
import com.antirat.scan.ScanRegistry;
import com.antirat.scan.ScanResult;

import java.net.IDN;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

final class SensitiveNetworkPolicy {
    private static final StackWalker STACK_WALKER = StackWalker.getInstance();
    private static final Pattern RAW_IPV4 = Pattern.compile("^(?:\\d{1,3}\\.){3}\\d{1,3}$");
    private static final Pattern INTEGER_IPV4 = Pattern.compile("^(?:0x[0-9a-f]{1,8}|[0-9]{8,10})$");
    private static final Pattern DISCORD_WEBHOOK_PATH = Pattern.compile(".*/api(?:/v[0-9]{1,2})?/webhooks/.*");
    private static final Set<String> TRUSTED_SUFFIXES = Set.of(
            "minecraft.net",
            "mojang.com",
            "mojangservices.com",
            "minecraftservices.com",
            "xboxlive.com",
            "live.com",
            "microsoft.com",
            "fabricmc.net",
            "modrinth.com",
            "curseforge.com"
    );

    private SensitiveNetworkPolicy() {
    }

    static NetworkDecision classify(URI uri, ModIdentity source) {
        String scheme = safeLower(uri.getScheme());
        boolean networkScheme = scheme.equals("http") || scheme.equals("https") || scheme.equals("ws")
                || scheme.equals("wss") || scheme.equals("ftp");
        if (!networkScheme) {
            return NetworkDecision.allow();
        }

        String host = normalizedHost(uri.getHost());
        String path = canonicalComponent(uri.getRawPath());
        String query = canonicalComponent(uri.getRawQuery());
        String userInfo = canonicalComponent(uri.getRawUserInfo());
        String fullTarget = canonicalComponent(uri.toASCIIString());
        List<String> evidence = new ArrayList<>();

        // Explicit hash trust covers ordinary runtime capabilities, but never overrides fixed
        // exfiltration endpoints below; a reviewed mod should not need a Discord/Telegram stealer route.
        boolean runtimeOverride = AntiRatRuntime.runtimeHashAllowed(source.id());

        RiskLevel sourceRisk = AntiRatRuntime.riskForMod(source.id());
        boolean networkDenied = AntiRatRuntime.capabilityDenied(source.id(), Capability.UNTRUSTED_NETWORK);
        ScanResult startupScan = ScanRegistry.startupResult(source.id());
        if (startupScan != null) {
            if (startupScan.riskLevel().atLeast(sourceRisk)) sourceRisk = startupScan.riskLevel();
            networkDenied |= startupScan.quarantineRecommended()
                    || startupScan.deniedCapabilities().contains(Capability.UNTRUSTED_NETWORK);
        }
        if (host.isBlank()) {
            if (networkDenied || sourceRisk.atLeast(RiskLevel.HIGH)) {
                evidence.add("Network destination has no verifiable hostname");
                return block(RiskLevel.HIGH, 88, "Blocked ambiguous network destination",
                        "A risky mod attempted a request whose host could not be validated.",
                        "Remove the source mod unless this destination is documented and independently verified.", evidence);
            }
            return NetworkDecision.allow();
        }

        if (isDiscordWebhook(host, path)) {
            evidence.add("Discord webhook endpoint");
            evidence.add("Webhooks are commonly used by token stealers because they need no account login.");
            return block(RiskLevel.CRITICAL, 98, "Blocked Discord webhook request",
                    "A mod attempted to send data to a Discord webhook endpoint.",
                    "Remove the source mod if you did not expect it to post Discord webhook data.",
                    evidence);
        }

        if (isTelegramBotSend(host, path)) {
            evidence.add("Telegram bot send endpoint");
            return block(RiskLevel.CRITICAL, 96, "Blocked Telegram bot exfiltration route",
                    "A mod attempted to use a Telegram bot send endpoint.",
                    "Telegram bot APIs are rarely needed by client mods; verify the jar before running it again.",
                    evidence);
        }

        if (isSlackWebhook(host, path)) {
            evidence.add("Slack webhook endpoint");
            return block(RiskLevel.HIGH, 94, "Blocked Slack webhook request",
                    "A mod attempted to send data to a Slack webhook.",
                    "Check the mod source or remove the jar unless this behavior is documented.",
                    evidence);
        }

        if (isWebhookCollector(host)) {
            evidence.add("Temporary webhook or request collection host");
            return block(RiskLevel.HIGH, 90, "Blocked webhook collector request",
                    "A mod attempted to send data to a request collection service.",
                    "Request collection hosts are a strong malware indicator in distributed client mods.",
                    evidence);
        }

        if (runtimeOverride) return NetworkDecision.allow();

        boolean sensitivePayload = containsSensitiveTokenMarker(path) || containsSensitiveTokenMarker(query)
                || containsSensitiveTokenMarker(userInfo);
        boolean trustedHost = isTrustedHost(host);
        boolean rawIp = isRawAddress(host);

        if (source.known() && !trustedHost && authenticatedAuthlibTransportOnStack()) {
            evidence.add("Authenticated Mojang/Authlib HTTP client on the live call stack");
            evidence.add("Destination is outside the trusted game/authentication host set");
            return block(RiskLevel.CRITICAL, 97, "Blocked authenticated-client credential relay",
                    "A mod attempted to route Mojang's token-bearing Authlib client to an untrusted host.",
                    "Remove the source mod; authenticated game clients must not be repointed to arbitrary services.",
                    evidence);
        }

        if (networkDenied && !trustedHost) {
            evidence.add("Startup scan denied this mod untrusted-network capability");
            evidence.add("Destination is outside the trusted game/authentication host set");
            return block(RiskLevel.CRITICAL, 94, "Blocked network access from quarantinable code",
                    "A startup-scanned mod attempted outbound access to an untrusted destination.",
                    "Remove the source mod; this restriction is tied to its scan evidence.", evidence);
        }

        if (sensitivePayload && !trustedHost) {
            evidence.add("Sensitive token marker in outbound URL");
            evidence.add("Destination is not a trusted Minecraft/Microsoft/Fabric/mod platform host");
            return block(RiskLevel.HIGH, 89, "Blocked token-bearing request",
                    "A mod attempted to send a URL containing sensitive token/session markers to an untrusted host.",
                    "Rotate your Minecraft session if you saw this after installing a new jar.",
                    evidence);
        }

        if (rawIp && (sensitivePayload || sourceRisk.atLeast(RiskLevel.HIGH))) {
            evidence.add("Raw IP destination");
            if (sourceRisk.atLeast(RiskLevel.HIGH)) {
                evidence.add("Source mod was already marked " + sourceRisk.label() + " by startup scan");
            }
            return block(RiskLevel.HIGH, 84, "Blocked suspicious raw-IP request",
                    "A suspicious mod attempted to contact a raw IP address.",
                    "Legitimate mods usually use named APIs, not raw IPs, for client telemetry.",
                    evidence);
        }

        if (sourceRisk.atLeast(RiskLevel.HIGH) && !trustedHost) {
            evidence.add("Source mod was marked " + sourceRisk.label() + " by startup scan");
            evidence.add("Outbound request to non-trusted host: " + host);
            return block(RiskLevel.HIGH, 86, "Blocked request from high-risk mod",
                    "A mod rated high-risk during startup attempted an outbound request.",
                    "Review or remove the source jar before allowing its network activity.",
                    evidence);
        }

        if (fullTarget.contains("discord") && containsSensitiveTokenMarker(fullTarget)) {
            evidence.add("Discord-related URL with sensitive marker");
            return block(RiskLevel.HIGH, 87, "Blocked Discord token-related request",
                    "A mod attempted a Discord-related request containing sensitive token markers.",
                    "Review the source jar and consider changing affected tokens.",
                    evidence);
        }

        return NetworkDecision.allow();
    }

    /** Avoids a stack walk for the high-volume first-party endpoints the full policy always allows. */
    static boolean fastAllowTrustedHost(URI uri) {
        if (uri == null) return false;
        String scheme = safeLower(uri.getScheme());
        if (!scheme.equals("http") && !scheme.equals("https") && !scheme.equals("ws") && !scheme.equals("wss")) {
            return false;
        }
        return isTrustedHost(normalizedHost(uri.getHost()));
    }

    private static NetworkDecision block(
            RiskLevel riskLevel,
            int accuracy,
            String title,
            String summary,
            String tip,
            List<String> evidence
    ) {
        return new NetworkDecision(true, true, riskLevel, accuracy, title, summary, tip, List.copyOf(evidence));
    }

    private static NetworkDecision flag(
            RiskLevel riskLevel,
            int accuracy,
            String title,
            String summary,
            String tip,
            List<String> evidence
    ) {
        return new NetworkDecision(true, false, riskLevel, accuracy, title, summary, tip, List.copyOf(evidence));
    }

    private static boolean isDiscordWebhook(String host, String path) {
        return (host.equals("discord.com") || host.endsWith(".discord.com")
                || host.equals("discordapp.com") || host.endsWith(".discordapp.com"))
                && DISCORD_WEBHOOK_PATH.matcher(path).matches();
    }

    private static boolean isTelegramBotSend(String host, String path) {
        return host.equals("api.telegram.org")
                && path.startsWith("/bot")
                && (path.contains("/sendmessage") || path.contains("/senddocument") || path.contains("/sendphoto"));
    }

    private static boolean isSlackWebhook(String host, String path) {
        return host.equals("hooks.slack.com") && path.startsWith("/services/");
    }

    private static boolean isWebhookCollector(String host) {
        return host.equals("webhook.site")
                || host.endsWith(".webhook.site")
                || host.equals("requestbin.net")
                || host.endsWith(".requestbin.net")
                || host.equals("pipedream.net")
                || host.endsWith(".m.pipedream.net")
                || host.equals("beeceptor.com")
                || host.endsWith(".free.beeceptor.com")
                || host.equals("requestcatcher.com")
                || host.endsWith(".requestcatcher.com")
                || host.equals("hookdeck.com")
                || host.endsWith(".hookdeck.com");
    }

    private static boolean containsSensitiveTokenMarker(String value) {
        return value.contains("accesstoken")
                || value.contains("access_token")
                || value.contains("clienttoken")
                || value.contains("sessiontoken")
                || value.contains("session_token")
                || value.contains("authorization")
                || value.contains("bearer%20")
                || value.contains("discord_token")
                || value.contains("discordtoken")
                || value.contains("launcher_accounts")
                || value.contains("yggdrasil");
    }

    private static boolean isTrustedHost(String host) {
        for (String suffix : TRUSTED_SUFFIXES) {
            if (host.equals(suffix) || host.endsWith("." + suffix)) {
                return true;
            }
        }
        return false;
    }

    private static boolean authenticatedAuthlibTransportOnStack() {
        return STACK_WALKER.walk(frames -> frames.anyMatch(frame -> frame.getClassName().equals(
                "com.mojang.authlib.minecraft.client.MinecraftClient")));
    }

    private static String normalizedHost(String value) {
        if (value == null || value.isBlank()) return "";
        try {
            String host = IDN.toASCII(value, IDN.USE_STD3_ASCII_RULES).toLowerCase(Locale.ROOT);
            while (host.endsWith(".")) host = host.substring(0, host.length() - 1);
            return host;
        } catch (IllegalArgumentException ignored) {
            return "";
        }
    }

    private static boolean isRawAddress(String host) {
        if (host.indexOf(':') >= 0 || RAW_IPV4.matcher(host).matches() || INTEGER_IPV4.matcher(host).matches()) {
            return true;
        }
        return host.startsWith("0") && host.length() > 1 && host.chars().allMatch(Character::isDigit);
    }

    private static String canonicalComponent(String value) {
        String current = safeLower(value).replace('\\', '/');
        for (int pass = 0; pass < 3; pass++) {
            StringBuilder decoded = new StringBuilder(current.length());
            boolean changed = false;
            for (int index = 0; index < current.length(); index++) {
                char c = current.charAt(index);
                if (c == '%' && index + 2 < current.length()) {
                    int high = Character.digit(current.charAt(index + 1), 16);
                    int low = Character.digit(current.charAt(index + 2), 16);
                    if (high >= 0 && low >= 0) {
                        decoded.append((char) ((high << 4) | low));
                        index += 2;
                        changed = true;
                        continue;
                    }
                }
                decoded.append(c);
            }
            current = decoded.toString();
            if (!changed) break;
        }
        while (current.contains("//")) current = current.replace("//", "/");
        return current;
    }

    private static String safeLower(String value) {
        return value == null ? "" : value.toLowerCase(Locale.ROOT);
    }
}
