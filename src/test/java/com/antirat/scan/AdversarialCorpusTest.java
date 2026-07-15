package com.antirat.scan;

import com.antirat.config.AntiRatConfig;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AdversarialCorpusTest {
    @TempDir
    Path temporaryDirectory;

    @TestFactory
    Stream<DynamicTest> quarantinesInertAdversarialCorpus() {
        Map<String, Map<String, Object>> corpus = new LinkedHashMap<>();
        corpus.put("base64-discord-webhook", entries(
                "payload.dat", base64("https://discord.com/api/webhooks/123/secret"),
                "client.txt", "java/net/http/HttpClient"));
        corpus.put("hex-telegram-bot", entries(
                "route.dat", hex("https://api.telegram.org/bot123/sendDocument"),
                "client.txt", "java/net/URLConnection"));
        corpus.put("reversed-slack-hook", entries(
                "route.dat", reverse("https://hooks.slack.com/services/T/B/secret"),
                "client.txt", "okhttp3/OkHttpClient"));
        corpus.put("rot13-request-collector", entries(
                "route.dat", rot13("https://capture.webhook.site/id"),
                "client.txt", "java/net/http/HttpClient"));
        corpus.put("percent-encoded-webhook", entries(
                "route.dat", "https://discord.com/api/%77%65%62%68%6f%6f%6b%73/123/secret",
                "client.txt", "java/net/URL"));
        corpus.put("base64-single-byte-xor", entries(
                "route.dat", base64(xor("https://discord.com/api/webhooks/123/secret", 0x5a)),
                "client.txt", "java/net/http/HttpClient"));
        corpus.put("nested-base64-webhook", entries(
                "route.dat", base64(base64("https://discord.com/api/webhooks/123/secret")),
                "client.txt", "java/net/http/HttpClient"));
        corpus.put("reversed-base64-webhook", entries(
                "route.dat", reverse(base64("https://discord.com/api/webhooks/123/secret")),
                "client.txt", "java/net/http/HttpClient"));
        corpus.put("escaped-character-webhook", entries(
                "route.dat", "https://\\u0064iscord.com/api/\\x77ebhooks/123/secret",
                "client.txt", "java/net/http/HttpClient"));
        corpus.put("caesar-webhook", entries(
                "route.dat", caesar("https://discord.com/api/webhooks/123/secret", 7),
                "client.txt", "java/net/http/HttpClient"));
        corpus.put("split-domain-and-path", entries(
                "a.dat", "disc", "b.dat", "ord.com", "c.dat", "api/web", "d.dat", "hooks",
                "client.txt", "java/net/http/HttpClient"));
        corpus.put("many-way-split-domain-and-path", entries(
                "a.dat", "di", "b.dat", "sc", "c.dat", "ord", "d.dat", ".com",
                "e.dat", "api", "f.dat", "web", "g.dat", "hooks",
                "client.txt", "java/net/http/HttpClient"));
        corpus.put("delayed-session-grabber", entries(
                "timer.txt", "ScheduledExecutorService delay 86400 net/minecraft/client/session/Session getAccessToken",
                "route.txt", "webhook.site java/net/http/HttpClient"));
        corpus.put("versioned-discord-webhook", entries(
                "route.txt", "https://canary.discord.com/api/v10/webhooks/123/secret java/net/URL"));
        corpus.put("credential-process-chain", entries(
                "chain.txt", "launcher_profiles.json selectedUser java/lang/ProcessBuilder java/net/http/HttpClient"));
        corpus.put("native-concealed-session-chain", entries(
                "source.txt", "net/minecraft/class_320 method_1674 java/lang/System.loadLibrary java/net/Socket",
                "native/payload.dylib", randomBytes(16 * 1024, 19L)));

        return corpus.entrySet().stream().map(entry -> DynamicTest.dynamicTest(entry.getKey(), () -> {
            ScanResult result = scan(entry.getKey(), entry.getValue());
            assertTrue(result.highConfidence(), () -> entry.getKey() + " was not high confidence: " + result);
            assertTrue(result.quarantineRecommended(), () -> entry.getKey() + " was not quarantined: " + result);
        }));
    }

    @org.junit.jupiter.api.Test
    void warnsOnAmbiguousEncryptedDynamicLoaderWithoutFalsePositiveQuarantine() throws Exception {
        ScanResult result = scan("encrypted-dynamic-loader", entries(
                "loader.txt", "java/lang/invoke/MethodHandles$Lookup defineHiddenClass javax/crypto/Cipher java/net/http/HttpClient",
                "assets/cache.bin", randomBytes(32 * 1024, 41L)));

        assertFalse(result.quarantineRecommended());
        assertTrue(result.score() >= AntiRatConfig.DEFAULT_WARNING_THRESHOLD);
        assertTrue(result.evidence().stream().anyMatch(value -> value.contains("Encrypted runtime code loader")));
    }

    @org.junit.jupiter.api.Test
    void detectsCredentialStoreCorpusForRuntimeFileBarrierWithoutAutoQuarantine() throws Exception {
        List<ScanResult> results = List.of(
                scan("encoded-discord-store", entries(
                        "source.dat", base64("Discord/Local Storage/leveldb/000001.ldb discord_token"),
                        "client.txt", "javax/crypto/Cipher java/net/http/HttpClient")),
                scan("encoded-browser-store", entries(
                        "source.dat", hex("Google/Chrome/User Data/Default/Login Data"),
                        "client.txt", "CryptUnprotectData java/net/Socket")),
                scan("encoded-launcher-account", entries(
                        "source.dat", reverse("launcher_accounts.json access_token"),
                        "client.txt", "java/net/http/HttpClient"))
        );

        for (ScanResult result : results) {
            assertFalse(result.quarantineRecommended());
            assertTrue(result.score() >= AntiRatConfig.DEFAULT_WARNING_THRESHOLD);
            assertTrue(result.evidence().stream().anyMatch(value -> value.contains("credential-store")
                    || value.contains("account-store")));
        }
    }

    @TestFactory
    Stream<DynamicTest> preservesInertBenignCorpus() throws IOException {
        Map<String, Map<String, Object>> corpus = new LinkedHashMap<>();
        corpus.put("essential-style-auth", entries("client.txt",
                "net/minecraft/client/session/Session getAccessToken java/net/http/HttpClient authorization"));
        corpus.put("discord-rich-presence", entries("client.txt",
                "https://discord.com/api/v10/users/@me discord rich presence java/net/Socket"));
        corpus.put("browser-backup-without-decryption", entries("client.txt",
                "Google/Chrome/User Data Login Data java/net/http/HttpClient backup documentation"));
        corpus.put("launcher-profile-reader-without-egress", entries("client.txt",
                "launcher_profiles.json selectedUser local account switcher"));
        corpus.put("leveldb-library", entries("client.txt", "org/iq80/leveldb local storage cache"));
        corpus.put("native-voice-client", entries("client.txt",
                "java/lang/System.loadLibrary voice codec java/net/DatagramSocket"));
        corpus.put("dynamic-plugin-without-credentials", entries("client.txt",
                "java/lang/invoke/MethodHandles$Lookup defineClass plugin api"));
        corpus.put("webhook-example-in-readme", entries(
                "README.md", "Example: https://discord.com/api/webhooks/123/not-real",
                "client.txt", "java/net/http/HttpClient"));
        corpus.put("security-scanner-vocabulary-in-docs", entries(
                "docs/security.md", "launcher_accounts.json Discord/Local Storage/leveldb Login Data CryptUnprotectData",
                "client.txt", "java/net/http/HttpClient"));

        byte[] randomAsset = new byte[64 * 1024];
        new Random(7L).nextBytes(randomAsset);
        corpus.put("high-entropy-texture", entries("assets/texture.bin", randomAsset));
        corpus.put("base64-localization", entries("assets/lang/blob.txt",
                base64("This is an ordinary localization payload with no credential or network behavior.")));
        corpus.put("slack-domain-without-webhook", entries("client.txt",
                "https://api.slack.com/methods/chat.postMessage java/net/http/HttpClient"));
        corpus.put("telegram-read-only-link", entries("client.txt",
                "https://telegram.org java/net/URL community documentation"));
        corpus.put("ordinary-http-client", entries("client.txt",
                "java/net/http/HttpClient https://example.invalid/mod-update.json"));

        byte[] plainClass;
        try (var input = AdversarialCorpusTest.class.getResourceAsStream("AdversarialCorpusTest$PlainFixture.class")) {
            plainClass = input.readAllBytes();
        }
        Map<String, Object> obfuscated = new LinkedHashMap<>();
        for (int index = 0; index < 20; index++) obfuscated.put("x/" + (char) ('a' + index) + ".class", plainClass);
        obfuscated.put("network.txt", "java/net/http/HttpClient ordinary update checker");
        corpus.put("obfuscated-names-without-credential-chain", obfuscated);

        return corpus.entrySet().stream().map(entry -> DynamicTest.dynamicTest(entry.getKey(), () -> {
            ScanResult result = scan(entry.getKey(), entry.getValue());
            assertFalse(result.quarantineRecommended(), () -> entry.getKey() + " false-positive quarantine: " + result);
        }));
    }

    private ScanResult scan(String name, Map<String, Object> entries) throws IOException {
        Path jar = temporaryDirectory.resolve(name + ".jar");
        try (JarOutputStream output = new JarOutputStream(Files.newOutputStream(jar))) {
            write(output, "fabric.mod.json", "{\"schemaVersion\":1,\"id\":\"" + safeId(name)
                    + "\",\"name\":\"Corpus fixture\",\"version\":\"1\"}");
            for (Map.Entry<String, Object> entry : entries.entrySet()) write(output, entry.getKey(), entry.getValue());
        }
        return new JarScanner(AntiRatConfig.defaults()).scan(jar);
    }

    private static void write(JarOutputStream output, String name, Object value) throws IOException {
        output.putNextEntry(new JarEntry(name));
        output.write(value instanceof byte[] bytes ? bytes : value.toString().getBytes(StandardCharsets.UTF_8));
        output.closeEntry();
    }

    private static Map<String, Object> entries(Object... values) {
        Map<String, Object> result = new LinkedHashMap<>();
        for (int index = 0; index < values.length; index += 2) result.put(values[index].toString(), values[index + 1]);
        return result;
    }

    private static String safeId(String value) {
        return value.replaceAll("[^a-z0-9_-]", "_");
    }

    private static String base64(String value) {
        return base64(value.getBytes(StandardCharsets.UTF_8));
    }

    private static String base64(byte[] value) {
        return Base64.getEncoder().encodeToString(value);
    }

    private static String hex(String value) {
        StringBuilder result = new StringBuilder();
        for (byte b : value.getBytes(StandardCharsets.UTF_8)) result.append(String.format("%02x", b & 0xff));
        return result.toString();
    }

    private static byte[] xor(String value, int key) {
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        for (int index = 0; index < bytes.length; index++) bytes[index] ^= (byte) key;
        return bytes;
    }

    private static String reverse(String value) {
        return new StringBuilder(value).reverse().toString();
    }

    private static String rot13(String value) {
        StringBuilder result = new StringBuilder();
        for (char c : value.toCharArray()) {
            if (c >= 'a' && c <= 'z') c = (char) ('a' + (c - 'a' + 13) % 26);
            else if (c >= 'A' && c <= 'Z') c = (char) ('A' + (c - 'A' + 13) % 26);
            result.append(c);
        }
        return result.toString();
    }

    private static String caesar(String value, int shift) {
        StringBuilder result = new StringBuilder(value.length());
        for (char c : value.toCharArray()) {
            if (c >= 'a' && c <= 'z') c = (char) ('a' + (c - 'a' + shift) % 26);
            else if (c >= 'A' && c <= 'Z') c = (char) ('A' + (c - 'A' + shift) % 26);
            result.append(c);
        }
        return result.toString();
    }

    private static byte[] randomBytes(int length, long seed) {
        byte[] bytes = new byte[length];
        new Random(seed).nextBytes(bytes);
        return bytes;
    }

    private static final class PlainFixture {
    }
}
