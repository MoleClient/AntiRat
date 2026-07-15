package com.antirat.scan;

import com.antirat.config.AntiRatConfig;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.objectweb.asm.AnnotationVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JarScannerTest {
    @TempDir
    Path temporaryDirectory;

    @Test
    void quarantinesEmbeddedWebhookExfiltrationChain() throws Exception {
        Path jar = createJar("webhook.jar", Map.of(
                "fabric.mod.json", metadata("badmod", "Bad Mod"),
                "payload.txt", "https://discord.com/api/webhooks/123456/secret java/net/http/HttpClient"
        ));

        ScanResult result = new JarScanner(AntiRatConfig.defaults()).scan(jar);

        assertEquals("badmod", result.modId());
        assertTrue(result.highConfidence());
        assertTrue(result.quarantineRecommended());
        assertTrue(result.score() >= 98);
        assertTrue(result.deniedCapabilities().contains(Capability.WEBHOOK_EXFILTRATION));
    }

    @Test
    void correlatesWebhookComponentsSplitAcrossResources() throws Exception {
        Path jar = createJar("split-webhook.jar", Map.of(
                "fabric.mod.json", metadata("split", "Split"),
                "one.txt", "https://discord.com",
                "two.txt", "/api/webhooks/",
                "three.txt", "javax/net/ssl/HttpsURLConnection"
        ));

        ScanResult result = new JarScanner(AntiRatConfig.defaults()).scan(jar);

        assertTrue(result.quarantineRecommended());
        assertTrue(result.evidence().stream().anyMatch(value -> value.contains("assembled across")));
    }

    @Test
    void findsPayloadInsideNestedJar() throws Exception {
        byte[] nested = jarBytes(Map.of(
                "hidden.txt", "api.telegram.org/bot123/sendDocument java/net/URL"
        ));
        Path jar = createJar("nested.jar", Map.of(
                "fabric.mod.json", metadata("nested", "Nested"),
                "META-INF/jars/library.jar", nested
        ));

        ScanResult result = new JarScanner(AntiRatConfig.defaults()).scan(jar);

        assertEquals(1, result.nestedArchiveCount());
        assertTrue(result.quarantineRecommended());
        assertTrue(result.evidence().stream().anyMatch(value -> value.contains("nested executable")));
    }

    @Test
    void findsArchiveHiddenBehindDataExtension() throws Exception {
        byte[] nested = jarBytes(Map.of(
                "hidden.txt", "webhook.site java/net/http/HttpClient"
        ));
        Path jar = createJar("hidden-archive.jar", Map.of(
                "fabric.mod.json", metadata("hiddenarchive", "Hidden Archive"),
                "assets/cache/payload.dat", nested
        ));

        ScanResult result = new JarScanner(AntiRatConfig.defaults()).scan(jar);

        assertEquals(1, result.nestedArchiveCount());
        assertTrue(result.quarantineRecommended());
        assertTrue(result.evidence().stream().anyMatch(value -> value.contains("non-archive name")));
    }

    @Test
    void carvesExecutableArchiveHiddenBehindPrefixBytes() throws Exception {
        byte[] nested = jarBytes(Map.of(
                "hidden.txt", "hooks.slack.com/services/T/B/secret java/net/URLConnection"
        ));
        byte[] prefixed = new byte[nested.length + 97];
        java.util.Arrays.fill(prefixed, 0, 97, (byte) 0x41);
        System.arraycopy(nested, 0, prefixed, 97, nested.length);
        Path jar = createJar("prefixed-archive.jar", Map.of(
                "fabric.mod.json", metadata("prefixed", "Prefixed"),
                "assets/cache/payload.dat", prefixed
        ));

        ScanResult result = new JarScanner(AntiRatConfig.defaults()).scan(jar);

        assertEquals(1, result.nestedArchiveCount());
        assertTrue(result.quarantineRecommended());
    }

    @Test
    void inspectsClassBytesHiddenBehindResourceName() throws Exception {
        byte[] classBytes;
        try (var input = JarScannerTest.class.getResourceAsStream("JarScannerTest.class")) {
            classBytes = input.readAllBytes();
        }
        Path jar = createJar("hidden-class.jar", Map.of(
                "fabric.mod.json", metadata("hiddenclass", "Hidden Class"),
                "assets/cache/blob.dat", classBytes
        ));

        ScanResult result = new JarScanner(AntiRatConfig.defaults()).scan(jar);

        assertEquals(1, result.classCount());
        assertTrue(result.evidence().stream().anyMatch(value -> value.contains("Class bytes concealed")));
    }

    @Test
    void doesNotQuarantineOrdinarySessionAwareNetworkingAlone() throws Exception {
        Path jar = createJar("legitimate-auth.jar", Map.of(
                "fabric.mod.json", metadata("legitauth", "Legitimate Auth"),
                "client.txt", "net/minecraft/client/session/Session getAccessToken java/net/http/HttpClient authorization"
        ));

        ScanResult result = new JarScanner(AntiRatConfig.defaults()).scan(jar);

        assertFalse(result.highConfidence());
        assertFalse(result.quarantineRecommended());
        assertTrue(result.score() >= AntiRatConfig.DEFAULT_WARNING_THRESHOLD);
    }

    @Test
    void quarantinesConcealedSessionExfiltrationThatCanLaunchAProcess() throws Exception {
        Path jar = createJar("concealed-session-process.jar", Map.of(
                "fabric.mod.json", metadata("concealedstealer", "Concealed Stealer"),
                "payload.txt", "net/minecraft/class_320 method_1674 authorization "
                        + "java/net/Socket java/lang/ProcessBuilder java/lang/reflect/Method java/util/Base64"
        ));

        ScanResult result = new JarScanner(AntiRatConfig.defaults()).scan(jar);

        assertTrue(result.highConfidence(), result.toString());
        assertTrue(result.quarantineRecommended());
        assertTrue(result.score() >= 97);
        assertTrue(result.deniedCapabilities().contains(Capability.MINECRAFT_SESSION));
        assertTrue(result.deniedCapabilities().contains(Capability.PROCESS_EXECUTION));
        assertTrue(result.deniedCapabilities().contains(Capability.UNTRUSTED_NETWORK));
    }

    @Test
    void doesNotQuarantineNetworkedProcessHelperWithoutCredentialAccess() throws Exception {
        Path jar = createJar("network-helper.jar", Map.of(
                "fabric.mod.json", metadata("networkhelper", "Network Helper"),
                "helper.txt", "java/net/http/HttpClient java/lang/ProcessBuilder java/util/Base64"
        ));

        ScanResult result = new JarScanner(AntiRatConfig.defaults()).scan(jar);

        assertFalse(result.highConfidence());
        assertFalse(result.quarantineRecommended());
    }

    @Test
    void recoversEncodedSessionIdAccessorAsCredentialAccess() throws Exception {
        String concealed = java.util.Base64.getEncoder().encodeToString(
                "net/minecraft/client/session/Session getSessionId java/net/http/HttpClient"
                        .getBytes(java.nio.charset.StandardCharsets.UTF_8));
        Path jar = createJar("session-id.jar", Map.of(
                "fabric.mod.json", metadata("sessionid", "Session Id"),
                "payload.txt", concealed
        ));

        ScanResult result = new JarScanner(AntiRatConfig.defaults()).scan(jar);

        assertTrue(result.score() >= AntiRatConfig.DEFAULT_WARNING_THRESHOLD);
        assertTrue(result.evidence().stream().anyMatch(value -> value.contains("Recovered security indicators")));
        assertTrue(result.evidence().stream().anyMatch(value -> value.contains("session/access-token")));
    }

    @Test
    void quarantinesNetworkedMixinThatInterceptsAuthlibJoinCredentials() throws Exception {
        Path jar = createJar("credential-mixin.jar", Map.of(
                "fabric.mod.json", metadata("credentialmixin", "Credential Mixin"),
                "evil/JoinRequestMixin.class", credentialMixinBytes()
        ));

        ScanResult result = new JarScanner(AntiRatConfig.defaults()).scan(jar);

        assertTrue(result.highConfidence(), result.toString());
        assertTrue(result.quarantineRecommended());
        assertTrue(result.deniedCapabilities().contains(Capability.MINECRAFT_SESSION));
        assertTrue(result.evidence().stream().anyMatch(value -> value.contains("token-bearing")));
    }

    @Test
    void readsHardDependenciesForSafeRelaunchCascade() throws Exception {
        Path jar = createJar("dependent.jar", Map.of(
                "fabric.mod.json", "{\"id\":\"dependent\",\"name\":\"Dependent\",\"depends\":{\"ratlib\":\">=1\",\"minecraft\":\"*\"}}"
        ));

        ScanResult result = new JarScanner(AntiRatConfig.defaults()).scan(jar);

        assertEquals(Set.of("ratlib"), result.requiredModIds());
    }

    @Test
    void entropyAloneDoesNotProduceAThreatVerdict() throws Exception {
        byte[] random = new byte[64 * 1024];
        new SecureRandom().nextBytes(random);
        Path jar = createJar("assets.jar", Map.of(
                "fabric.mod.json", metadata("assets", "Assets"),
                "assets/example/texture.bin", random
        ));

        ScanResult result = new JarScanner(AntiRatConfig.defaults()).scan(jar);

        assertFalse(result.highConfidence());
        assertFalse(result.quarantineRecommended());
        assertEquals(0, result.score());
    }

    @Test
    void recognizesNativeExecutableMagicWithoutTreatingItAsMaliciousAlone() throws Exception {
        byte[] elf = new byte[8 * 1024];
        new SecureRandom().nextBytes(elf);
        elf[0] = 0x7f;
        elf[1] = 'E';
        elf[2] = 'L';
        elf[3] = 'F';
        Path jar = createJar("native-helper.jar", Map.of(
                "fabric.mod.json", metadata("nativehelper", "Native Helper"),
                "assets/helper.dat", elf
        ));

        ScanResult result = new JarScanner(AntiRatConfig.defaults()).scan(jar);

        assertFalse(result.highConfidence());
        assertFalse(result.quarantineRecommended());
        assertTrue(result.score() >= AntiRatConfig.DEFAULT_WARNING_THRESHOLD);
        assertTrue(result.evidence().stream().anyMatch(value -> value.contains("native executable")));
    }

    @Test
    void inspectsSecurityIndicatorsBeyondTheOrdinarySampleInNamedNativeArtifacts() throws Exception {
        byte[] nativePayload = new byte[640 * 1024];
        nativePayload[0] = 'M';
        nativePayload[1] = 'Z';
        byte[] indicators = ("https://discord.com/api/webhooks/123/native-placeholder "
                + "java/net/http/HttpClient").getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        System.arraycopy(indicators, 0, nativePayload, 560 * 1024, indicators.length);
        Path jar = createJar("native-late-payload.jar", Map.of(
                "fabric.mod.json", metadata("nativelate", "Native Late Payload"),
                "natives/windows/helper.dll", nativePayload
        ));

        ScanResult result = new JarScanner(AntiRatConfig.defaults()).scan(jar);

        assertTrue(result.highConfidence());
        assertTrue(result.quarantineRecommended());
        assertTrue(result.evidence().stream().anyMatch(value -> value.contains("webhook")));
    }

    @Test
    void exactHashAllowlistOverridesAutomaticQuarantine() throws Exception {
        Path jar = createJar("allowed.jar", Map.of(
                "fabric.mod.json", metadata("allowed", "Allowed"),
                "payload.txt", "https://discord.com/api/webhooks/123/secret java/net/URL"
        ));
        ScanResult first = new JarScanner(AntiRatConfig.defaults()).scan(jar);
        AntiRatConfig allowed = new AntiRatConfig(86, 35, 256L << 20, 12L << 20,
                512L << 20, 30_000, 2, Set.of(first.sha256()), Set.of());

        ScanResult result = new JarScanner(allowed).scan(jar);

        assertTrue(result.highConfidence());
        assertFalse(result.quarantineRecommended());
        assertTrue(result.evidence().stream().anyMatch(value -> value.contains("allowlisted")));
    }

    @Test
    void failsClosedWhenArchiveEntryBudgetIsExceeded() throws Exception {
        Map<String, Object> entries = new LinkedHashMap<>();
        entries.put("fabric.mod.json", metadata("overflow", "Overflow"));
        for (int index = 0; index < 101; index++) entries.put("assets/x/" + index + ".bin", new byte[]{1});
        Path jar = createJar("overflow.jar", entries);
        AntiRatConfig bounded = new AntiRatConfig(86, 35, 256L << 20, 12L << 20,
                512L << 20, 100, 2, Set.of(), Set.of());

        ScanResult result = new JarScanner(bounded).scan(jar);

        assertTrue(result.highConfidence());
        assertTrue(result.quarantineRecommended());
        assertTrue(result.evidence().stream().anyMatch(value -> value.contains("Fail-closed")));
    }

    private Path createJar(String name, Map<String, ?> entries) throws IOException {
        Path path = temporaryDirectory.resolve(name);
        try (JarOutputStream output = new JarOutputStream(Files.newOutputStream(path))) {
            writeEntries(output, entries);
        }
        return path;
    }

    private static byte[] jarBytes(Map<String, ?> entries) throws IOException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (JarOutputStream output = new JarOutputStream(bytes)) {
            writeEntries(output, entries);
        }
        return bytes.toByteArray();
    }

    private static byte[] credentialMixinBytes() {
        ClassWriter writer = new ClassWriter(0);
        writer.visit(Opcodes.V21, Opcodes.ACC_PUBLIC, "evil/JoinRequestMixin", null,
                "java/lang/Object", null);
        writer.visitField(Opcodes.ACC_PRIVATE, "network", "Ljava/net/URL;", null, null).visitEnd();
        AnnotationVisitor mixin = writer.visitAnnotation("Lorg/spongepowered/asm/mixin/Mixin;", false);
        AnnotationVisitor targets = mixin.visitArray("targets");
        targets.visit(null, "com.mojang.authlib.yggdrasil.request.JoinMinecraftServerRequest");
        targets.visitEnd();
        mixin.visitEnd();
        MethodVisitor method = writer.visitMethod(Opcodes.ACC_PUBLIC, "capture", "()V", null, null);
        AnnotationVisitor inject = method.visitAnnotation(
                "Lorg/spongepowered/asm/mixin/injection/Inject;", false);
        inject.visit("method", "<init>");
        inject.visitEnd();
        method.visitCode();
        method.visitLdcInsn("https://collector.example.invalid");
        method.visitInsn(Opcodes.POP);
        method.visitInsn(Opcodes.RETURN);
        method.visitMaxs(1, 1);
        method.visitEnd();
        writer.visitEnd();
        return writer.toByteArray();
    }

    private static void writeEntries(JarOutputStream output, Map<String, ?> entries) throws IOException {
        for (Map.Entry<String, ?> entry : entries.entrySet()) {
            output.putNextEntry(new JarEntry(entry.getKey()));
            Object value = entry.getValue();
            output.write(value instanceof byte[] bytes ? bytes : value.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8));
            output.closeEntry();
        }
    }

    private static String metadata(String id, String name) {
        return "{\"schemaVersion\":1,\"id\":\"" + id + "\",\"name\":\"" + name + "\",\"version\":\"1\"}";
    }
}
