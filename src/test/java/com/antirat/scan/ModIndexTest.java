package com.antirat.scan;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.net.URI;
import java.nio.file.Path;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ModIndexTest {
    @TempDir
    Path temporaryDirectory;

    @Test
    void trustedInfrastructureCannotBeClaimedWithAPrefixLookalikeId() {
        assertTrue(ModIndex.isInfrastructure("a-"));
        assertTrue(ModIndex.isInfrastructure("minecraft"));
        assertTrue(ModIndex.isInfrastructure("fabricloader"));
        assertFalse(ModIndex.isInfrastructure("fabric-api"));
        assertFalse(ModIndex.isInfrastructure("fabric-credential-helper"));
        assertFalse(ModIndex.isInfrastructure("a--lookalike"));
    }

    @Test
    void derivesProcessedJarPathFromNestedFabricRootUri() {
        Path path = ModIndex.pathFromRootUri(URI.create(
                "jar:file:///tmp/.fabric/processedMods/essential-loader.jar!/"));

        assertEquals(Path.of("/tmp/.fabric/processedMods/essential-loader.jar"), path);
    }

    @Test
    void deeplyScansAndAttributesAFileBackedRuntimeLoadedJar() throws Exception {
        Path jar = temporaryDirectory.resolve("runtime.jar");
        try (JarOutputStream output = new JarOutputStream(Files.newOutputStream(jar))) {
            output.putNextEntry(new JarEntry("fabric.mod.json"));
            output.write("{\"schemaVersion\":1,\"id\":\"legit_runtime\",\"name\":\"Runtime Fixture\",\"version\":\"1\"}"
                    .getBytes(java.nio.charset.StandardCharsets.UTF_8));
            output.closeEntry();
        }

        ModIdentity identity = ModIndex.inspectRuntimeOrigin(jar);

        assertTrue(identity.known());
        assertTrue(identity.id().startsWith("runtime-legit_runtime-"));
        assertTrue(ScanRegistry.startupResult(identity.id()) != null);
    }

    @Test
    void credentialEntrySkipsCarrierAndTransparentJdkFramesButStopsAtTheRealCaller() throws Exception {
        Class<?> carrier = sessionCarrier();
        Class<?> caller = ModIndex.firstCredentialCaller(carrier, List.of(
                com.antirat.guard.TokenGuard.class,
                carrier,
                carrier,
                java.lang.reflect.Method.class,
                org.junit.jupiter.api.Test.class));

        assertEquals(org.junit.jupiter.api.Test.class, caller);
    }

    @Test
    void credentialEntryIdentifiesMinecraftAsTheImmediateConsumer() throws Exception {
        Class<?> carrier = sessionCarrier();
        Class<?> client = minecraftClient();
        Class<?> caller = ModIndex.firstCredentialCaller(carrier, List.of(
                com.antirat.guard.TokenGuard.class,
                carrier,
                carrier,
                client,
                org.junit.jupiter.api.Test.class));

        assertEquals(client, caller);
    }

    @Test
    void credentialEntryCannotInventACarrierForADirectGuardCall() throws Exception {
        Class<?> caller = ModIndex.firstCredentialCaller(sessionCarrier(), List.of(
                com.antirat.guard.TokenGuard.class,
                org.junit.jupiter.api.Test.class,
                minecraftClient()));

        assertNull(caller);
    }

    private static Class<?> sessionCarrier() throws ClassNotFoundException {
        try {
            return Class.forName("net.minecraft.client.session.Session");
        } catch (ClassNotFoundException modern) {
            return Class.forName("net.minecraft.client.User");
        }
    }

    private static Class<?> minecraftClient() throws ClassNotFoundException {
        try {
            return Class.forName("net.minecraft.client.MinecraftClient");
        } catch (ClassNotFoundException modern) {
            return Class.forName("net.minecraft.client.Minecraft");
        }
    }
}
