package dev.runtimefixture;

import net.fabricmc.api.ClientModInitializer;
import net.fabricmc.loader.api.FabricLoader;
import net.minecraft.client.MinecraftClient;
import com.antirat.guard.TokenGuard;
import com.antirat.scan.ModIndex;
import com.antirat.AntiRatRuntime;

import javax.net.SocketFactory;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.InputStream;
import java.lang.management.ManagementFactory;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodType;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.URL;
import java.net.Proxy;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.channels.AsynchronousFileChannel;
import java.util.Properties;
import java.util.Scanner;
import java.util.UUID;
import java.sql.DriverManager;

/** Inert dev-only fixture: no credential value or external request is ever persisted or transmitted. */
public final class RuntimeAttackFixture implements ClientModInitializer {
    @Override
    public void onInitializeClient() {
        if (!Boolean.getBoolean("antirat.runtime.fixture")) return;
        MinecraftClient client = MinecraftClient.getInstance();
        Properties result = new Properties();
        result.setProperty("agentActive", Boolean.toString(Boolean.getBoolean("antirat.agent.active")));
        ModIndex.CallerContext caller = ModIndex.findCredentialCaller();
        result.setProperty("callerAttributed", Boolean.toString(caller.source().known()));
        result.setProperty("tokenGuardDenied", Boolean.toString(TokenGuard.shouldDenySessionToken()));

        String token = client.getSession().getAccessToken();
        result.setProperty("sessionTokenBlocked", Boolean.toString(token == null || token.isEmpty()));

        String sessionId = client.getSession().getSessionId();
        result.setProperty("sessionIdBlocked", Boolean.toString(sessionId == null || sessionId.isEmpty()));

        boolean networkBlocked = false;
        try {
            new URL("https://discord.com/api/webhooks/123456/inert-runtime-fixture").openConnection();
        } catch (SecurityException expected) {
            networkBlocked = true;
        } catch (Exception ignored) {
        }
        result.setProperty("webhookBlocked", Boolean.toString(networkBlocked));

        boolean unsafeCopyContainedWithoutCrash = false;
        try {
            Field singleton = sun.misc.Unsafe.class.getDeclaredField("theUnsafe");
            singleton.setAccessible(true);
            sun.misc.Unsafe unsafe = (sun.misc.Unsafe) singleton.get(null);
            byte[] source = new byte[]{7};
            byte[] destination = new byte[]{0};
            long base = unsafe.arrayBaseOffset(byte[].class);
            unsafe.copyMemory(source, base, destination, base, 1L);
            unsafeCopyContainedWithoutCrash = destination[0] == 0;
        } catch (Throwable ignored) {
        }
        result.setProperty("unsafeCopyContainedWithoutCrash", Boolean.toString(unsafeCopyContainedWithoutCrash));

        boolean sensitiveFileBlocked = false;
        Path harmlessCredentialLookalike = FabricLoader.getInstance().getGameDir()
                .resolve("antirat-runtime-fixture").resolve(".minecraft").resolve("launcher_accounts.json");
        try {
            Files.createDirectories(harmlessCredentialLookalike.getParent());
            Files.writeString(harmlessCredentialLookalike, "{\"fixture\":true}");
            Files.readAllBytes(harmlessCredentialLookalike);
        } catch (SecurityException expected) {
            sensitiveFileBlocked = true;
        } catch (Exception ignored) {
        }
        result.setProperty("credentialFileBlocked", Boolean.toString(sensitiveFileBlocked));

        boolean copyBlocked = false;
        try {
            Files.copy(harmlessCredentialLookalike, new ByteArrayOutputStream());
        } catch (SecurityException expected) {
            copyBlocked = true;
        } catch (Exception ignored) {
        }
        result.setProperty("credentialCopyBlocked", Boolean.toString(copyBlocked));

        boolean fileUrlBlocked = false;
        try (var ignored = harmlessCredentialLookalike.toUri().toURL().openStream()) {
        } catch (SecurityException expected) {
            fileUrlBlocked = true;
        } catch (Exception ignored) {
        }
        result.setProperty("credentialFileUrlBlocked", Boolean.toString(fileUrlBlocked));

        boolean reflectiveFileBlocked = false;
        try {
            Method readAllBytes = Files.class.getMethod("readAllBytes", Path.class);
            readAllBytes.invoke(null, harmlessCredentialLookalike);
        } catch (SecurityException expected) {
            reflectiveFileBlocked = true;
        } catch (Exception ignored) {
        }
        result.setProperty("reflectiveFileBlocked", Boolean.toString(reflectiveFileBlocked));

        boolean reflectiveMetadataBlocked = false;
        try {
            System.setProperty("access_token", "inert-reflective-runtime-fixture");
            Method getProperty = System.class.getMethod("getProperty", String.class);
            Object value = getProperty.invoke(null, "access_token");
            reflectiveMetadataBlocked = value == null;
        } catch (SecurityException expected) {
            reflectiveMetadataBlocked = true;
        } catch (Exception ignored) {
        } finally {
            System.clearProperty("access_token");
        }
        result.setProperty("reflectiveMetadataBlocked", Boolean.toString(reflectiveMetadataBlocked));

        boolean reflectiveConstructorBlocked = false;
        try {
            FileInputStream.class.getConstructor(java.io.File.class)
                    .newInstance(harmlessCredentialLookalike.toFile()).close();
        } catch (SecurityException expected) {
            reflectiveConstructorBlocked = true;
        } catch (Exception ignored) {
        }
        result.setProperty("reflectiveConstructorBlocked", Boolean.toString(reflectiveConstructorBlocked));

        boolean scannerFileBlocked = false;
        try (Scanner ignored = new Scanner(harmlessCredentialLookalike)) {
        } catch (SecurityException expected) {
            scannerFileBlocked = true;
        } catch (Exception ignored) {
        }
        result.setProperty("scannerFileBlocked", Boolean.toString(scannerFileBlocked));

        boolean methodHandleFileBlocked = false;
        try {
            MethodHandle reader = MethodHandles.lookup().findStatic(Files.class, "readAllBytes",
                    MethodType.methodType(byte[].class, Path.class));
            reader.invoke(harmlessCredentialLookalike);
        } catch (SecurityException expected) {
            methodHandleFileBlocked = true;
        } catch (Throwable ignored) {
        }
        result.setProperty("methodHandleFileBlocked", Boolean.toString(methodHandleFileBlocked));

        boolean reflectiveLookupFileBlocked = false;
        try {
            Method findStatic = MethodHandles.Lookup.class.getMethod(
                    "findStatic", Class.class, String.class, MethodType.class);
            MethodHandle reader = (MethodHandle) findStatic.invoke(MethodHandles.lookup(),
                    Files.class, "readAllBytes", MethodType.methodType(byte[].class, Path.class));
            reader.invoke(harmlessCredentialLookalike);
        } catch (SecurityException expected) {
            reflectiveLookupFileBlocked = true;
        } catch (Throwable ignored) {
        }
        result.setProperty("reflectiveLookupFileBlocked", Boolean.toString(reflectiveLookupFileBlocked));

        boolean constructorHandleFileBlocked = false;
        try {
            MethodHandle constructor = MethodHandles.lookup().findConstructor(FileInputStream.class,
                    MethodType.methodType(void.class, java.io.File.class));
            try (InputStream ignored = (InputStream) constructor.invoke(harmlessCredentialLookalike.toFile())) {
            }
        } catch (SecurityException expected) {
            constructorHandleFileBlocked = true;
        } catch (Throwable ignored) {
        }
        result.setProperty("constructorHandleFileBlocked", Boolean.toString(constructorHandleFileBlocked));

        boolean constructorReferenceFileBlocked = false;
        try {
            InputFactory factory = FileInputStream::new;
            try (InputStream ignored = factory.open(harmlessCredentialLookalike.toFile())) {
            }
        } catch (SecurityException expected) {
            constructorReferenceFileBlocked = true;
        } catch (Exception ignored) {
        }
        result.setProperty("constructorReferenceFileBlocked", Boolean.toString(constructorReferenceFileBlocked));

        boolean methodReferenceFileBlocked = false;
        try {
            PathReader reader = Files::readAllBytes;
            reader.read(harmlessCredentialLookalike);
        } catch (SecurityException expected) {
            methodReferenceFileBlocked = true;
        } catch (Exception ignored) {
        }
        result.setProperty("methodReferenceFileBlocked", Boolean.toString(methodReferenceFileBlocked));

        boolean asynchronousFileBlocked = false;
        try (AsynchronousFileChannel ignored = AsynchronousFileChannel.open(
                harmlessCredentialLookalike, StandardOpenOption.READ)) {
        } catch (SecurityException expected) {
            asynchronousFileBlocked = true;
        } catch (Exception ignored) {
        }
        result.setProperty("asynchronousFileBlocked", Boolean.toString(asynchronousFileBlocked));

        boolean jdbcFileBlocked = false;
        try {
            DriverManager.getConnection("jdbc:sqlite:" + harmlessCredentialLookalike);
        } catch (SecurityException expected) {
            jdbcFileBlocked = true;
        } catch (Exception ignored) {
        }
        result.setProperty("jdbcFileBlocked", Boolean.toString(jdbcFileBlocked));

        boolean processBlocked = false;
        try {
            new ProcessBuilder("sh", "-c", "exit 97").start();
        } catch (SecurityException expected) {
            processBlocked = true;
        } catch (Exception ignored) {
        }
        result.setProperty("processBlocked", Boolean.toString(processBlocked));

        boolean pipelineBlocked = false;
        try {
            ProcessBuilder.startPipeline(java.util.List.of(new ProcessBuilder("sh", "-c", "exit 98")));
        } catch (SecurityException expected) {
            pipelineBlocked = true;
        } catch (Exception ignored) {
        }
        result.setProperty("pipelineBlocked", Boolean.toString(pipelineBlocked));

        boolean processEnvironmentBlocked = false;
        try {
            ProcessBuilder builder = new ProcessBuilder();
            builder.environment().put("ACCESS_TOKEN", "inert-process-environment-fixture");
            processEnvironmentBlocked = builder.environment().get("ACCESS_TOKEN") == null;
        } catch (SecurityException expected) {
            processEnvironmentBlocked = true;
        }
        result.setProperty("processEnvironmentBlocked", Boolean.toString(processEnvironmentBlocked));

        boolean runtimePropertiesBlocked = false;
        try {
            System.setProperty("access_token", "inert-runtime-mxbean-fixture");
            runtimePropertiesBlocked = ManagementFactory.getRuntimeMXBean()
                    .getSystemProperties().get("access_token") == null;
        } catch (SecurityException expected) {
            runtimePropertiesBlocked = true;
        } finally {
            System.clearProperty("access_token");
        }
        result.setProperty("runtimePropertiesBlocked", Boolean.toString(runtimePropertiesBlocked));

        boolean nativeLoadBlocked = false;
        try {
            System.load(FabricLoader.getInstance().getGameDir().resolve("inert-nonexistent-library").toString());
        } catch (SecurityException expected) {
            nativeLoadBlocked = true;
        } catch (Throwable ignored) {
        }
        result.setProperty("nativeLoadBlocked", Boolean.toString(nativeLoadBlocked));

        boolean datagramBlocked = false;
        try (DatagramSocket socket = new DatagramSocket()) {
            DatagramPacket packet = new DatagramPacket(new byte[]{0}, 1, InetAddress.getLoopbackAddress(), 9);
            socket.send(packet);
        } catch (SecurityException expected) {
            datagramBlocked = true;
        } catch (Exception ignored) {
        }
        result.setProperty("datagramBlocked", Boolean.toString(datagramBlocked));

        boolean socketFactoryBlocked = false;
        try {
            SocketFactory.getDefault().createSocket("127.0.0.1", 9).close();
        } catch (SecurityException expected) {
            socketFactoryBlocked = true;
        } catch (Exception ignored) {
        }
        result.setProperty("socketFactoryBlocked", Boolean.toString(socketFactoryBlocked));

        boolean dnsBlocked = false;
        try {
            InetAddress.getByName("127.0.0.1");
        } catch (SecurityException expected) {
            dnsBlocked = true;
        } catch (Exception ignored) {
        }
        result.setProperty("dnsBlocked", Boolean.toString(dnsBlocked));

        boolean dynamicCodeBlocked = false;
        try {
            MethodHandles.lookup().defineClass(new byte[]{0, 1, 2, 3});
        } catch (SecurityException expected) {
            dynamicCodeBlocked = true;
        } catch (Exception | LinkageError ignored) {
        }
        result.setProperty("dynamicCodeBlocked", Boolean.toString(dynamicCodeBlocked));

        boolean reflectionBlocked = false;
        try {
            Field accessToken = client.getSession().getClass().getDeclaredField("accessToken");
            accessToken.setAccessible(true);
            Object reflected = accessToken.get(client.getSession());
            reflectionBlocked = reflected == null || reflected.toString().isEmpty();
        } catch (SecurityException expected) {
            reflectionBlocked = true;
        } catch (Exception ignored) {
        }
        result.setProperty("reflectiveTokenBlocked", Boolean.toString(reflectionBlocked));

        boolean unsafeTokenBlocked = false;
        try {
            Field singleton = sun.misc.Unsafe.class.getDeclaredField("theUnsafe");
            singleton.setAccessible(true);
            sun.misc.Unsafe unsafe = (sun.misc.Unsafe) singleton.get(null);
            Field accessToken = client.getSession().getClass().getDeclaredField("accessToken");
            unsafe.objectFieldOffset(accessToken);
        } catch (SecurityException expected) {
            unsafeTokenBlocked = true;
        } catch (Exception ignored) {
        }
        result.setProperty("unsafeTokenBlocked", Boolean.toString(unsafeTokenBlocked));

        boolean methodHandleTokenBlocked = false;
        try {
            MethodHandle getter = MethodHandles.lookup().findGetter(
                    client.getSession().getClass(), "accessToken", String.class);
            Object value = getter.invoke(client.getSession());
            methodHandleTokenBlocked = value == null || value.toString().isEmpty();
        } catch (SecurityException expected) {
            methodHandleTokenBlocked = true;
        } catch (Throwable ignored) {
        }
        result.setProperty("methodHandleTokenBlocked", Boolean.toString(methodHandleTokenBlocked));

        boolean antiRatTamperBlocked = false;
        try {
            Field enforcementState = AntiRatRuntime.class.getDeclaredField("RUNTIME_LOCKED_MODS");
            enforcementState.setAccessible(true);
            enforcementState.get(null);
        } catch (SecurityException expected) {
            antiRatTamperBlocked = true;
        } catch (Exception ignored) {
        }
        result.setProperty("antiRatTamperBlocked", Boolean.toString(antiRatTamperBlocked));

        boolean reflectivePrimitiveTamperBlocked = false;
        try {
            Field maxHistory = AntiRatRuntime.class.getDeclaredField("MAX_HISTORY");
            Method primitiveGetter = Field.class.getMethod("getInt", Object.class);
            primitiveGetter.invoke(maxHistory, (Object) null);
        } catch (SecurityException expected) {
            reflectivePrimitiveTamperBlocked = true;
        } catch (Exception ignored) {
        }
        result.setProperty("reflectivePrimitiveTamperBlocked",
                Boolean.toString(reflectivePrimitiveTamperBlocked));

        boolean reflectiveMethodTokenBlocked = false;
        try {
            Method getter = client.getSession().getClass().getMethod("getAccessToken");
            Object reflected = getter.invoke(client.getSession());
            reflectiveMethodTokenBlocked = reflected == null || reflected.toString().isEmpty();
        } catch (SecurityException expected) {
            reflectiveMethodTokenBlocked = true;
        } catch (Exception ignored) {
        }
        result.setProperty("reflectiveMethodTokenBlocked", Boolean.toString(reflectiveMethodTokenBlocked));

        boolean authlibFieldBlocked = false;
        try {
            var authenticatedClient = new com.mojang.authlib.minecraft.client.MinecraftClient(
                    "inert-authlib-token", Proxy.NO_PROXY);
            Field accessToken = authenticatedClient.getClass().getDeclaredField("accessToken");
            accessToken.setAccessible(true);
            Object reflected = accessToken.get(authenticatedClient);
            authlibFieldBlocked = reflected == null || reflected.toString().isEmpty();
        } catch (SecurityException expected) {
            authlibFieldBlocked = true;
        } catch (Exception ignored) {
        }
        result.setProperty("authlibFieldBlocked", Boolean.toString(authlibFieldBlocked));

        var inertJoinRequest = new com.mojang.authlib.yggdrasil.request.JoinMinecraftServerRequest(
                "inert-join-token", UUID.randomUUID(), "inert-server");
        String joinToken = inertJoinRequest.accessToken();
        result.setProperty("authlibJoinTokenBlocked", Boolean.toString(joinToken == null || joinToken.isEmpty()));
        String joinDescription = inertJoinRequest.toString();
        result.setProperty("authlibJoinStringBlocked",
                Boolean.toString(joinDescription == null || joinDescription.isEmpty()
                        || !joinDescription.contains("inert-join-token")));

        Path installedFixture = FabricLoader.getInstance().getGameDir().resolve("mods")
                .resolve("antirat-runtime-fixture.jar");
        for (int attempt = 0; attempt < 80 && Files.exists(installedFixture); attempt++) {
            try {
                Thread.sleep(25L);
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
                break;
            }
        }
        result.setProperty("runtimeJarQuarantined", Boolean.toString(!Files.exists(installedFixture)));

        Path marker = FabricLoader.getInstance().getGameDir().resolve(".antirat").resolve("runtime-fixture.properties");
        try {
            Files.createDirectories(marker.getParent());
            try (var output = Files.newOutputStream(marker)) {
                result.store(output, "Inert AntiRat runtime verification; contains no credentials");
            }
        } catch (Exception exception) {
            throw new IllegalStateException("Could not write AntiRat runtime fixture result", exception);
        }
        client.scheduleStop();
    }

    @FunctionalInterface
    private interface PathReader {
        byte[] read(Path path) throws Exception;
    }

    @FunctionalInterface
    private interface InputFactory {
        FileInputStream open(java.io.File file) throws Exception;
    }
}
