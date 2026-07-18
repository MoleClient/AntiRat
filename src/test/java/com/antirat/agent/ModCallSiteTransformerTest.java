package com.antirat.agent;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Handle;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

import java.io.FileInputStream;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Constructor;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodType;
import java.net.Socket;
import java.net.URL;
import java.lang.management.ManagementFactory;
import java.nio.channels.AsynchronousFileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.CodeSource;
import java.security.ProtectionDomain;
import java.sql.Connection;
import java.sql.DriverManager;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Scanner;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ModCallSiteTransformerTest {
    @TempDir
    Path temporaryDirectory;

    @Test
    void guardsMixinHandlersCopiedIntoMinecraftCredentialCarrier() {
        byte[] transformed = ModCallSiteTransformer.transformCredentialCarrierBytes(credentialCarrierFixture());
        List<String> calls = methodCalls(transformed);

        assertTrue(calls.stream().anyMatch(value -> value.contains("RuntimeHooks.spoofCredentialMixinArgument")));
        assertTrue(calls.stream().anyMatch(value -> value.contains("RuntimeHooks.directSessionTokenMethod")));
        assertFalse(calls.stream().anyMatch(value -> value.contains("net.minecraft.client.User.getAccessToken")));
    }

    @Test
    void rewritesHighValueJdkCallSitesToRuntimeHooks() throws Exception {
        byte[] transformed = ModCallSiteTransformer.transformBytes(fixtureBytes());
        List<String> calls = methodCalls(transformed);

        assertTrue(calls.stream().anyMatch(value -> value.contains("RuntimeHooks.filesReadAllBytes")));
        assertTrue(calls.stream().anyMatch(value -> value.contains("RuntimeHooks.urlOpenConnection")));
        assertTrue(calls.stream().anyMatch(value -> value.contains("RuntimeHooks.processStart")));
        assertTrue(calls.stream().anyMatch(value -> value.contains("RuntimeHooks.reflectiveFieldGet")));
        assertTrue(calls.stream().anyMatch(value -> value.contains("RuntimeHooks.reflectiveFieldGetInt")));
        assertTrue(calls.stream().anyMatch(value -> value.contains("RuntimeHooks.reflectiveFieldSet")));
        assertTrue(calls.stream().anyMatch(value -> value.contains("RuntimeHooks.guardFileRead")));
        assertTrue(calls.stream().anyMatch(value -> value.contains("RuntimeHooks.checkHostPort")));
        assertTrue(calls.stream().anyMatch(value -> value.contains("RuntimeHooks.reflectiveMethodInvoke")));
        assertTrue(calls.stream().anyMatch(value -> value.contains("RuntimeHooks.reflectiveConstructorNewInstance")));
        assertTrue(calls.stream().anyMatch(value -> value.contains("RuntimeHooks.guardDynamicCode")));
        assertTrue(calls.stream().anyMatch(value -> value.contains("RuntimeHooks.filesReadAllLines")));
        assertTrue(calls.stream().anyMatch(value -> value.contains("RuntimeHooks.unsafeGetObject")));
        assertTrue(calls.stream().anyMatch(value -> value.contains("RuntimeHooks.unsafeCompareAndSwapObject")));
        assertTrue(calls.stream().anyMatch(value -> value.contains("RuntimeHooks.unsafeAllocateInstance")));
        assertTrue(calls.stream().anyMatch(value -> value.contains("RuntimeHooks.guardUnsafeField")));
        assertTrue(calls.stream().anyMatch(value -> value.contains("RuntimeHooks.unsafeAllocateMemory")));
        assertTrue(calls.stream().anyMatch(value -> value.contains("RuntimeHooks.unsafeCopyMemory")));
        assertTrue(calls.stream().anyMatch(value -> value.contains("sun.misc.Unsafe.putOrderedLong")));
        assertTrue(calls.stream().anyMatch(value -> value.contains("RuntimeHooks.systemGetenv")));
        assertTrue(calls.stream().anyMatch(value -> value.contains("RuntimeHooks.processInfoArguments")));
        assertTrue(calls.stream().anyMatch(value -> value.contains("RuntimeHooks.urlOpenStream")));
        assertTrue(calls.stream().anyMatch(value -> value.contains("RuntimeHooks.lookupFindStatic")));
        assertTrue(calls.stream().anyMatch(value -> value.contains("RuntimeHooks.lookupFindGetter")));
        assertTrue(calls.stream().anyMatch(value -> value.contains("RuntimeHooks.asynchronousFileChannelOpen")));
        assertTrue(calls.stream().anyMatch(value -> value.contains("RuntimeHooks.processStartPipeline")));
        assertTrue(calls.stream().anyMatch(value -> value.contains("RuntimeHooks.driverManagerGetConnection")));
        assertTrue(calls.stream().anyMatch(value -> value.contains("RuntimeHooks.systemLoad")));
        assertTrue(calls.stream().anyMatch(value -> value.contains("RuntimeHooks.runtimeLoad")));
        assertTrue(calls.stream().anyMatch(value -> value.contains("RuntimeHooks.processBuilderEnvironment")));
        assertTrue(calls.stream().anyMatch(value -> value.contains("RuntimeHooks.runtimeMxBeanGetSystemProperties")));
        assertTrue(calls.stream().anyMatch(value -> value.contains("RuntimeHooks.lookupFindConstructor")));
        assertFalse(calls.stream().anyMatch(value -> value.contains("java/nio/file/Files.readAllBytes")));
    }

    @Test
    void rewritesSensitiveInvokeDynamicMethodReferences() throws Exception {
        byte[] transformed = ModCallSiteTransformer.transformBytes(fixtureBytes());
        List<String> handles = bootstrapHandles(transformed);

        assertTrue(handles.stream().anyMatch(value -> value.contains("RuntimeHooks.filesReadAllBytes")));
        assertTrue(handles.stream().anyMatch(value -> value.contains("RuntimeHooks.fileInputStreamCreate")));
        assertFalse(handles.stream().anyMatch(value -> value.contains("java/nio/file/Files.readAllBytes")));
    }

    @Test
    void rewritesDirectConstantPoolMethodHandles() {
        byte[] transformed = ModCallSiteTransformer.transformBytes(constantMethodHandleFixture());
        List<String> handles = constantPoolHandles(transformed);

        assertTrue(handles.stream().anyMatch(value -> value.contains("RuntimeHooks.filesReadAllBytes")));
        assertFalse(handles.stream().anyMatch(value -> value.contains("java/nio/file/Files.readAllBytes")));
    }

    @Test
    void rewrittenConstantPoolMethodHandleExecutesThroughGuard() throws Throwable {
        byte[] expected = "safe constant handle".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        Path file = temporaryDirectory.resolve("ordinary-constant-handle.txt");
        Files.write(file, expected);
        byte[] transformed = ModCallSiteTransformer.transformBytes(constantMethodHandleFixture());
        Class<?> isolated = new ChildFirstLoader("fixture.ConstantHandle", transformed)
                .loadClass("fixture.ConstantHandle");
        java.lang.invoke.MethodHandle handle = (java.lang.invoke.MethodHandle) isolated.getMethod("handle").invoke(null);

        assertArrayEquals(expected, (byte[]) handle.invoke(file));
    }

    @Test
    void guardsNettyBootstrapDestinationsWithoutDependingOnNettyInternals() {
        List<String> calls = methodCalls(ModCallSiteTransformer.transformBytes(nettyBootstrapFixture()));

        assertTrue(calls.stream().anyMatch(value -> value.contains("RuntimeHooks.checkHostPort")));
        assertTrue(calls.stream().anyMatch(value -> value.contains("io.netty.bootstrap.Bootstrap.connect")));
    }

    @Test
    void transformedBytecodeExecutesForAnOrdinaryFileRead() throws Exception {
        byte[] expected = "safe fixture".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        Path file = temporaryDirectory.resolve("ordinary.txt");
        Files.write(file, expected);

        byte[] transformed = ModCallSiteTransformer.transformBytes(fixtureBytes());
        Class<?> isolated = new ChildFirstLoader(CallSiteFixture.class.getName(), transformed).loadClass(CallSiteFixture.class.getName());
        byte[] actual = (byte[]) isolated.getMethod("read", Path.class).invoke(null, file);

        assertArrayEquals(expected, actual);
    }

    @Test
    void transformedMethodHandleExecutesThroughGuardForAnOrdinaryFileRead() throws Exception {
        byte[] expected = "safe method handle".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        Path file = temporaryDirectory.resolve("ordinary-handle.txt");
        Files.write(file, expected);

        Class<?> isolated = new ChildFirstLoader(CallSiteFixture.class.getName(),
                ModCallSiteTransformer.transformBytes(fixtureBytes())).loadClass(CallSiteFixture.class.getName());
        byte[] actual = (byte[]) isolated.getMethod("lookupRead", Path.class).invoke(null, file);

        assertArrayEquals(expected, actual);
    }

    @Test
    void transformedMethodReferenceExecutesThroughGuardForAnOrdinaryFileRead() throws Exception {
        byte[] expected = "safe method reference".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        Path file = temporaryDirectory.resolve("ordinary-method-reference.txt");
        Files.write(file, expected);

        Class<?> isolated = new ChildFirstLoader(CallSiteFixture.class.getName(),
                ModCallSiteTransformer.transformBytes(fixtureBytes())).loadClass(CallSiteFixture.class.getName());
        PathReader reader = (PathReader) isolated.getMethod("methodReference").invoke(null);

        assertArrayEquals(expected, reader.read(file));
    }

    @Test
    void transformedConstructorMethodReferenceExecutesThroughGuardForAnOrdinaryFileRead() throws Exception {
        byte[] expected = "safe constructor reference".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        Path file = temporaryDirectory.resolve("ordinary-constructor-reference.txt");
        Files.write(file, expected);

        Class<?> isolated = new ChildFirstLoader(CallSiteFixture.class.getName(),
                ModCallSiteTransformer.transformBytes(fixtureBytes())).loadClass(CallSiteFixture.class.getName());
        InputFactory factory = (InputFactory) isolated.getMethod("inputFactory").invoke(null);
        byte[] actual;
        try (InputStream input = factory.open(file.toFile())) {
            actual = input.readAllBytes();
        }

        assertArrayEquals(expected, actual);
    }

    @Test
    void transformedLookupConstructorExecutesThroughGuardForAnOrdinaryFileRead() throws Exception {
        byte[] expected = "safe constructor handle".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        Path file = temporaryDirectory.resolve("ordinary-constructor-handle.txt");
        Files.write(file, expected);

        Class<?> isolated = new ChildFirstLoader(CallSiteFixture.class.getName(),
                ModCallSiteTransformer.transformBytes(fixtureBytes())).loadClass(CallSiteFixture.class.getName());
        byte[] actual = (byte[]) isolated.getMethod("constructorHandleRead", Path.class).invoke(null, file);

        assertArrayEquals(expected, actual);
    }

    @Test
    void modOriginCannotEvadeInstrumentationWithATrustedLookingPackage() throws Exception {
        ProtectionDomain modJar = new ProtectionDomain(
                new CodeSource(temporaryDirectory.resolve("mods/evil.jar").toUri().toURL(), (java.security.cert.Certificate[]) null),
                null);

        assertTrue(ModCallSiteTransformer.eligibleForTest("com/antirat/evasive/Payload", modJar));
        assertTrue(ModCallSiteTransformer.eligibleForTest("net/fabricmc/evasive/Payload", modJar));
        assertTrue(ModCallSiteTransformer.eligibleForTest("net/minecraft/evasive/Payload", modJar));
    }

    @Test
    void trustsAnExplicitFabricProcessedAgentOriginWithoutTrustingPackageLookalikes() throws Exception {
        ProtectionDomain processedAgent = new ProtectionDomain(
                new CodeSource(temporaryDirectory.resolve(".fabric/processedMods/antirat.jar").toUri().toURL(),
                        (java.security.cert.Certificate[]) null), null);
        ProtectionDomain lookalike = new ProtectionDomain(
                new CodeSource(temporaryDirectory.resolve("mods/antirat-lookalike.jar").toUri().toURL(),
                        (java.security.cert.Certificate[]) null), null);

        ModCallSiteTransformer.trustAgentOrigin(processedAgent);

        assertFalse(ModCallSiteTransformer.eligibleForTest("com/antirat/guard/RuntimeHooks", processedAgent));
        assertTrue(ModCallSiteTransformer.eligibleForTest("com/antirat/evasive/Payload", lookalike));
    }

    @Test
    void instrumentsDelayedExternalHelpersEvenWhenTheyImpersonatePlatformPackages() throws Exception {
        ProtectionDomain platform = new ProtectionDomain(
                new CodeSource(temporaryDirectory.resolve("libraries/minecraft-client.jar").toUri().toURL(),
                        (java.security.cert.Certificate[]) null), null);
        ProtectionDomain delayedHelper = new ProtectionDomain(
                new CodeSource(temporaryDirectory.resolve("staging/decrypted-helper.jar").toUri().toURL(),
                        (java.security.cert.Certificate[]) null), null);
        String previous = System.getProperty(AntiRatAgent.RUNTIME_READY_PROPERTY);
        try {
            ModCallSiteTransformer.trustPlatformOrigin(platform);
            System.setProperty(AntiRatAgent.RUNTIME_READY_PROPERTY, "true");

            assertFalse(ModCallSiteTransformer.eligibleForTest("net/minecraft/client/MinecraftClient", platform));
            assertTrue(ModCallSiteTransformer.eligibleForTest("com/antirat/evasive/Payload", delayedHelper));
            assertTrue(ModCallSiteTransformer.eligibleForTest("net/minecraft/evasive/Payload", delayedHelper));
            assertTrue(ModCallSiteTransformer.eligibleForTest("example/decrypted/Payload", delayedHelper));
        } finally {
            if (previous == null) System.clearProperty(AntiRatAgent.RUNTIME_READY_PROPERTY);
            else System.setProperty(AntiRatAgent.RUNTIME_READY_PROPERTY, previous);
        }
    }

    private static byte[] fixtureBytes() throws Exception {
        String resource = '/' + CallSiteFixture.class.getName().replace('.', '/') + ".class";
        try (var input = ModCallSiteTransformerTest.class.getResourceAsStream(resource)) {
            return input.readAllBytes();
        }
    }

    private static List<String> methodCalls(byte[] bytes) {
        List<String> calls = new ArrayList<>();
        new ClassReader(bytes).accept(new ClassVisitor(Opcodes.ASM9) {
            @Override
            public MethodVisitor visitMethod(int access, String name, String descriptor, String signature, String[] exceptions) {
                return new MethodVisitor(Opcodes.ASM9) {
                    @Override
                    public void visitMethodInsn(int opcode, String owner, String method, String descriptor, boolean isInterface) {
                        calls.add(owner.replace('/', '.') + '.' + method + descriptor);
                    }
                };
            }
        }, 0);
        return calls;
    }

    private static List<String> bootstrapHandles(byte[] bytes) {
        List<String> handles = new ArrayList<>();
        new ClassReader(bytes).accept(new ClassVisitor(Opcodes.ASM9) {
            @Override
            public MethodVisitor visitMethod(int access, String name, String descriptor, String signature, String[] exceptions) {
                return new MethodVisitor(Opcodes.ASM9) {
                    @Override
                    public void visitInvokeDynamicInsn(
                            String name, String descriptor, org.objectweb.asm.Handle bootstrap,
                            Object... arguments
                    ) {
                        for (Object argument : arguments) {
                            if (argument instanceof org.objectweb.asm.Handle handle) {
                                handles.add(handle.getOwner().replace('/', '.') + '.' + handle.getName()
                                        + handle.getDesc());
                            }
                        }
                    }
                };
            }
        }, 0);
        return handles;
    }

    private static List<String> constantPoolHandles(byte[] bytes) {
        List<String> handles = new ArrayList<>();
        new ClassReader(bytes).accept(new ClassVisitor(Opcodes.ASM9) {
            @Override
            public MethodVisitor visitMethod(int access, String name, String descriptor, String signature, String[] exceptions) {
                return new MethodVisitor(Opcodes.ASM9) {
                    @Override
                    public void visitLdcInsn(Object value) {
                        if (value instanceof Handle handle) {
                            handles.add(handle.getOwner().replace('/', '.') + '.' + handle.getName()
                                    + handle.getDesc());
                        }
                    }
                };
            }
        }, 0);
        return handles;
    }

    private static byte[] constantMethodHandleFixture() {
        ClassWriter writer = new ClassWriter(0);
        writer.visit(Opcodes.V21, Opcodes.ACC_PUBLIC, "fixture/ConstantHandle", null,
                "java/lang/Object", null);
        MethodVisitor method = writer.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "handle",
                "()Ljava/lang/invoke/MethodHandle;", null, null);
        method.visitCode();
        method.visitLdcInsn(new Handle(Opcodes.H_INVOKESTATIC, "java/nio/file/Files", "readAllBytes",
                "(Ljava/nio/file/Path;)[B", false));
        method.visitInsn(Opcodes.ARETURN);
        method.visitMaxs(1, 0);
        method.visitEnd();
        writer.visitEnd();
        return writer.toByteArray();
    }

    private static byte[] nettyBootstrapFixture() {
        ClassWriter writer = new ClassWriter(0);
        writer.visit(Opcodes.V21, Opcodes.ACC_PUBLIC, "fixture/NettyBootstrap", null,
                "java/lang/Object", null);
        MethodVisitor method = writer.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "connect",
                "(Lio/netty/bootstrap/Bootstrap;Ljava/lang/String;I)V", null, null);
        method.visitCode();
        method.visitVarInsn(Opcodes.ALOAD, 0);
        method.visitVarInsn(Opcodes.ALOAD, 1);
        method.visitVarInsn(Opcodes.ILOAD, 2);
        method.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "io/netty/bootstrap/Bootstrap", "connect",
                "(Ljava/lang/String;I)Lio/netty/channel/ChannelFuture;", false);
        method.visitInsn(Opcodes.POP);
        method.visitInsn(Opcodes.RETURN);
        method.visitMaxs(3, 3);
        method.visitEnd();
        writer.visitEnd();
        return writer.toByteArray();
    }

    private static byte[] credentialCarrierFixture() {
        ClassWriter writer = new ClassWriter(0);
        writer.visit(Opcodes.V21, Opcodes.ACC_PUBLIC, "net/minecraft/client/User", null,
                "java/lang/Object", null);
        MethodVisitor getter = writer.visitMethod(Opcodes.ACC_PUBLIC, "getAccessToken",
                "()Ljava/lang/String;", null, null);
        getter.visitCode();
        getter.visitLdcInsn("fixture-token");
        getter.visitInsn(Opcodes.ARETURN);
        getter.visitMaxs(1, 1);
        getter.visitEnd();

        MethodVisitor handler = writer.visitMethod(Opcodes.ACC_PRIVATE | Opcodes.ACC_SYNTHETIC,
                "handler$abc123$tokenreader$onUserConstructed",
                "(Ljava/lang/String;Ljava/lang/String;)V", null, null);
        handler.visitCode();
        handler.visitVarInsn(Opcodes.ALOAD, 0);
        handler.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "net/minecraft/client/User", "getAccessToken",
                "()Ljava/lang/String;", false);
        handler.visitInsn(Opcodes.POP);
        handler.visitInsn(Opcodes.RETURN);
        handler.visitMaxs(1, 3);
        handler.visitEnd();
        writer.visitEnd();
        return writer.toByteArray();
    }

    public static final class CallSiteFixture {
        public static byte[] read(Path path) throws Exception {
            return Files.readAllBytes(path);
        }

        public static Object reflect(Field field, Object target) throws Exception {
            return field.get(target);
        }

        public static int reflectInt(Field field, Object target) throws Exception {
            return field.getInt(target);
        }

        public static void mutate(Field field, Object target, Object value) throws Exception {
            field.set(target, value);
        }

        public static Object invoke(Method method, Object target, Object[] arguments) throws Exception {
            return method.invoke(target, arguments);
        }

        public static Object construct(Constructor<?> constructor, Object[] arguments) throws Exception {
            return constructor.newInstance(arguments);
        }

        public static List<String> lines(Path path) throws Exception {
            return Files.readAllLines(path);
        }

        public static Class<?> define(MethodHandles.Lookup lookup, byte[] bytecode) throws Exception {
            return lookup.defineClass(bytecode);
        }

        @SuppressWarnings("removal")
        public static Object unsafeRead(sun.misc.Unsafe unsafe, Object target, long offset) {
            return unsafe.getObject(target, offset);
        }

        @SuppressWarnings("removal")
        public static long unsafeOffset(sun.misc.Unsafe unsafe, Field field) {
            return unsafe.objectFieldOffset(field);
        }

        @SuppressWarnings("removal")
        public static long unsafeAllocate(sun.misc.Unsafe unsafe) {
            return unsafe.allocateMemory(8L);
        }

        @SuppressWarnings("removal")
        public static void unsafeCopyMemory(sun.misc.Unsafe unsafe, long source, long destination, long bytes) {
            unsafe.copyMemory(source, destination, bytes);
        }

        @SuppressWarnings("removal")
        public static Object unsafeAllocateInstance(sun.misc.Unsafe unsafe, Class<?> type)
                throws InstantiationException {
            return unsafe.allocateInstance(type);
        }

        @SuppressWarnings("removal")
        public static boolean unsafeCompareAndSwapObject(
                sun.misc.Unsafe unsafe, Object target, long offset, Object expected, Object replacement
        ) {
            return unsafe.compareAndSwapObject(target, offset, expected, replacement);
        }

        @SuppressWarnings("removal")
        public static void unsafePutOrderedLong(sun.misc.Unsafe unsafe, Object target, long offset, long value) {
            unsafe.putOrderedLong(target, offset, value);
        }

        public static String environment(String name) {
            return System.getenv(name);
        }

        public static java.util.Optional<String[]> processArguments(ProcessHandle.Info info) {
            return info.arguments();
        }

        public static java.io.InputStream urlStream(URL url) throws Exception {
            return url.openStream();
        }

        public static AsynchronousFileChannel asynchronousRead(Path path) throws Exception {
            return AsynchronousFileChannel.open(path, StandardOpenOption.READ);
        }

        public static List<Process> pipeline() throws Exception {
            return ProcessBuilder.startPipeline(List.of(new ProcessBuilder("definitely-not-run")));
        }

        public static Connection database(String url) throws Exception {
            return DriverManager.getConnection(url);
        }

        public static void nativeLoad(String path) {
            System.load(path);
            Runtime.getRuntime().load(path);
        }

        public static MethodHandles.Lookup lookupStatic(MethodHandles.Lookup lookup) throws Exception {
            lookup.findStatic(Files.class, "readAllBytes", MethodType.methodType(byte[].class, Path.class));
            return lookup;
        }

        public static byte[] lookupRead(Path path) throws Throwable {
            var handle = MethodHandles.lookup().findStatic(Files.class, "readAllBytes",
                    MethodType.methodType(byte[].class, Path.class));
            return (byte[]) handle.invoke(path);
        }

        public static MethodHandles.Lookup lookupGetter(MethodHandles.Lookup lookup, Class<?> owner) throws Exception {
            lookup.findGetter(owner, "value", String.class);
            return lookup;
        }

        public static PathReader methodReference() {
            return Files::readAllBytes;
        }

        public static InputFactory inputFactory() {
            return FileInputStream::new;
        }

        public static byte[] constructorHandleRead(Path path) throws Throwable {
            MethodHandle constructor = MethodHandles.lookup().findConstructor(FileInputStream.class,
                    MethodType.methodType(void.class, java.io.File.class));
            try (InputStream input = (InputStream) constructor.invoke(path.toFile())) {
                return input.readAllBytes();
            }
        }

        public static String scannerRead(Path path) throws Exception {
            try (Scanner scanner = new Scanner(path)) {
                return scanner.hasNextLine() ? scanner.nextLine() : "";
            }
        }

        public static Map<String, String> processEnvironment(ProcessBuilder builder) {
            return builder.environment();
        }

        public static Map<String, String> runtimeProperties() {
            return ManagementFactory.getRuntimeMXBean().getSystemProperties();
        }

        public static Socket fourArgumentSocket(String host, int port, java.net.InetAddress local, int localPort)
                throws Exception {
            return new Socket(host, port, local, localPort);
        }

        public static void assorted(Path path) throws Exception {
            try (FileInputStream ignored = new FileInputStream(path.toFile())) {
                new URL("https://example.invalid").openConnection();
                new ProcessBuilder("definitely-not-run").start();
                new Socket("example.invalid", 443).close();
            }
        }
    }

    @FunctionalInterface
    public interface PathReader {
        byte[] read(Path path) throws Exception;
    }

    @FunctionalInterface
    public interface InputFactory {
        FileInputStream open(java.io.File file) throws Exception;
    }

    private static final class ChildFirstLoader extends ClassLoader {
        private final String targetName;
        private final byte[] bytes;

        private ChildFirstLoader(String targetName, byte[] bytes) {
            super(ModCallSiteTransformerTest.class.getClassLoader());
            this.targetName = targetName;
            this.bytes = bytes;
        }

        @Override
        protected Class<?> loadClass(String name, boolean resolve) throws ClassNotFoundException {
            if (!name.equals(targetName)) return super.loadClass(name, resolve);
            synchronized (getClassLoadingLock(name)) {
                Class<?> loaded = findLoadedClass(name);
                if (loaded == null) loaded = defineClass(name, bytes, 0, bytes.length);
                if (resolve) resolveClass(loaded);
                return loaded;
            }
        }
    }
}
