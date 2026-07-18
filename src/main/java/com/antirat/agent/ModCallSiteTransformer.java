package com.antirat.agent;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.ConstantDynamic;
import org.objectweb.asm.Handle;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;

import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.IllegalClassFormatException;
import java.net.URI;
import java.security.ProtectionDomain;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

final class ModCallSiteTransformer implements ClassFileTransformer {
    private static final String HOOKS = "com/antirat/guard/RuntimeHooks";
    private static final String[] JVM_PREFIXES = {
            "java/", "jdk/", "sun/", "com/sun/"
    };
    private static final String[] SHARED_PLATFORM_PREFIXES = {
            "com/antirat/",
            "net/minecraft/", "com/mojang/", "net/fabricmc/", "org/spongepowered/", "org/objectweb/asm/"
    };
    private static final String[] REFLECTION_LIBRARY_PREFIXES = {
            "com/google/gson/", "com/fasterxml/jackson/", "org/apache/commons/lang3/reflect/",
            "org/apache/commons/beanutils/", "kotlin/reflect/"
    };
    private static final Set<URI> AGENT_ORIGINS = ConcurrentHashMap.newKeySet();
    private static final Set<URI> PLATFORM_ORIGINS = ConcurrentHashMap.newKeySet();
    private static final byte[][] NEEDLES = {
            ascii("java/nio/file/Files"), ascii("java/nio/channels/FileChannel"),
            ascii("java/nio/channels/AsynchronousFileChannel"),
            ascii("java/nio/file/spi/FileSystemProvider"),
            ascii("java/sql/DriverManager"),
            ascii("java/io/FileInputStream"), ascii("java/io/FileReader"), ascii("java/io/RandomAccessFile"),
            ascii("java/util/Scanner"), ascii("java/lang/management/RuntimeMXBean"),
            ascii("java/net/URL"), ascii("java/net/http/HttpClient"), ascii("java/net/http/WebSocket"),
            ascii("io/netty/bootstrap/Bootstrap"),
            ascii("java/net/Socket"),
            ascii("java/net/InetAddress"), ascii("javax/net/SocketFactory"), ascii("javax/net/ssl/SSLSocketFactory"),
            ascii("java/nio/channels/SocketChannel"), ascii("java/nio/channels/AsynchronousSocketChannel"),
            ascii("java/net/DatagramSocket"),
            ascii("java/nio/channels/DatagramChannel"), ascii("java/awt/Desktop"),
            ascii("java/net/ProxySelector"), ascii("java/net/CookieHandler"),
            ascii("java/lang/ProcessHandle$Info"),
            ascii("java/lang/ProcessBuilder"), ascii("java/lang/Runtime"), ascii("java/lang/System"),
            ascii("java/lang/reflect/Field"), ascii("java/lang/reflect/Method"),
            ascii("java/lang/reflect/Constructor"), ascii("java/lang/invoke/MethodHandles"),
            ascii("java/lang/ClassLoader"), ascii("sun/misc/Unsafe"), ascii("jdk/internal/misc/Unsafe"),
            ascii("net/minecraft/client/session/Session"), ascii("net/minecraft/class_320"),
            ascii("net/minecraft/client/User"),
            ascii("com/mojang/authlib/minecraft/client/MinecraftClient"),
            ascii("com/mojang/authlib/yggdrasil/request/JoinMinecraftServerRequest")
    };

    static {
        trustAgentOrigin(AntiRatAgent.class.getProtectionDomain());
    }

    @Override
    public byte[] transform(
            Module module,
            ClassLoader loader,
            String className,
            Class<?> classBeingRedefined,
            ProtectionDomain protectionDomain,
            byte[] classfileBuffer
    ) throws IllegalClassFormatException {
        if (loader == null || className == null || classfileBuffer == null) return null;
        boolean credentialCarrier = isSessionOwner(className);
        if ((!credentialCarrier && !eligible(module, className, protectionDomain))
                || (!credentialCarrier && !containsAnyNeedle(classfileBuffer))) return null;
        try {
            return credentialCarrier
                    ? transformCredentialCarrierBytes(classfileBuffer)
                    : transformBytes(classfileBuffer);
        } catch (RuntimeException | LinkageError failure) {
            IllegalClassFormatException denied = new IllegalClassFormatException(
                    "AntiRat could not safely instrument a security-sensitive application class");
            denied.initCause(failure);
            throw denied;
        }
    }

    static boolean shouldRetransform(Class<?> type) {
        if (type == null || type.isArray() || type.isPrimitive()) return false;
        String className = type.getName().replace('.', '/');
        return isSessionOwner(className)
                || (eligible(type.getModule(), className, type.getProtectionDomain())
                && (isModOrigin(type.getProtectionDomain())
                || startsWithAny(className, REFLECTION_LIBRARY_PREFIXES)));
    }

    static boolean eligibleForTest(String className, ProtectionDomain protectionDomain) {
        return eligible(null, className, protectionDomain);
    }

    static void trustAgentOrigin(ProtectionDomain protectionDomain) {
        URI origin = originOf(protectionDomain);
        if (origin != null) AGENT_ORIGINS.add(origin);
    }

    static void trustPlatformOrigin(ProtectionDomain protectionDomain) {
        trustPlatformOrigin(originOf(protectionDomain));
    }

    static void trustPlatformOrigin(URI origin) {
        if (origin != null) PLATFORM_ORIGINS.add(origin.normalize());
    }

    private static boolean eligible(Module module, String className, ProtectionDomain protectionDomain) {
        if (className == null || isJvmModule(module) || startsWithAny(className, JVM_PREFIXES)) return false;
        // The agent origin is never eligible because RuntimeHooks would recurse into itself. The
        // explicit transform-all switch is an integration-test/debug override for every other
        // application origin, including the child JVM's initial class path.
        if (isAgentOrigin(protectionDomain)) return false;
        if (Boolean.getBoolean("antirat.agent.transformAll")) return true;
        if (isPlatformOrigin(protectionDomain)) return false;

        boolean modOrigin = isModOrigin(protectionDomain);
        if (modOrigin) return true;

        if (!Boolean.getBoolean(AntiRatAgent.RUNTIME_READY_PROPERTY)) return false;
        // Exact platform and AntiRat origins were excluded above. Package names alone are not trusted:
        // delayed/decrypted helpers routinely impersonate platform namespaces to evade transformers.
        return true;
    }

    static byte[] transformBytes(byte[] input) {
        ClassReader reader = new ClassReader(input);
        ClassWriter writer = new ClassWriter(reader, ClassWriter.COMPUTE_MAXS);
        ClassVisitor visitor = new ClassVisitor(Opcodes.ASM9, writer) {
            @Override
            public MethodVisitor visitMethod(int access, String name, String descriptor, String signature, String[] exceptions) {
                MethodVisitor delegate = super.visitMethod(access, name, descriptor, signature, exceptions);
                return new GuardingMethodVisitor(delegate);
            }
        };
        reader.accept(visitor, 0);
        return writer.toByteArray();
    }

    /**
     * Mixin handler methods are copied into their Minecraft target class. That makes ordinary
     * CodeSource/stack attribution see a trusted Minecraft class even though the handler came
     * from a mod. Guard the copied handler itself and redact credential-looking constructor
     * arguments before its first instruction can observe them.
     */
    static byte[] transformCredentialCarrierBytes(byte[] input) {
        ClassReader reader = new ClassReader(input);
        ClassWriter writer = new ClassWriter(reader, ClassWriter.COMPUTE_MAXS);
        ClassVisitor visitor = new ClassVisitor(Opcodes.ASM9, writer) {
            @Override
            public MethodVisitor visitMethod(int access, String name, String descriptor, String signature,
                                             String[] exceptions) {
                MethodVisitor delegate = super.visitMethod(access, name, descriptor, signature, exceptions);
                if (!isCopiedMixinHandler(access, name)) return delegate;
                MethodVisitor guarded = new GuardingMethodVisitor(delegate);
                return new CredentialHandlerVisitor(guarded, access, name, descriptor);
            }
        };
        reader.accept(visitor, 0);
        return writer.toByteArray();
    }

    private static boolean isCopiedMixinHandler(int access, String name) {
        if (name == null || name.startsWith("antirat$") || name.startsWith("lambda$")) return false;
        String lower = name.toLowerCase(java.util.Locale.ROOT);
        return lower.startsWith("handler$") || lower.startsWith("redirect$")
                || lower.startsWith("modify$") || lower.startsWith("wrap$")
                || ((access & Opcodes.ACC_SYNTHETIC) != 0 && name.indexOf('$') >= 0);
    }

    private static final class CredentialHandlerVisitor extends MethodVisitor {
        private final int access;
        private final String methodName;
        private final String descriptor;

        private CredentialHandlerVisitor(MethodVisitor delegate, int access, String methodName, String descriptor) {
            super(Opcodes.ASM9, delegate);
            this.access = access;
            this.methodName = methodName;
            this.descriptor = descriptor;
        }

        @Override
        public void visitCode() {
            super.visitCode();
            int local = (access & Opcodes.ACC_STATIC) == 0 ? 1 : 0;
            int stringOrdinal = 0;
            for (Type argument : Type.getArgumentTypes(descriptor)) {
                if (argument.getSort() == Type.OBJECT
                        && argument.getInternalName().equals("java/lang/String")) {
                    stringOrdinal++;
                    super.visitVarInsn(Opcodes.ALOAD, local);
                    super.visitInsn(stringOrdinal >= 2 ? Opcodes.ICONST_1 : Opcodes.ICONST_0);
                    super.visitLdcInsn(methodName);
                    super.visitMethodInsn(Opcodes.INVOKESTATIC, HOOKS, "spoofCredentialMixinArgument",
                            "(Ljava/lang/String;ZLjava/lang/String;)Ljava/lang/String;", false);
                    super.visitVarInsn(Opcodes.ASTORE, local);
                }
                local += argument.getSize();
            }
        }
    }

    private static final class GuardingMethodVisitor extends MethodVisitor {
        private GuardingMethodVisitor(MethodVisitor delegate) {
            super(Opcodes.ASM9, delegate);
        }

        @Override
        public void visitFieldInsn(int opcode, String owner, String name, String descriptor) {
            if (opcode == Opcodes.GETFIELD && isCredentialTokenField(owner, name, descriptor)) {
                super.visitLdcInsn(name);
                super.visitMethodInsn(Opcodes.INVOKESTATIC, HOOKS, "directSessionTokenField",
                        "(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/String;", false);
                return;
            }
            super.visitFieldInsn(opcode, owner, name, descriptor);
        }

        @Override
        public void visitMethodInsn(int opcode, String owner, String name, String descriptor, boolean isInterface) {
            if (rewriteMethodCall(opcode, owner, name, descriptor)) return;
            guardConstructor(owner, name, descriptor);
            super.visitMethodInsn(opcode, owner, name, descriptor, isInterface);
        }

        @Override
        public void visitInvokeDynamicInsn(
                String name, String descriptor, Handle bootstrapMethodHandle, Object... bootstrapMethodArguments
        ) {
            Object[] guardedArguments = rewriteDynamicArguments(bootstrapMethodArguments);
            super.visitInvokeDynamicInsn(name, descriptor, bootstrapMethodHandle, guardedArguments);
        }

        @Override
        public void visitLdcInsn(Object value) {
            if (value instanceof Handle handle) value = rewriteBootstrapHandle(handle);
            else if (value instanceof ConstantDynamic dynamic) value = rewriteConstantDynamic(dynamic);
            super.visitLdcInsn(value);
        }

        private boolean rewriteMethodCall(int opcode, String owner, String name, String descriptor) {
            if (opcode == Opcodes.INVOKEVIRTUAL && isSessionOwner(owner)
                    && (name.equals("getAccessToken") || name.equals("getSessionId")
                    || name.equals("method_1674") || name.equals("method_1675"))
                    && descriptor.equals("()Ljava/lang/String;")) {
                invokeStatic("directSessionTokenMethod", "(Ljava/lang/Object;)Ljava/lang/String;");
                return true;
            }
            if (opcode == Opcodes.INVOKEVIRTUAL
                    && owner.equals("com/mojang/authlib/yggdrasil/request/JoinMinecraftServerRequest")
                    && (name.equals("accessToken") || name.equals("toString"))
                    && descriptor.equals("()Ljava/lang/String;")) {
                invokeStatic("directSessionTokenMethod", "(Ljava/lang/Object;)Ljava/lang/String;");
                return true;
            }
            if (opcode == Opcodes.INVOKEVIRTUAL && owner.equals("io/netty/bootstrap/Bootstrap")
                    && (name.equals("connect") || name.equals("remoteAddress"))) {
                if (descriptor.startsWith("(Ljava/lang/String;I)")) {
                    super.visitInsn(Opcodes.DUP2);
                    invokeStatic("checkHostPort", "(Ljava/lang/String;I)V");
                } else if (descriptor.startsWith("(Ljava/net/SocketAddress;)")) {
                    super.visitInsn(Opcodes.DUP);
                    invokeStatic("checkSocketAddress", "(Ljava/net/SocketAddress;)V");
                } else if (descriptor.startsWith("(Ljava/net/SocketAddress;Ljava/net/SocketAddress;)")) {
                    super.visitInsn(Opcodes.DUP2);
                    super.visitInsn(Opcodes.POP);
                    invokeStatic("checkSocketAddress", "(Ljava/net/SocketAddress;)V");
                }
            }
            if (opcode == Opcodes.INVOKESTATIC && owner.equals("java/nio/file/Files")) {
                String hook = switch (name + descriptor) {
                    case "newInputStream(Ljava/nio/file/Path;[Ljava/nio/file/OpenOption;)Ljava/io/InputStream;" -> "filesNewInputStream";
                    case "readAllBytes(Ljava/nio/file/Path;)[B" -> "filesReadAllBytes";
                    case "readString(Ljava/nio/file/Path;)Ljava/lang/String;",
                            "readString(Ljava/nio/file/Path;Ljava/nio/charset/Charset;)Ljava/lang/String;" -> "filesReadString";
                    case "newBufferedReader(Ljava/nio/file/Path;)Ljava/io/BufferedReader;",
                            "newBufferedReader(Ljava/nio/file/Path;Ljava/nio/charset/Charset;)Ljava/io/BufferedReader;" -> "filesNewBufferedReader";
                    case "readAllLines(Ljava/nio/file/Path;)Ljava/util/List;",
                            "readAllLines(Ljava/nio/file/Path;Ljava/nio/charset/Charset;)Ljava/util/List;" -> "filesReadAllLines";
                    case "lines(Ljava/nio/file/Path;)Ljava/util/stream/Stream;",
                            "lines(Ljava/nio/file/Path;Ljava/nio/charset/Charset;)Ljava/util/stream/Stream;" -> "filesLines";
                    case "copy(Ljava/nio/file/Path;Ljava/io/OutputStream;)J",
                            "copy(Ljava/nio/file/Path;Ljava/nio/file/Path;[Ljava/nio/file/CopyOption;)Ljava/nio/file/Path;" -> "filesCopy";
                    case "mismatch(Ljava/nio/file/Path;Ljava/nio/file/Path;)J" -> "filesMismatch";
                    case "createLink(Ljava/nio/file/Path;Ljava/nio/file/Path;)Ljava/nio/file/Path;" -> "filesCreateLink";
                    case "createSymbolicLink(Ljava/nio/file/Path;Ljava/nio/file/Path;[Ljava/nio/file/attribute/FileAttribute;)Ljava/nio/file/Path;" -> "filesCreateSymbolicLink";
                    case "move(Ljava/nio/file/Path;Ljava/nio/file/Path;[Ljava/nio/file/CopyOption;)Ljava/nio/file/Path;" -> "filesMove";
                    case "newByteChannel(Ljava/nio/file/Path;[Ljava/nio/file/OpenOption;)Ljava/nio/channels/SeekableByteChannel;",
                            "newByteChannel(Ljava/nio/file/Path;Ljava/util/Set;[Ljava/nio/file/attribute/FileAttribute;)Ljava/nio/channels/SeekableByteChannel;" -> "filesNewByteChannel";
                    default -> null;
                };
                if (hook != null) {
                    super.visitMethodInsn(Opcodes.INVOKESTATIC, HOOKS, hook, descriptor, false);
                    return true;
                }
            }
            if (opcode == Opcodes.INVOKESTATIC && owner.equals("java/sql/DriverManager")
                    && name.equals("getConnection")) {
                if (descriptor.equals("(Ljava/lang/String;)Ljava/sql/Connection;")
                        || descriptor.equals("(Ljava/lang/String;Ljava/util/Properties;)Ljava/sql/Connection;")
                        || descriptor.equals("(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/sql/Connection;")) {
                    invokeStatic("driverManagerGetConnection", descriptor);
                    return true;
                }
            }
            if (opcode == Opcodes.INVOKESTATIC && owner.equals("java/nio/channels/FileChannel") && name.equals("open")) {
                if (descriptor.equals("(Ljava/nio/file/Path;[Ljava/nio/file/OpenOption;)Ljava/nio/channels/FileChannel;")
                        || descriptor.equals("(Ljava/nio/file/Path;Ljava/util/Set;[Ljava/nio/file/attribute/FileAttribute;)Ljava/nio/channels/FileChannel;")) {
                    super.visitMethodInsn(Opcodes.INVOKESTATIC, HOOKS, "fileChannelOpen", descriptor, false);
                    return true;
                }
            }
            if (opcode == Opcodes.INVOKESTATIC && owner.equals("java/nio/channels/AsynchronousFileChannel")
                    && name.equals("open")) {
                if (descriptor.equals("(Ljava/nio/file/Path;[Ljava/nio/file/OpenOption;)Ljava/nio/channels/AsynchronousFileChannel;")
                        || descriptor.equals("(Ljava/nio/file/Path;Ljava/util/Set;Ljava/util/concurrent/ExecutorService;[Ljava/nio/file/attribute/FileAttribute;)Ljava/nio/channels/AsynchronousFileChannel;")) {
                    invokeStatic("asynchronousFileChannelOpen", descriptor);
                    return true;
                }
            }
            if (opcode == Opcodes.INVOKEVIRTUAL && owner.equals("java/nio/file/spi/FileSystemProvider")) {
                String hook = switch (name + descriptor) {
                    case "newInputStream(Ljava/nio/file/Path;[Ljava/nio/file/OpenOption;)Ljava/io/InputStream;" -> "providerNewInputStream";
                    case "newByteChannel(Ljava/nio/file/Path;Ljava/util/Set;[Ljava/nio/file/attribute/FileAttribute;)Ljava/nio/channels/SeekableByteChannel;" -> "providerNewByteChannel";
                    case "newFileChannel(Ljava/nio/file/Path;Ljava/util/Set;[Ljava/nio/file/attribute/FileAttribute;)Ljava/nio/channels/FileChannel;" -> "providerNewFileChannel";
                    case "newAsynchronousFileChannel(Ljava/nio/file/Path;Ljava/util/Set;Ljava/util/concurrent/ExecutorService;[Ljava/nio/file/attribute/FileAttribute;)Ljava/nio/channels/AsynchronousFileChannel;" -> "providerNewAsynchronousFileChannel";
                    default -> null;
                };
                if (hook != null) {
                    invokeStatic(hook, prependReceiver(owner, descriptor));
                    return true;
                }
            }
            if (opcode == Opcodes.INVOKESTATIC && owner.equals("java/nio/channels/SocketChannel")
                    && name.equals("open")
                    && descriptor.equals("(Ljava/net/SocketAddress;)Ljava/nio/channels/SocketChannel;")) {
                invokeStatic("socketChannelOpen", descriptor);
                return true;
            }
            if (opcode == Opcodes.INVOKEVIRTUAL && owner.equals("java/net/URL") && name.equals("openConnection")) {
                if (descriptor.equals("()Ljava/net/URLConnection;")) {
                    invokeStatic("urlOpenConnection", "(Ljava/net/URL;)Ljava/net/URLConnection;");
                    return true;
                }
                if (descriptor.equals("(Ljava/net/Proxy;)Ljava/net/URLConnection;")) {
                    invokeStatic("urlOpenConnection", "(Ljava/net/URL;Ljava/net/Proxy;)Ljava/net/URLConnection;");
                    return true;
                }
            }
            if (opcode == Opcodes.INVOKEVIRTUAL && owner.equals("java/net/URL")) {
                String hook = switch (name + descriptor) {
                    case "openStream()Ljava/io/InputStream;" -> "urlOpenStream";
                    case "getContent()Ljava/lang/Object;", "getContent([Ljava/lang/Class;)Ljava/lang/Object;" -> "urlGetContent";
                    default -> null;
                };
                if (hook != null) {
                    invokeStatic(hook, prependReceiver(owner, descriptor));
                    return true;
                }
            }
            if (opcode == Opcodes.INVOKEVIRTUAL && owner.equals("java/net/http/HttpClient")) {
                if (name.equals("send") && descriptor.equals("(Ljava/net/http/HttpRequest;Ljava/net/http/HttpResponse$BodyHandler;)Ljava/net/http/HttpResponse;")) {
                    invokeStatic("httpSend", prependReceiver(owner, descriptor));
                    return true;
                }
                if (name.equals("sendAsync") && (descriptor.equals("(Ljava/net/http/HttpRequest;Ljava/net/http/HttpResponse$BodyHandler;)Ljava/util/concurrent/CompletableFuture;")
                        || descriptor.equals("(Ljava/net/http/HttpRequest;Ljava/net/http/HttpResponse$BodyHandler;Ljava/net/http/HttpResponse$PushPromiseHandler;)Ljava/util/concurrent/CompletableFuture;"))) {
                    invokeStatic("httpSendAsync", prependReceiver(owner, descriptor));
                    return true;
                }
            }
            if (opcode == Opcodes.INVOKEINTERFACE && owner.equals("java/net/http/WebSocket$Builder")
                    && name.equals("buildAsync")
                    && descriptor.equals("(Ljava/net/URI;Ljava/net/http/WebSocket$Listener;)Ljava/util/concurrent/CompletableFuture;")) {
                invokeStatic("webSocketBuildAsync", prependReceiver(owner, descriptor));
                return true;
            }
            if (opcode == Opcodes.INVOKEVIRTUAL && owner.equals("java/net/Socket") && name.equals("connect")) {
                if (descriptor.equals("(Ljava/net/SocketAddress;)V") || descriptor.equals("(Ljava/net/SocketAddress;I)V")) {
                    invokeStatic("socketConnect", prependReceiver(owner, descriptor));
                    return true;
                }
            }
            if (opcode == Opcodes.INVOKEVIRTUAL && owner.equals("java/nio/channels/SocketChannel") && name.equals("connect")
                    && descriptor.equals("(Ljava/net/SocketAddress;)Z")) {
                invokeStatic("socketChannelConnect", prependReceiver(owner, descriptor));
                return true;
            }
            if (opcode == Opcodes.INVOKEVIRTUAL && owner.equals("java/nio/channels/AsynchronousSocketChannel")
                    && name.equals("connect")) {
                if (descriptor.equals("(Ljava/net/SocketAddress;)Ljava/util/concurrent/Future;")
                        || descriptor.equals("(Ljava/net/SocketAddress;Ljava/lang/Object;Ljava/nio/channels/CompletionHandler;)V")) {
                    invokeStatic("asynchronousSocketConnect", prependReceiver(owner, descriptor));
                    return true;
                }
            }
            if (opcode == Opcodes.INVOKEVIRTUAL && owner.equals("java/net/DatagramSocket") && name.equals("connect")) {
                if (descriptor.equals("(Ljava/net/SocketAddress;)V")) {
                    invokeStatic("datagramConnect", prependReceiver(owner, descriptor));
                    return true;
                }
                if (descriptor.equals("(Ljava/net/InetAddress;I)V")) {
                    invokeStatic("datagramConnect", prependReceiver(owner, descriptor));
                    return true;
                }
            }
            if (opcode == Opcodes.INVOKEVIRTUAL && owner.equals("java/net/DatagramSocket") && name.equals("send")
                    && descriptor.equals("(Ljava/net/DatagramPacket;)V")) {
                invokeStatic("datagramSend", prependReceiver(owner, descriptor));
                return true;
            }
            if (opcode == Opcodes.INVOKEVIRTUAL && owner.equals("java/nio/channels/DatagramChannel")
                    && name.equals("send")
                    && descriptor.equals("(Ljava/nio/ByteBuffer;Ljava/net/SocketAddress;)I")) {
                invokeStatic("datagramChannelSend", prependReceiver(owner, descriptor));
                return true;
            }
            if (opcode == Opcodes.INVOKEVIRTUAL && owner.equals("java/nio/channels/DatagramChannel")
                    && name.equals("connect")
                    && descriptor.equals("(Ljava/net/SocketAddress;)Ljava/nio/channels/DatagramChannel;")) {
                invokeStatic("datagramChannelConnect", prependReceiver(owner, descriptor));
                return true;
            }
            if (opcode == Opcodes.INVOKEVIRTUAL
                    && (owner.equals("javax/net/SocketFactory") || owner.equals("javax/net/ssl/SSLSocketFactory"))
                    && name.equals("createSocket")) {
                String hookDescriptor = switch (descriptor) {
                    case "(Ljava/lang/String;I)Ljava/net/Socket;",
                            "(Ljava/net/InetAddress;I)Ljava/net/Socket;",
                            "(Ljava/lang/String;ILjava/net/InetAddress;I)Ljava/net/Socket;",
                            "(Ljava/net/InetAddress;ILjava/net/InetAddress;I)Ljava/net/Socket;" ->
                            "(Ljavax/net/SocketFactory;" + descriptor.substring(1);
                    default -> null;
                };
                if (hookDescriptor != null) {
                    invokeStatic("socketFactoryCreateSocket", hookDescriptor);
                    return true;
                }
            }
            if (opcode == Opcodes.INVOKESTATIC && owner.equals("java/net/InetAddress")) {
                if (name.equals("getByName") && descriptor.equals("(Ljava/lang/String;)Ljava/net/InetAddress;")) {
                    invokeStatic("inetAddressGetByName", descriptor);
                    return true;
                }
                if (name.equals("getAllByName") && descriptor.equals("(Ljava/lang/String;)[Ljava/net/InetAddress;")) {
                    invokeStatic("inetAddressGetAllByName", descriptor);
                    return true;
                }
            }
            if (opcode == Opcodes.INVOKEVIRTUAL && owner.equals("java/awt/Desktop") && name.equals("browse")
                    && descriptor.equals("(Ljava/net/URI;)V")) {
                invokeStatic("desktopBrowse", prependReceiver(owner, descriptor));
                return true;
            }
            if (opcode == Opcodes.INVOKESTATIC && owner.equals("java/net/ProxySelector")
                    && name.equals("setDefault") && descriptor.equals("(Ljava/net/ProxySelector;)V")) {
                invokeStatic("proxySelectorSetDefault", descriptor);
                return true;
            }
            if (opcode == Opcodes.INVOKESTATIC && owner.equals("java/net/CookieHandler")
                    && name.equals("setDefault") && descriptor.equals("(Ljava/net/CookieHandler;)V")) {
                invokeStatic("cookieHandlerSetDefault", descriptor);
                return true;
            }
            if (opcode == Opcodes.INVOKEVIRTUAL && owner.equals("java/lang/ProcessBuilder") && name.equals("start")
                    && descriptor.equals("()Ljava/lang/Process;")) {
                invokeStatic("processStart", "(Ljava/lang/ProcessBuilder;)Ljava/lang/Process;");
                return true;
            }
            if (opcode == Opcodes.INVOKEVIRTUAL && owner.equals("java/lang/ProcessBuilder")
                    && name.equals("environment") && descriptor.equals("()Ljava/util/Map;")) {
                invokeStatic("processBuilderEnvironment", "(Ljava/lang/ProcessBuilder;)Ljava/util/Map;");
                return true;
            }
            if (opcode == Opcodes.INVOKEINTERFACE && owner.equals("java/lang/management/RuntimeMXBean")) {
                if (name.equals("getInputArguments") && descriptor.equals("()Ljava/util/List;")) {
                    invokeStatic("runtimeMxBeanGetInputArguments",
                            "(Ljava/lang/management/RuntimeMXBean;)Ljava/util/List;");
                    return true;
                }
                if (name.equals("getSystemProperties") && descriptor.equals("()Ljava/util/Map;")) {
                    invokeStatic("runtimeMxBeanGetSystemProperties",
                            "(Ljava/lang/management/RuntimeMXBean;)Ljava/util/Map;");
                    return true;
                }
            }
            if (opcode == Opcodes.INVOKESTATIC && owner.equals("java/lang/ProcessBuilder")
                    && name.equals("startPipeline")
                    && descriptor.equals("(Ljava/util/List;)Ljava/util/List;")) {
                invokeStatic("processStartPipeline", descriptor);
                return true;
            }
            if (opcode == Opcodes.INVOKEVIRTUAL && owner.equals("java/lang/Runtime") && name.equals("exec")) {
                invokeStatic("runtimeExec", prependReceiver(owner, descriptor));
                return true;
            }
            if (opcode == Opcodes.INVOKEVIRTUAL && owner.equals("java/lang/Runtime")
                    && name.equals("load") && descriptor.equals("(Ljava/lang/String;)V")) {
                invokeStatic("runtimeLoad", prependReceiver(owner, descriptor));
                return true;
            }
            if (opcode == Opcodes.INVOKEVIRTUAL && owner.equals("java/lang/Runtime")
                    && name.equals("loadLibrary") && descriptor.equals("(Ljava/lang/String;)V")) {
                invokeStatic("runtimeLoadLibrary", prependReceiver(owner, descriptor));
                return true;
            }
            if (opcode == Opcodes.INVOKESTATIC && owner.equals("java/lang/System")) {
                if (name.equals("load") && descriptor.equals("(Ljava/lang/String;)V")) {
                    invokeStatic("systemLoad", descriptor);
                    return true;
                }
                if (name.equals("loadLibrary") && descriptor.equals("(Ljava/lang/String;)V")) {
                    invokeStatic("systemLoadLibrary", descriptor);
                    return true;
                }
                String hook = switch (name + descriptor) {
                    case "getenv(Ljava/lang/String;)Ljava/lang/String;", "getenv()Ljava/util/Map;" -> "systemGetenv";
                    case "getProperty(Ljava/lang/String;)Ljava/lang/String;",
                            "getProperty(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;" -> "systemGetProperty";
                    case "getProperties()Ljava/util/Properties;" -> "systemGetProperties";
                    default -> null;
                };
                if (hook != null) {
                    invokeStatic(hook, descriptor);
                    return true;
                }
            }
            if (opcode == Opcodes.INVOKEINTERFACE && owner.equals("java/lang/ProcessHandle$Info")) {
                if (name.equals("arguments") && descriptor.equals("()Ljava/util/Optional;")) {
                    invokeStatic("processInfoArguments", "(Ljava/lang/ProcessHandle$Info;)Ljava/util/Optional;");
                    return true;
                }
                if (name.equals("commandLine") && descriptor.equals("()Ljava/util/Optional;")) {
                    invokeStatic("processInfoCommandLine", "(Ljava/lang/ProcessHandle$Info;)Ljava/util/Optional;");
                    return true;
                }
            }
            if (opcode == Opcodes.INVOKEVIRTUAL && owner.equals("java/lang/reflect/Field") && name.equals("get")
                    && descriptor.equals("(Ljava/lang/Object;)Ljava/lang/Object;")) {
                invokeStatic("reflectiveFieldGet", "(Ljava/lang/reflect/Field;Ljava/lang/Object;)Ljava/lang/Object;");
                return true;
            }
            if (opcode == Opcodes.INVOKEVIRTUAL && owner.equals("java/lang/reflect/Field")) {
                String hook = switch (name + descriptor) {
                    case "getBoolean(Ljava/lang/Object;)Z" -> "reflectiveFieldGetBoolean";
                    case "getByte(Ljava/lang/Object;)B" -> "reflectiveFieldGetByte";
                    case "getChar(Ljava/lang/Object;)C" -> "reflectiveFieldGetChar";
                    case "getShort(Ljava/lang/Object;)S" -> "reflectiveFieldGetShort";
                    case "getInt(Ljava/lang/Object;)I" -> "reflectiveFieldGetInt";
                    case "getLong(Ljava/lang/Object;)J" -> "reflectiveFieldGetLong";
                    case "getFloat(Ljava/lang/Object;)F" -> "reflectiveFieldGetFloat";
                    case "getDouble(Ljava/lang/Object;)D" -> "reflectiveFieldGetDouble";
                    case "set(Ljava/lang/Object;Ljava/lang/Object;)V" -> "reflectiveFieldSet";
                    case "setBoolean(Ljava/lang/Object;Z)V" -> "reflectiveFieldSetBoolean";
                    case "setByte(Ljava/lang/Object;B)V" -> "reflectiveFieldSetByte";
                    case "setChar(Ljava/lang/Object;C)V" -> "reflectiveFieldSetChar";
                    case "setShort(Ljava/lang/Object;S)V" -> "reflectiveFieldSetShort";
                    case "setInt(Ljava/lang/Object;I)V" -> "reflectiveFieldSetInt";
                    case "setLong(Ljava/lang/Object;J)V" -> "reflectiveFieldSetLong";
                    case "setFloat(Ljava/lang/Object;F)V" -> "reflectiveFieldSetFloat";
                    case "setDouble(Ljava/lang/Object;D)V" -> "reflectiveFieldSetDouble";
                    case "setAccessible(Z)V" -> "reflectiveFieldSetAccessible";
                    case "trySetAccessible()Z" -> "reflectiveFieldTrySetAccessible";
                    default -> null;
                };
                if (hook != null) {
                    invokeStatic(hook, prependReceiver(owner, descriptor));
                    return true;
                }
            }
            if (opcode == Opcodes.INVOKEVIRTUAL && owner.equals("java/lang/reflect/Method")
                    && name.equals("invoke")
                    && descriptor.equals("(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;")) {
                invokeStatic("reflectiveMethodInvoke",
                        "(Ljava/lang/reflect/Method;Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;");
                return true;
            }
            if (opcode == Opcodes.INVOKEVIRTUAL && owner.equals("java/lang/reflect/Constructor")
                    && name.equals("newInstance")
                    && descriptor.equals("([Ljava/lang/Object;)Ljava/lang/Object;")) {
                invokeStatic("reflectiveConstructorNewInstance",
                        "(Ljava/lang/reflect/Constructor;[Ljava/lang/Object;)Ljava/lang/Object;");
                return true;
            }
            if (opcode == Opcodes.INVOKESTATIC && owner.equals("java/lang/invoke/MethodHandles")
                    && name.equals("privateLookupIn")
                    && descriptor.equals("(Ljava/lang/Class;Ljava/lang/invoke/MethodHandles$Lookup;)Ljava/lang/invoke/MethodHandles$Lookup;")) {
                invokeStatic("privateLookupIn", descriptor);
                return true;
            }
            if (opcode == Opcodes.INVOKEVIRTUAL && owner.equals("java/lang/invoke/MethodHandles$Lookup")) {
                String hook = switch (name + descriptor) {
                    case "findStatic(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/invoke/MethodType;)Ljava/lang/invoke/MethodHandle;" ->
                            "lookupFindStatic";
                    case "findVirtual(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/invoke/MethodType;)Ljava/lang/invoke/MethodHandle;" ->
                            "lookupFindVirtual";
                    case "findSpecial(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/invoke/MethodType;Ljava/lang/Class;)Ljava/lang/invoke/MethodHandle;" ->
                            "lookupFindSpecial";
                    case "findConstructor(Ljava/lang/Class;Ljava/lang/invoke/MethodType;)Ljava/lang/invoke/MethodHandle;" ->
                            "lookupFindConstructor";
                    case "unreflect(Ljava/lang/reflect/Method;)Ljava/lang/invoke/MethodHandle;" ->
                            "lookupUnreflect";
                    case "unreflectSpecial(Ljava/lang/reflect/Method;Ljava/lang/Class;)Ljava/lang/invoke/MethodHandle;" ->
                            "lookupUnreflectSpecial";
                    case "unreflectConstructor(Ljava/lang/reflect/Constructor;)Ljava/lang/invoke/MethodHandle;" ->
                            "lookupUnreflectConstructor";
                    case "findGetter(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/Class;)Ljava/lang/invoke/MethodHandle;" ->
                            "lookupFindGetter";
                    case "findSetter(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/Class;)Ljava/lang/invoke/MethodHandle;" ->
                            "lookupFindSetter";
                    case "findStaticGetter(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/Class;)Ljava/lang/invoke/MethodHandle;" ->
                            "lookupFindStaticGetter";
                    case "findStaticSetter(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/Class;)Ljava/lang/invoke/MethodHandle;" ->
                            "lookupFindStaticSetter";
                    case "unreflectGetter(Ljava/lang/reflect/Field;)Ljava/lang/invoke/MethodHandle;" ->
                            "lookupUnreflectGetter";
                    case "unreflectSetter(Ljava/lang/reflect/Field;)Ljava/lang/invoke/MethodHandle;" ->
                            "lookupUnreflectSetter";
                    case "findVarHandle(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/Class;)Ljava/lang/invoke/VarHandle;" ->
                            "lookupFindVarHandle";
                    case "findStaticVarHandle(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/Class;)Ljava/lang/invoke/VarHandle;" ->
                            "lookupFindStaticVarHandle";
                    case "unreflectVarHandle(Ljava/lang/reflect/Field;)Ljava/lang/invoke/VarHandle;" ->
                            "lookupUnreflectVarHandle";
                    default -> null;
                };
                if (hook != null) {
                    invokeStatic(hook, prependReceiver(owner, descriptor));
                    return true;
                }
            }
            if ((owner.equals("sun/misc/Unsafe") || owner.equals("jdk/internal/misc/Unsafe"))
                    && (name.equals("objectFieldOffset") || name.equals("staticFieldOffset")
                    || name.equals("staticFieldBase"))) {
                if (descriptor.startsWith("(Ljava/lang/reflect/Field;)")) {
                    super.visitInsn(Opcodes.DUP);
                    invokeStatic("guardUnsafeField", "(Ljava/lang/reflect/Field;)V");
                } else if (descriptor.startsWith("(Ljava/lang/Class;Ljava/lang/String;)")) {
                    super.visitInsn(Opcodes.DUP2);
                    invokeStatic("guardUnsafeField", "(Ljava/lang/Class;Ljava/lang/String;)V");
                }
            }
            if (opcode == Opcodes.INVOKEVIRTUAL && owner.equals("sun/misc/Unsafe")) {
                String hook = unsafeVirtualHook(name, descriptor);
                if (hook == null) hook = switch (name + descriptor) {
                    case "getObject(Ljava/lang/Object;J)Ljava/lang/Object;" -> "unsafeGetObject";
                    case "getObjectVolatile(Ljava/lang/Object;J)Ljava/lang/Object;" -> "unsafeGetObjectVolatile";
                    case "putObject(Ljava/lang/Object;JLjava/lang/Object;)V" -> "unsafePutObject";
                    case "putObjectVolatile(Ljava/lang/Object;JLjava/lang/Object;)V" -> "unsafePutObjectVolatile";
                    case "putOrderedObject(Ljava/lang/Object;JLjava/lang/Object;)V" -> "unsafePutOrderedObject";
                    case "compareAndSwapObject(Ljava/lang/Object;JLjava/lang/Object;Ljava/lang/Object;)Z" ->
                            "unsafeCompareAndSwapObject";
                    case "getAndSetObject(Ljava/lang/Object;JLjava/lang/Object;)Ljava/lang/Object;" ->
                            "unsafeGetAndSetObject";
                    case "allocateInstance(Ljava/lang/Class;)Ljava/lang/Object;" -> "unsafeAllocateInstance";
                    default -> null;
                };
                if (hook != null) {
                    invokeStatic(hook, prependReceiver(owner, descriptor));
                    return true;
                }
            }
            if ((owner.equals("sun/misc/Unsafe") || owner.equals("jdk/internal/misc/Unsafe"))
                    && isDangerousUnsafeOperation(owner, name, descriptor)) {
                invokeStatic("guardUnsafeOperation", "()V");
            }
            if ((name.startsWith("defineClass") || name.startsWith("defineHiddenClass"))
                    && (owner.equals("java/lang/ClassLoader")
                    || owner.equals("java/lang/invoke/MethodHandles$Lookup")
                    || owner.endsWith("ClassLoader"))) {
                invokeStatic("guardDynamicCode", "()V");
            }
            return false;
        }

        private Handle rewriteBootstrapHandle(Handle handle) {
            String owner = handle.getOwner();
            String name = handle.getName();
            String descriptor = handle.getDesc();
            int tag = handle.getTag();
            String hook = null;
            String hookDescriptor = descriptor;

            if (tag == Opcodes.H_NEWINVOKESPECIAL && name.equals("<init>")) {
                hook = bootstrapConstructorHook(owner, descriptor);
                if (hook != null) hookDescriptor = constructorFactoryDescriptor(owner, descriptor);
            } else if (tag == Opcodes.H_INVOKESTATIC && owner.equals("java/nio/file/Files")) {
                hook = switch (name + descriptor) {
                    case "newInputStream(Ljava/nio/file/Path;[Ljava/nio/file/OpenOption;)Ljava/io/InputStream;" -> "filesNewInputStream";
                    case "readAllBytes(Ljava/nio/file/Path;)[B" -> "filesReadAllBytes";
                    case "readString(Ljava/nio/file/Path;)Ljava/lang/String;",
                            "readString(Ljava/nio/file/Path;Ljava/nio/charset/Charset;)Ljava/lang/String;" -> "filesReadString";
                    case "newBufferedReader(Ljava/nio/file/Path;)Ljava/io/BufferedReader;",
                            "newBufferedReader(Ljava/nio/file/Path;Ljava/nio/charset/Charset;)Ljava/io/BufferedReader;" -> "filesNewBufferedReader";
                    case "readAllLines(Ljava/nio/file/Path;)Ljava/util/List;",
                            "readAllLines(Ljava/nio/file/Path;Ljava/nio/charset/Charset;)Ljava/util/List;" -> "filesReadAllLines";
                    case "lines(Ljava/nio/file/Path;)Ljava/util/stream/Stream;",
                            "lines(Ljava/nio/file/Path;Ljava/nio/charset/Charset;)Ljava/util/stream/Stream;" -> "filesLines";
                    case "copy(Ljava/nio/file/Path;Ljava/io/OutputStream;)J",
                            "copy(Ljava/nio/file/Path;Ljava/nio/file/Path;[Ljava/nio/file/CopyOption;)Ljava/nio/file/Path;" -> "filesCopy";
                    case "mismatch(Ljava/nio/file/Path;Ljava/nio/file/Path;)J" -> "filesMismatch";
                    case "move(Ljava/nio/file/Path;Ljava/nio/file/Path;[Ljava/nio/file/CopyOption;)Ljava/nio/file/Path;" -> "filesMove";
                    case "newByteChannel(Ljava/nio/file/Path;[Ljava/nio/file/OpenOption;)Ljava/nio/channels/SeekableByteChannel;",
                            "newByteChannel(Ljava/nio/file/Path;Ljava/util/Set;[Ljava/nio/file/attribute/FileAttribute;)Ljava/nio/channels/SeekableByteChannel;" -> "filesNewByteChannel";
                    default -> null;
                };
            } else if (tag == Opcodes.H_INVOKESTATIC && owner.equals("java/nio/channels/FileChannel")) {
                if (name.equals("open") && (descriptor.equals("(Ljava/nio/file/Path;[Ljava/nio/file/OpenOption;)Ljava/nio/channels/FileChannel;")
                        || descriptor.equals("(Ljava/nio/file/Path;Ljava/util/Set;[Ljava/nio/file/attribute/FileAttribute;)Ljava/nio/channels/FileChannel;"))) {
                    hook = "fileChannelOpen";
                }
            } else if (tag == Opcodes.H_INVOKESTATIC
                    && owner.equals("java/nio/channels/AsynchronousFileChannel")) {
                if (name.equals("open") && (descriptor.equals("(Ljava/nio/file/Path;[Ljava/nio/file/OpenOption;)Ljava/nio/channels/AsynchronousFileChannel;")
                        || descriptor.equals("(Ljava/nio/file/Path;Ljava/util/Set;Ljava/util/concurrent/ExecutorService;[Ljava/nio/file/attribute/FileAttribute;)Ljava/nio/channels/AsynchronousFileChannel;"))) {
                    hook = "asynchronousFileChannelOpen";
                }
            } else if (tag == Opcodes.H_INVOKESTATIC && owner.equals("java/lang/System")) {
                hook = switch (name + descriptor) {
                    case "getenv(Ljava/lang/String;)Ljava/lang/String;", "getenv()Ljava/util/Map;" -> "systemGetenv";
                    case "getProperty(Ljava/lang/String;)Ljava/lang/String;",
                            "getProperty(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;" -> "systemGetProperty";
                    case "getProperties()Ljava/util/Properties;" -> "systemGetProperties";
                    case "load(Ljava/lang/String;)V" -> "systemLoad";
                    case "loadLibrary(Ljava/lang/String;)V" -> "systemLoadLibrary";
                    default -> null;
                };
            } else if (tag == Opcodes.H_INVOKESTATIC && owner.equals("java/sql/DriverManager")
                    && name.equals("getConnection")) {
                if (descriptor.equals("(Ljava/lang/String;)Ljava/sql/Connection;")
                        || descriptor.equals("(Ljava/lang/String;Ljava/util/Properties;)Ljava/sql/Connection;")
                        || descriptor.equals("(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/sql/Connection;")) {
                    hook = "driverManagerGetConnection";
                }
            } else if (tag == Opcodes.H_INVOKESTATIC && owner.equals("java/lang/ProcessBuilder")
                    && name.equals("startPipeline")
                    && descriptor.equals("(Ljava/util/List;)Ljava/util/List;")) {
                hook = "processStartPipeline";
            } else if (tag == Opcodes.H_INVOKESTATIC && owner.equals("java/net/InetAddress")) {
                hook = switch (name + descriptor) {
                    case "getByName(Ljava/lang/String;)Ljava/net/InetAddress;" -> "inetAddressGetByName";
                    case "getAllByName(Ljava/lang/String;)[Ljava/net/InetAddress;" -> "inetAddressGetAllByName";
                    default -> null;
                };
            } else if (tag == Opcodes.H_INVOKESTATIC && owner.equals("java/net/ProxySelector")
                    && name.equals("setDefault")
                    && descriptor.equals("(Ljava/net/ProxySelector;)V")) {
                hook = "proxySelectorSetDefault";
            } else if (tag == Opcodes.H_INVOKESTATIC && owner.equals("java/net/CookieHandler")
                    && name.equals("setDefault")
                    && descriptor.equals("(Ljava/net/CookieHandler;)V")) {
                hook = "cookieHandlerSetDefault";
            } else if (isVirtualHandle(tag) && owner.equals("sun/misc/Unsafe")
                    && unsafeVirtualHook(name, descriptor) != null) {
                hook = unsafeVirtualHook(name, descriptor);
                hookDescriptor = prependReceiver(owner, descriptor);
            } else if (isVirtualHandle(tag) && isUnsafeOwner(owner)
                    && isDangerousUnsafeOperation(owner, name, descriptor)) {
                // A dangerous Unsafe method reference cannot preserve its original signature while
                // also delegating safely: replace it with a fail-closed handle. Lambda linkage or
                // invokeExact will stop before the raw-memory operation can execute.
                return new Handle(Opcodes.H_INVOKESTATIC, HOOKS, "guardUnsafeOperation", "()V", false);
            } else if (isVirtualHandle(tag)) {
                hook = bootstrapVirtualHook(owner, name, descriptor);
                if (hook != null) hookDescriptor = prependReceiver(owner, descriptor);
            }

            if (hook == null) return handle;
            return new Handle(Opcodes.H_INVOKESTATIC, HOOKS, hook, hookDescriptor, false);
        }

        private ConstantDynamic rewriteConstantDynamic(ConstantDynamic dynamic) {
            Object[] arguments = new Object[dynamic.getBootstrapMethodArgumentCount()];
            for (int index = 0; index < arguments.length; index++) {
                Object argument = dynamic.getBootstrapMethodArgument(index);
                if (argument instanceof Handle handle) argument = rewriteBootstrapHandle(handle);
                else if (argument instanceof ConstantDynamic nested) argument = rewriteConstantDynamic(nested);
                arguments[index] = argument;
            }
            return new ConstantDynamic(dynamic.getName(), dynamic.getDescriptor(),
                    dynamic.getBootstrapMethod(), arguments);
        }

        private Object[] rewriteDynamicArguments(Object[] input) {
            Object[] guarded = input.clone();
            for (int index = 0; index < guarded.length; index++) {
                if (guarded[index] instanceof Handle handle) guarded[index] = rewriteBootstrapHandle(handle);
                else if (guarded[index] instanceof ConstantDynamic dynamic) {
                    guarded[index] = rewriteConstantDynamic(dynamic);
                }
            }
            return guarded;
        }

        private String bootstrapVirtualHook(String owner, String name, String descriptor) {
            if (owner.equals("sun/misc/Unsafe")) {
                String guardedMemory = unsafeVirtualHook(name, descriptor);
                if (guardedMemory != null) return guardedMemory;
                return switch (name + descriptor) {
                    case "objectFieldOffset(Ljava/lang/reflect/Field;)J" -> "unsafeObjectFieldOffset";
                    case "staticFieldOffset(Ljava/lang/reflect/Field;)J" -> "unsafeStaticFieldOffset";
                    case "staticFieldBase(Ljava/lang/reflect/Field;)Ljava/lang/Object;" -> "unsafeStaticFieldBase";
                    case "getObject(Ljava/lang/Object;J)Ljava/lang/Object;" -> "unsafeGetObject";
                    case "getObjectVolatile(Ljava/lang/Object;J)Ljava/lang/Object;" -> "unsafeGetObjectVolatile";
                    case "putObject(Ljava/lang/Object;JLjava/lang/Object;)V" -> "unsafePutObject";
                    case "putObjectVolatile(Ljava/lang/Object;JLjava/lang/Object;)V" -> "unsafePutObjectVolatile";
                    case "putOrderedObject(Ljava/lang/Object;JLjava/lang/Object;)V" -> "unsafePutOrderedObject";
                    case "compareAndSwapObject(Ljava/lang/Object;JLjava/lang/Object;Ljava/lang/Object;)Z" ->
                            "unsafeCompareAndSwapObject";
                    case "getAndSetObject(Ljava/lang/Object;JLjava/lang/Object;)Ljava/lang/Object;" ->
                            "unsafeGetAndSetObject";
                    case "allocateInstance(Ljava/lang/Class;)Ljava/lang/Object;" -> "unsafeAllocateInstance";
                    default -> null;
                };
            }
            if (owner.equals("java/net/URL")) {
                return switch (name + descriptor) {
                    case "openConnection()Ljava/net/URLConnection;",
                            "openConnection(Ljava/net/Proxy;)Ljava/net/URLConnection;" -> "urlOpenConnection";
                    case "openStream()Ljava/io/InputStream;" -> "urlOpenStream";
                    case "getContent()Ljava/lang/Object;", "getContent([Ljava/lang/Class;)Ljava/lang/Object;" -> "urlGetContent";
                    default -> null;
                };
            }
            if (owner.equals("com/mojang/authlib/yggdrasil/request/JoinMinecraftServerRequest")
                    && (name.equals("accessToken") || name.equals("toString"))
                    && descriptor.equals("()Ljava/lang/String;")) {
                return "directSessionTokenMethod";
            }
            if (isSessionOwner(owner)
                    && (name.equals("getAccessToken") || name.equals("getSessionId")
                    || name.equals("method_1674") || name.equals("method_1675"))
                    && descriptor.equals("()Ljava/lang/String;")) {
                return "directSessionTokenMethod";
            }
            if (owner.equals("java/lang/ProcessBuilder") && name.equals("start")
                    && descriptor.equals("()Ljava/lang/Process;")) return "processStart";
            if (owner.equals("java/lang/ProcessBuilder") && name.equals("environment")
                    && descriptor.equals("()Ljava/util/Map;")) return "processBuilderEnvironment";
            if (owner.equals("java/lang/management/RuntimeMXBean")) {
                if (name.equals("getInputArguments") && descriptor.equals("()Ljava/util/List;")) {
                    return "runtimeMxBeanGetInputArguments";
                }
                if (name.equals("getSystemProperties") && descriptor.equals("()Ljava/util/Map;")) {
                    return "runtimeMxBeanGetSystemProperties";
                }
            }
            if (owner.equals("java/lang/Runtime") && name.equals("exec")) return "runtimeExec";
            if (owner.equals("java/lang/Runtime") && name.equals("load")
                    && descriptor.equals("(Ljava/lang/String;)V")) return "runtimeLoad";
            if (owner.equals("java/lang/Runtime") && name.equals("loadLibrary")
                    && descriptor.equals("(Ljava/lang/String;)V")) return "runtimeLoadLibrary";
            if (owner.equals("java/lang/reflect/Field")) {
                return switch (name + descriptor) {
                    case "get(Ljava/lang/Object;)Ljava/lang/Object;" -> "reflectiveFieldGet";
                    case "getBoolean(Ljava/lang/Object;)Z" -> "reflectiveFieldGetBoolean";
                    case "getByte(Ljava/lang/Object;)B" -> "reflectiveFieldGetByte";
                    case "getChar(Ljava/lang/Object;)C" -> "reflectiveFieldGetChar";
                    case "getShort(Ljava/lang/Object;)S" -> "reflectiveFieldGetShort";
                    case "getInt(Ljava/lang/Object;)I" -> "reflectiveFieldGetInt";
                    case "getLong(Ljava/lang/Object;)J" -> "reflectiveFieldGetLong";
                    case "getFloat(Ljava/lang/Object;)F" -> "reflectiveFieldGetFloat";
                    case "getDouble(Ljava/lang/Object;)D" -> "reflectiveFieldGetDouble";
                    case "set(Ljava/lang/Object;Ljava/lang/Object;)V" -> "reflectiveFieldSet";
                    case "setBoolean(Ljava/lang/Object;Z)V" -> "reflectiveFieldSetBoolean";
                    case "setByte(Ljava/lang/Object;B)V" -> "reflectiveFieldSetByte";
                    case "setChar(Ljava/lang/Object;C)V" -> "reflectiveFieldSetChar";
                    case "setShort(Ljava/lang/Object;S)V" -> "reflectiveFieldSetShort";
                    case "setInt(Ljava/lang/Object;I)V" -> "reflectiveFieldSetInt";
                    case "setLong(Ljava/lang/Object;J)V" -> "reflectiveFieldSetLong";
                    case "setFloat(Ljava/lang/Object;F)V" -> "reflectiveFieldSetFloat";
                    case "setDouble(Ljava/lang/Object;D)V" -> "reflectiveFieldSetDouble";
                    case "setAccessible(Z)V" -> "reflectiveFieldSetAccessible";
                    case "trySetAccessible()Z" -> "reflectiveFieldTrySetAccessible";
                    default -> null;
                };
            }
            if (owner.equals("java/lang/reflect/Method") && name.equals("invoke")
                    && descriptor.equals("(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;")) {
                return "reflectiveMethodInvoke";
            }
            if (owner.equals("java/lang/reflect/Constructor") && name.equals("newInstance")
                    && descriptor.equals("([Ljava/lang/Object;)Ljava/lang/Object;")) {
                return "reflectiveConstructorNewInstance";
            }
            if (owner.equals("java/net/Socket") && name.equals("connect")) return "socketConnect";
            if (owner.equals("java/net/DatagramSocket")) {
                if (name.equals("send")) return "datagramSend";
                if (name.equals("connect")) return "datagramConnect";
            }
            if (owner.equals("java/awt/Desktop") && name.equals("browse")) return "desktopBrowse";
            if (owner.equals("java/net/http/HttpClient")) {
                if (name.equals("send")) return "httpSend";
                if (name.equals("sendAsync")) return "httpSendAsync";
            }
            return null;
        }

        private static String unsafeVirtualHook(String name, String descriptor) {
            return switch (name + descriptor) {
                case "copyMemory(JJJ)V",
                        "copyMemory(Ljava/lang/Object;JLjava/lang/Object;JJ)V" -> "unsafeCopyMemory";
                case "setMemory(JJB)V",
                        "setMemory(Ljava/lang/Object;JJB)V" -> "unsafeSetMemory";
                case "allocateMemory(J)J" -> "unsafeAllocateMemory";
                case "reallocateMemory(JJ)J" -> "unsafeReallocateMemory";
                case "freeMemory(J)V" -> "unsafeFreeMemory";
                case "getAddress(J)J" -> "unsafeGetAddress";
                case "putAddress(JJ)V" -> "unsafePutAddress";
                default -> null;
            };
        }

        private boolean isVirtualHandle(int tag) {
            return tag == Opcodes.H_INVOKEVIRTUAL || tag == Opcodes.H_INVOKEINTERFACE
                    || tag == Opcodes.H_INVOKESPECIAL;
        }

        private void guardConstructor(String owner, String name, String descriptor) {
            if (!name.equals("<init>")) return;
            if ((owner.equals("java/io/FileInputStream") || owner.equals("java/io/FileReader"))
                    && descriptor.equals("(Ljava/lang/String;)V")) {
                invokeStatic("guardFileRead", "(Ljava/lang/String;)Ljava/lang/String;");
            } else if ((owner.equals("java/io/FileInputStream") || owner.equals("java/io/FileReader"))
                    && descriptor.equals("(Ljava/io/File;)V")) {
                invokeStatic("guardFileRead", "(Ljava/io/File;)Ljava/io/File;");
            } else if (owner.equals("java/io/FileReader")
                    && (descriptor.equals("(Ljava/lang/String;Ljava/nio/charset/Charset;)V")
                    || descriptor.equals("(Ljava/io/File;Ljava/nio/charset/Charset;)V"))) {
                super.visitInsn(Opcodes.SWAP);
                invokeStatic("guardFileRead", descriptor.startsWith("(Ljava/io/File;")
                        ? "(Ljava/io/File;)Ljava/io/File;" : "(Ljava/lang/String;)Ljava/lang/String;");
                super.visitInsn(Opcodes.SWAP);
            } else if (owner.equals("java/io/RandomAccessFile")
                    && (descriptor.equals("(Ljava/lang/String;Ljava/lang/String;)V")
                    || descriptor.equals("(Ljava/io/File;Ljava/lang/String;)V"))) {
                super.visitInsn(Opcodes.SWAP);
                invokeStatic("guardFileRead", descriptor.startsWith("(Ljava/io/File;")
                        ? "(Ljava/io/File;)Ljava/io/File;" : "(Ljava/lang/String;)Ljava/lang/String;");
                super.visitInsn(Opcodes.SWAP);
            } else if (owner.equals("java/util/Scanner") && (descriptor.equals("(Ljava/io/File;)V")
                    || descriptor.equals("(Ljava/nio/file/Path;)V"))) {
                invokeStatic("guardFileRead", descriptor.startsWith("(Ljava/io/File;")
                        ? "(Ljava/io/File;)Ljava/io/File;" : "(Ljava/nio/file/Path;)Ljava/nio/file/Path;");
            } else if (owner.equals("java/util/Scanner") && (descriptor.equals("(Ljava/io/File;Ljava/lang/String;)V")
                    || descriptor.equals("(Ljava/io/File;Ljava/nio/charset/Charset;)V")
                    || descriptor.equals("(Ljava/nio/file/Path;Ljava/lang/String;)V")
                    || descriptor.equals("(Ljava/nio/file/Path;Ljava/nio/charset/Charset;)V"))) {
                super.visitInsn(Opcodes.SWAP);
                invokeStatic("guardFileRead", descriptor.startsWith("(Ljava/io/File;")
                        ? "(Ljava/io/File;)Ljava/io/File;" : "(Ljava/nio/file/Path;)Ljava/nio/file/Path;");
                super.visitInsn(Opcodes.SWAP);
            } else if (owner.equals("java/net/Socket") && descriptor.equals("(Ljava/lang/String;I)V")) {
                super.visitInsn(Opcodes.DUP2);
                invokeStatic("checkHostPort", "(Ljava/lang/String;I)V");
            } else if (owner.equals("java/net/Socket") && descriptor.equals("(Ljava/net/InetAddress;I)V")) {
                super.visitInsn(Opcodes.DUP2);
                invokeStatic("checkHostPort", "(Ljava/net/InetAddress;I)V");
            } else if (owner.equals("java/net/Socket")
                    && (descriptor.equals("(Ljava/lang/String;ILjava/net/InetAddress;I)V")
                    || descriptor.equals("(Ljava/net/InetAddress;ILjava/net/InetAddress;I)V"))) {
                // Duplicate the remote host/port pair from beneath the local bind pair.
                super.visitInsn(Opcodes.DUP2_X2);
                super.visitInsn(Opcodes.POP2);
                super.visitInsn(Opcodes.DUP2_X2);
                invokeStatic("checkHostPort", descriptor.startsWith("(Ljava/lang/String;")
                        ? "(Ljava/lang/String;I)V" : "(Ljava/net/InetAddress;I)V");
            }
        }

        private String bootstrapConstructorHook(String owner, String descriptor) {
            if (owner.equals("java/io/FileInputStream") && (descriptor.equals("(Ljava/lang/String;)V")
                    || descriptor.equals("(Ljava/io/File;)V"))) return "fileInputStreamCreate";
            if (owner.equals("java/io/FileReader") && Set.of(
                    "(Ljava/lang/String;)V", "(Ljava/io/File;)V",
                    "(Ljava/lang/String;Ljava/nio/charset/Charset;)V",
                    "(Ljava/io/File;Ljava/nio/charset/Charset;)V").contains(descriptor)) {
                return "fileReaderCreate";
            }
            if (owner.equals("java/io/RandomAccessFile") && (descriptor.equals(
                    "(Ljava/lang/String;Ljava/lang/String;)V")
                    || descriptor.equals("(Ljava/io/File;Ljava/lang/String;)V"))) {
                return "randomAccessFileCreate";
            }
            if (owner.equals("java/util/Scanner") && Set.of(
                    "(Ljava/io/File;)V", "(Ljava/io/File;Ljava/lang/String;)V",
                    "(Ljava/io/File;Ljava/nio/charset/Charset;)V", "(Ljava/nio/file/Path;)V",
                    "(Ljava/nio/file/Path;Ljava/lang/String;)V",
                    "(Ljava/nio/file/Path;Ljava/nio/charset/Charset;)V").contains(descriptor)) {
                return "scannerCreate";
            }
            if (owner.equals("java/net/Socket") && Set.of(
                    "(Ljava/lang/String;I)V", "(Ljava/net/InetAddress;I)V",
                    "(Ljava/lang/String;ILjava/net/InetAddress;I)V",
                    "(Ljava/net/InetAddress;ILjava/net/InetAddress;I)V").contains(descriptor)) {
                return "socketCreate";
            }
            return null;
        }

        private void invokeStatic(String name, String descriptor) {
            super.visitMethodInsn(Opcodes.INVOKESTATIC, HOOKS, name, descriptor, false);
        }
    }

    private static String prependReceiver(String owner, String descriptor) {
        return "(L" + owner + ';' + descriptor.substring(1);
    }

    private static String constructorFactoryDescriptor(String owner, String descriptor) {
        int end = descriptor.lastIndexOf(')');
        return descriptor.substring(0, end + 1) + 'L' + owner + ';';
    }

    private static boolean isSessionOwner(String owner) {
        return owner.equals("net/minecraft/client/session/Session")
                || owner.equals("net/minecraft/class_320")
                || owner.equals("net/minecraft/client/User");
    }

    private static boolean isCredentialTokenField(String owner, String name, String descriptor) {
        if (!descriptor.equals("Ljava/lang/String;")) return false;
        if (isSessionOwner(owner)) return name.equals("accessToken") || name.equals("field_1983");
        return (owner.equals("com/mojang/authlib/minecraft/client/MinecraftClient")
                || owner.equals("com/mojang/authlib/yggdrasil/request/JoinMinecraftServerRequest"))
                && name.equals("accessToken");
    }

    private static boolean isUnsafeOwner(String owner) {
        return owner.equals("sun/misc/Unsafe") || owner.equals("jdk/internal/misc/Unsafe");
    }

    private static boolean isDangerousUnsafeOperation(String owner, String name, String descriptor) {
        if (!isUnsafeOwner(owner)) return false;
        if (name.equals("objectFieldOffset") || name.equals("staticFieldOffset")
                || name.equals("staticFieldBase")) return false;
        // jdk.internal.misc.Unsafe has a much larger, unstable surface and cannot be safely linked
        // from this Java agent. Ordinary mod libraries use the supported sun.misc facade instead.
        if (owner.equals("jdk/internal/misc/Unsafe")) return true;
        if (name.startsWith("define") || name.equals("allocateMemory") || name.equals("reallocateMemory")
                || name.equals("freeMemory") || name.equals("setMemory") || name.equals("copyMemory")
                || name.equals("getAddress") || name.equals("putAddress")) return true;
        // Primitive raw-address overloads start with a long address. Object-relative overloads
        // start with Object and are constrained by guarded field-offset acquisition.
        return descriptor.startsWith("(J") && (name.startsWith("get") || name.startsWith("put"));
    }

    private static boolean startsWithAny(String className, String[] prefixes) {
        for (String prefix : prefixes) if (className.startsWith(prefix)) return true;
        return false;
    }

    private static boolean isJvmModule(Module module) {
        if (module == null || !module.isNamed()) return false;
        String name = module.getName();
        return name != null && (name.equals("java.base") || name.startsWith("java.") || name.startsWith("jdk."));
    }

    private static boolean isAgentOrigin(ProtectionDomain protectionDomain) {
        URI candidate = originOf(protectionDomain);
        return candidate != null && AGENT_ORIGINS.contains(candidate);
    }

    private static boolean isPlatformOrigin(ProtectionDomain protectionDomain) {
        URI candidate = originOf(protectionDomain);
        return candidate != null && PLATFORM_ORIGINS.contains(candidate);
    }

    private static boolean isModOrigin(ProtectionDomain protectionDomain) {
        try {
            if (protectionDomain == null || protectionDomain.getCodeSource() == null
                    || protectionDomain.getCodeSource().getLocation() == null) return false;
            String path = protectionDomain.getCodeSource().getLocation().toURI().getPath();
            if (path == null) return false;
            String lower = path.replace('\\', '/').toLowerCase(java.util.Locale.ROOT);
            return lower.contains("/mods/") || lower.contains("/.fabric/processedmods/")
                    || lower.contains("/build/classes/java/runtimefixture/");
        } catch (Exception ignored) {
            return false;
        }
    }

    private static boolean isRuntimeApplicationOrigin(ProtectionDomain protectionDomain) {
        URI origin = originOf(protectionDomain);
        if (origin == null) return true;
        if (!"file".equalsIgnoreCase(origin.getScheme())) return false;
        try {
            String path = java.nio.file.Path.of(origin).toAbsolutePath().normalize().toString()
                    .replace('\\', '/').toLowerCase(java.util.Locale.ROOT);
            String working = java.nio.file.Path.of(System.getProperty("user.dir", "."))
                    .toAbsolutePath().normalize().toString().replace('\\', '/').toLowerCase(java.util.Locale.ROOT);
            return path.equals(working) || path.startsWith(working.endsWith("/") ? working : working + '/')
                    || path.contains("/mods/") || path.contains("/.fabric/processedmods/");
        } catch (RuntimeException ignored) {
            return false;
        }
    }

    private static URI originOf(Class<?> type) {
        return type == null ? null : originOf(type.getProtectionDomain());
    }

    private static URI originOf(ProtectionDomain protectionDomain) {
        try {
            if (protectionDomain == null || protectionDomain.getCodeSource() == null
                    || protectionDomain.getCodeSource().getLocation() == null) return null;
            return protectionDomain.getCodeSource().getLocation().toURI().normalize();
        } catch (Exception ignored) {
            return null;
        }
    }

    private static boolean containsAnyNeedle(byte[] haystack) {
        for (byte[] needle : NEEDLES) if (contains(haystack, needle)) return true;
        return false;
    }

    private static boolean contains(byte[] haystack, byte[] needle) {
        outer:
        for (int index = 0; index <= haystack.length - needle.length; index++) {
            for (int offset = 0; offset < needle.length; offset++) {
                if (haystack[index + offset] != needle[offset]) continue outer;
            }
            return true;
        }
        return false;
    }

    private static byte[] ascii(String value) {
        return value.getBytes(java.nio.charset.StandardCharsets.US_ASCII);
    }
}
