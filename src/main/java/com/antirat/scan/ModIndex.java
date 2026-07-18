package com.antirat.scan;

import com.antirat.AntiRatRuntime;
import net.fabricmc.loader.api.FabricLoader;
import net.fabricmc.loader.api.ModContainer;

import java.io.IOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.stream.Stream;

public final class ModIndex {
    private static final int MAX_INDEXED_CLASSES = 300_000;
    private static final StackWalker WALKER = StackWalker.getInstance(StackWalker.Option.RETAIN_CLASS_REFERENCE);
    private static final AtomicBoolean INITIALIZED = new AtomicBoolean();
    private static final Map<Path, ModIdentity> PATH_OWNERS = new ConcurrentHashMap<>();
    private static final Map<String, ModIdentity> CLASS_OWNERS = new ConcurrentHashMap<>();
    private static final Map<Class<?>, ModIdentity> CLASS_CACHE = new ConcurrentHashMap<>();
    private static final Map<String, Set<Path>> MOD_ORIGINS = new ConcurrentHashMap<>();
    private static final Map<String, ModIdentity> MOD_IDENTITIES = new ConcurrentHashMap<>();
    private static final Map<Path, ModIdentity> RUNTIME_ORIGIN_OWNERS = new ConcurrentHashMap<>();
    private static final Set<Path> TRUSTED_PATHS = ConcurrentHashMap.newKeySet();

    private ModIndex() {
    }

    public static void initialize() {
        if (!INITIALIZED.compareAndSet(false, true)) return;
        registerTrustedOrigin(ModIndex.class);
        // Exact launcher-provided library artifacts used by Minecraft's own authenticated flows.
        // A mod-shaded lookalike has a different CodeSource and remains attributable to its JAR.
        registerTrustedOrigin("com.google.gson.Gson");
        registerTrustedOrigin("com.mojang.authlib.GameProfile");
        try {
            if (FabricLoader.getInstance().isDevelopmentEnvironment()) {
                Class<?> devLauncher = Class.forName("net.fabricmc.devlaunchinjector.Main", false,
                        ClassLoader.getSystemClassLoader());
                registerTrustedOrigin(devLauncher);
            }
        } catch (ClassNotFoundException | LinkageError | RuntimeException ignored) {
        }
        int indexed = 0;
        for (ModContainer container : FabricLoader.getInstance().getAllMods()) {
            String id = container.getMetadata().getId();
            boolean infrastructure = isInfrastructure(id);
            ModIdentity identity = new ModIdentity(id, container.getMetadata().getName());
            if (!infrastructure) MOD_IDENTITIES.put(id, identity);
            for (Path origin : safeOriginPaths(container)) {
                Path normalized = realOrNormalized(origin);
                if (infrastructure) TRUSTED_PATHS.add(normalized);
                else {
                    PATH_OWNERS.put(normalized, identity);
                    MOD_ORIGINS.computeIfAbsent(id, ignored -> ConcurrentHashMap.newKeySet()).add(normalized);
                }
            }
            if (infrastructure) continue;
            if (indexed >= MAX_INDEXED_CLASSES) continue;
            for (Path root : safeRootPaths(container)) {
                try (Stream<Path> paths = Files.walk(root)) {
                    List<Path> classes = paths.filter(Files::isRegularFile)
                            .filter(path -> path.toString().endsWith(".class"))
                            .limit(MAX_INDEXED_CLASSES - indexed)
                            .toList();
                    for (Path classPath : classes) {
                        String relative = root.relativize(classPath).toString().replace('\\', '/');
                        if (relative.startsWith("META-INF/versions/")) continue;
                        String className = relative.substring(0, relative.length() - ".class".length()).replace('/', '.');
                        CLASS_OWNERS.putIfAbsent(className, identity);
                        indexed++;
                    }
                } catch (IOException | RuntimeException ignored) {
                }
            }
        }
    }

    public static ModIdentity findByCurrentStack() {
        initialize();
        return WALKER.walk(frames -> mostRestrictive(frames
                .map(StackWalker.StackFrame::getDeclaringClass)
                .map(ModIndex::ownerOf)
                .filter(ModIdentity::known)
                .toList()));
    }

    /** Fast attribution for an already identified direct caller class. */
    public static ModIdentity findByClass(Class<?> type) {
        initialize();
        return type == null ? ModIdentity.UNKNOWN : ownerOf(type);
    }

    /** Resolves the mod id Mixin embeds in a copied handler name such as handler$abc$modid$hook. */
    public static ModIdentity findMergedMixinOwner(String methodName) {
        initialize();
        if (methodName == null || methodName.isBlank()) return ModIdentity.UNKNOWN;
        String normalized = methodName.toLowerCase(java.util.Locale.ROOT).replaceAll("[^a-z0-9]", "");
        ModIdentity best = ModIdentity.UNKNOWN;
        int bestLength = 0;
        for (Map.Entry<String, ModIdentity> entry : MOD_IDENTITIES.entrySet()) {
            String id = entry.getKey().toLowerCase(java.util.Locale.ROOT).replaceAll("[^a-z0-9]", "");
            if (id.length() >= 3 && id.length() > bestLength && normalized.contains(id)) {
                best = entry.getValue();
                bestLength = id.length();
            }
        }
        return best;
    }

    /** Distinguishes a platform-only call from unattributed code, which is important for fail-closed token access. */
    public static CallerContext findCredentialCaller() {
        initialize();
        return WALKER.walk(frames -> {
            boolean unknownApplicationFrame = false;
            java.util.LinkedHashMap<String, ModIdentity> sources = new java.util.LinkedHashMap<>();
            for (StackWalker.StackFrame frame : frames.toList()) {
                Class<?> type = frame.getDeclaringClass();
                ModIdentity owner = ownerOf(type);
                if (owner.known()) {
                    sources.putIfAbsent(owner.id(), owner);
                } else if (!isTrustedPlatformFrame(type)) {
                    unknownApplicationFrame = true;
                }
            }
            List<ModIdentity> attributed = List.copyOf(sources.values());
            ModIdentity primary = attributed.isEmpty() ? ModIdentity.UNKNOWN : attributed.getFirst();
            return new CallerContext(primary, attributed.isEmpty() && !unknownApplicationFrame, attributed);
        });
    }

    /**
     * Returns true when the credential accessor was entered by verified platform code itself.
     * This is intentionally based on the immediate meaningful caller, not every deeper frame:
     * a normal Minecraft authentication operation can legitimately have launcher libraries or
     * a mod-triggered game callback farther down the stack, but the token is still consumed by
     * Minecraft rather than returned to that mod.
     */
    public static boolean trustedCredentialEntryPoint(Class<?> credentialCarrier) {
        return credentialEntryPoint(credentialCarrier).trusted();
    }

    public static CredentialEntryPoint credentialEntryPoint(Class<?> credentialCarrier) {
        if (credentialCarrier == null) return new CredentialEntryPoint("<none>", false);
        initialize();
        return WALKER.walk(frames -> {
            Class<?> caller = firstCredentialCaller(credentialCarrier, frames
                    .map(StackWalker.StackFrame::getDeclaringClass)
                    .toList());
            return new CredentialEntryPoint(caller == null ? "<none>" : caller.getName(),
                    caller != null && isTrustedPlatformFrame(caller));
        });
    }

    static Class<?> firstCredentialCaller(Class<?> credentialCarrier, List<Class<?>> frames) {
        boolean carrierSeen = false;
        for (Class<?> type : frames) {
            if (isAntiRatGuardFrame(type)) continue;
            if (!carrierSeen) {
                if (type == credentialCarrier) carrierSeen = true;
                continue;
            }
            if (type == credentialCarrier || isTransparentJdkInvocationFrame(type)) continue;
            return type;
        }
        return null;
    }

    public static Optional<Path> primaryOrigin(String modId) {
        initialize();
        if (modId == null) return Optional.empty();
        Set<Path> origins = MOD_ORIGINS.get(modId);
        if (origins == null || origins.isEmpty()) return Optional.empty();
        List<Path> ordered = new ArrayList<>(origins);
        ordered.sort(Comparator.comparing((Path path) -> !Files.isRegularFile(path))
                .thenComparing(path -> path.toString().length()));
        return Optional.of(ordered.getFirst());
    }

    /** Exact infrastructure origins that the runtime transformer may leave untouched. */
    public static Set<URI> trustedOriginUris() {
        initialize();
        return TRUSTED_PATHS.stream().map(Path::toUri).collect(java.util.stream.Collectors.toUnmodifiableSet());
    }

    public static ModIdentity findByStack(StackTraceElement[] stack) {
        initialize();
        if (stack == null) return ModIdentity.UNKNOWN;
        ClassLoader loader = Thread.currentThread().getContextClassLoader();
        List<ModIdentity> sources = new ArrayList<>();
        for (StackTraceElement frame : stack) {
            ModIdentity indexed = CLASS_OWNERS.get(frame.getClassName());
            if (indexed != null) {
                sources.add(indexed);
                continue;
            }
            try {
                Class<?> type = Class.forName(frame.getClassName(), false, loader);
                ModIdentity identity = ownerOf(type);
                if (identity.known()) sources.add(identity);
            } catch (LinkageError | ClassNotFoundException | SecurityException ignored) {
            }
        }
        return mostRestrictive(sources);
    }

    private static ModIdentity mostRestrictive(List<ModIdentity> sources) {
        ModIdentity selected = ModIdentity.UNKNOWN;
        int selectedRank = Integer.MIN_VALUE;
        Set<String> seen = new java.util.HashSet<>();
        for (ModIdentity source : sources) {
            if (!source.known() || !seen.add(source.id())) continue;
            int rank = enforcementRank(source);
            if (rank > selectedRank) {
                selected = source;
                selectedRank = rank;
            }
        }
        return selected;
    }

    private static int enforcementRank(ModIdentity source) {
        if (AntiRatRuntime.runtimeLockedDown(source.id())) return 10_000;
        ScanResult result = ScanRegistry.startupResult(source.id());
        int rank = result == null ? 0 : result.score();
        if (result != null && result.highConfidence()) rank += 200;
        if (result != null && result.quarantineRecommended()) rank += 400;
        return Math.max(rank, AntiRatRuntime.riskForMod(source.id()).ordinal() * 100);
    }

    private static ModIdentity ownerOf(Class<?> type) {
        return CLASS_CACHE.computeIfAbsent(type, ignored -> {
            Path runtimeOrigin = null;
            try {
                if (type.getProtectionDomain() != null && type.getProtectionDomain().getCodeSource() != null
                        && type.getProtectionDomain().getCodeSource().getLocation() != null) {
                    URI uri = type.getProtectionDomain().getCodeSource().getLocation().toURI();
                    if ("file".equalsIgnoreCase(uri.getScheme())) {
                        runtimeOrigin = realOrNormalized(Path.of(uri));
                        ModIdentity byOrigin = PATH_OWNERS.get(runtimeOrigin);
                        if (byOrigin != null) return byOrigin;
                        if (TRUSTED_PATHS.contains(runtimeOrigin)) return ModIdentity.UNKNOWN;
                    }
                }
            } catch (Exception ignoredException) {
            }
            ModIdentity indexed = CLASS_OWNERS.getOrDefault(type.getName(), ModIdentity.UNKNOWN);
            if (!indexed.known() && runtimeOrigin != null && Files.isRegularFile(runtimeOrigin)
                    && isRuntimeDiscoverableOrigin(runtimeOrigin)) {
                indexed = RUNTIME_ORIGIN_OWNERS.computeIfAbsent(runtimeOrigin, ModIndex::inspectRuntimeOrigin);
            }
            if (indexed.known() && runtimeOrigin != null) {
                PATH_OWNERS.putIfAbsent(runtimeOrigin, indexed);
                MOD_ORIGINS.computeIfAbsent(indexed.id(), ignoredId -> ConcurrentHashMap.newKeySet())
                        .add(runtimeOrigin);
            }
            return indexed;
        });
    }

    static ModIdentity inspectRuntimeOrigin(Path source) {
        try {
            ScanResult result = new JarScanner(AntiRatRuntime.config()).scan(source);
            String declared = result.modId().toLowerCase(java.util.Locale.ROOT)
                    .replaceAll("[^a-z0-9_-]", "_");
            if (declared.isBlank() || !Character.isLetter(declared.charAt(0)) || isInfrastructure(declared)) {
                return ModIdentity.UNKNOWN;
            }
            if (declared.length() > 32) declared = declared.substring(0, 32);
            String attributedId = "runtime-" + declared + '-' + result.sha256().substring(0, 12);
            ScanRegistry.recordAs(attributedId, result);
            return new ModIdentity(attributedId, result.modName() + " (runtime-loaded)");
        } catch (IOException | RuntimeException failure) {
            return ModIdentity.UNKNOWN;
        }
    }

    private static List<Path> safeOriginPaths(ModContainer container) {
        try {
            return List.copyOf(container.getOrigin().getPaths());
        } catch (RuntimeException unsupportedOrigin) {
            List<Path> derived = new ArrayList<>();
            for (Path root : safeRootPaths(container)) {
                try {
                    Path path = pathFromRootUri(root.toUri());
                    if (path != null && !derived.contains(path)) derived.add(path);
                } catch (RuntimeException ignored) {
                }
            }
            return List.copyOf(derived);
        }
    }

    private static List<Path> safeRootPaths(ModContainer container) {
        try {
            return List.copyOf(container.getRootPaths());
        } catch (RuntimeException unavailable) {
            return List.of();
        }
    }

    static Path pathFromRootUri(URI uri) {
        if (uri == null) return null;
        try {
            if ("file".equalsIgnoreCase(uri.getScheme())) return Path.of(uri);
            String value = uri.toString();
            int file = value.indexOf("file:");
            int bang = value.indexOf("!/", Math.max(0, file));
            if (file >= 0 && bang > file) return Path.of(URI.create(value.substring(file, bang)));
        } catch (IllegalArgumentException ignored) {
        }
        return null;
    }

    private static boolean isTrustedPlatformFrame(Class<?> type) {
        if (type.getClassLoader() == null) return true;
        String moduleName = type.getModule() == null ? null : type.getModule().getName();
        if (moduleName != null && (moduleName.equals("java.base") || moduleName.startsWith("java.")
                || moduleName.startsWith("jdk."))) return true;
        try {
            if (type.getProtectionDomain() != null && type.getProtectionDomain().getCodeSource() != null
                    && type.getProtectionDomain().getCodeSource().getLocation() != null) {
                URI uri = type.getProtectionDomain().getCodeSource().getLocation().toURI();
                if ("file".equalsIgnoreCase(uri.getScheme()) && TRUSTED_PATHS.contains(realOrNormalized(Path.of(uri)))) {
                    return true;
                }
            }
        } catch (Exception ignored) {
        }
        return false;
    }

    private static boolean isAntiRatGuardFrame(Class<?> type) {
        return type.getName().startsWith("com.antirat.");
    }

    private static boolean isTransparentJdkInvocationFrame(Class<?> type) {
        if (type.getClassLoader() == null) return true;
        String name = type.getName();
        return name.startsWith("java.lang.reflect.") || name.startsWith("jdk.internal.reflect.")
                || name.startsWith("java.lang.invoke.");
    }

    static boolean isInfrastructure(String id) {
        return id.equals("a-") || id.equals("minecraft") || id.equals("java")
                || id.equals("fabricloader");
    }

    private static Path realOrNormalized(Path path) {
        try {
            return path.toRealPath();
        } catch (IOException ignored) {
            return path.toAbsolutePath().normalize();
        }
    }

    private static boolean isRuntimeDiscoverableOrigin(Path source) {
        try {
            Path gameDirectory = realOrNormalized(FabricLoader.getInstance().getGameDir());
            Path candidate = realOrNormalized(source);
            if (!candidate.startsWith(gameDirectory)) return false;
            Path quarantine = gameDirectory.resolve(".antirat").resolve("quarantine").normalize();
            return !candidate.startsWith(quarantine);
        } catch (RuntimeException failure) {
            return false;
        }
    }

    private static void registerTrustedOrigin(Class<?> type) {
        try {
            if (type.getProtectionDomain() != null && type.getProtectionDomain().getCodeSource() != null
                    && type.getProtectionDomain().getCodeSource().getLocation() != null) {
                URI uri = type.getProtectionDomain().getCodeSource().getLocation().toURI();
                if ("file".equalsIgnoreCase(uri.getScheme())) TRUSTED_PATHS.add(realOrNormalized(Path.of(uri)));
            }
        } catch (Exception ignored) {
        }
    }

    private static void registerTrustedOrigin(String className) {
        try {
            registerTrustedOrigin(Class.forName(className, false, ModIndex.class.getClassLoader()));
        } catch (ClassNotFoundException | LinkageError | RuntimeException ignored) {
        }
    }

    public record CallerContext(ModIdentity source, boolean trustedPlatformOnly, List<ModIdentity> sources) {
        public CallerContext {
            sources = List.copyOf(sources);
        }
    }

    public record CredentialEntryPoint(String className, boolean trusted) {
    }
}
