package com.antirat.agent;

import com.antirat.scan.ModIndex;

import java.lang.instrument.Instrumentation;
import java.io.File;
import java.nio.file.Path;
import java.security.ProtectionDomain;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;

/** Java-agent entrypoint embedded in the same drop-in mod JAR. */
public final class AntiRatAgent {
    public static final String ACTIVE_PROPERTY = "antirat.agent.active";
    public static final String RUNTIME_READY_PROPERTY = "antirat.agent.runtimeReady";
    private static final AtomicBoolean INSTALLED = new AtomicBoolean();
    private static final AtomicBoolean RETRANSFORM_FAILED = new AtomicBoolean();
    private static volatile Instrumentation instrumentation;
    private static volatile boolean installedByPremain;
    private static final Set<String> TRUSTED_RUNTIME_CLASSES = Set.of(
            "com.antirat.AntiRatRuntime",
            "com.antirat.agent.AntiRatAgent",
            "com.antirat.bootstrap.AntiRatLanguageAdapter",
            "com.antirat.bootstrap.StartupCoordinator",
            "com.antirat.guard.RuntimeHooks"
    );
    private static final Set<String> TRUSTED_PLATFORM_ANCHORS = Set.of(
            "net.fabricmc.loader.api.FabricLoader",
            "net.fabricmc.loader.impl.FabricLoaderImpl",
            "net.fabricmc.loader.impl.launch.knot.KnotClassLoader",
            "net.minecraft.client.MinecraftClient",
            "net.minecraft.class_310",
            "net.minecraft.client.Minecraft",
            "com.mojang.authlib.GameProfile",
            "org.spongepowered.asm.mixin.Mixin",
            "org.objectweb.asm.ClassReader"
    );

    private AntiRatAgent() {
    }

    public static void premain(String arguments, Instrumentation instrumentation) {
        install(instrumentation, true);
    }

    public static void agentmain(String arguments, Instrumentation instrumentation) {
        install(instrumentation, false);
    }

    private static void install(Instrumentation instrumentation, boolean premain) {
        if (!INSTALLED.compareAndSet(false, true)) return;
        installedByPremain = premain;
        AntiRatAgent.instrumentation = instrumentation;
        // With dynamic attachment, Fabric may have remapped AntiRat to a processed JAR while the
        // Attach API loads agentmain from the original JAR. Trust both exact code origins before
        // retransformation so enforcement hooks can never instrument and recurse into themselves.
        ModCallSiteTransformer.trustAgentOrigin(AntiRatAgent.class.getProtectionDomain());
        trustInitialClasspathOrigins();
        for (Class<?> type : instrumentation.getAllLoadedClasses()) {
            if (TRUSTED_RUNTIME_CLASSES.contains(type.getName())) {
                ModCallSiteTransformer.trustAgentOrigin(type.getProtectionDomain());
            }
            if (TRUSTED_PLATFORM_ANCHORS.contains(type.getName())) {
                ModCallSiteTransformer.trustPlatformOrigin(type.getProtectionDomain());
            }
        }
        if (Boolean.getBoolean(RUNTIME_READY_PROPERTY)) trustIndexedPlatformOrigins();
        instrumentation.addTransformer(new ModCallSiteTransformer(), instrumentation.isRetransformClassesSupported());
        System.setProperty(ACTIVE_PROPERTY, "true");
        if (Boolean.getBoolean(RUNTIME_READY_PROPERTY)) retransformLoadedModClasses();
    }

    /**
     * The launcher's original class path is fixed before any mod code runs and contains Minecraft
     * and its libraries. Trusting those exact origins avoids instrumenting Mixin, Log4j, LWJGL,
     * and similar platform machinery. Mod and Fabric processed-mod paths are deliberately skipped;
     * a helper JAR introduced later is not in this snapshot and therefore remains instrumented.
     */
    private static void trustInitialClasspathOrigins() {
        String classPath = System.getProperty("java.class.path", "");
        for (String rawEntry : classPath.split(java.util.regex.Pattern.quote(File.pathSeparator))) {
            if (rawEntry.isBlank()) continue;
            try {
                Path entry = Path.of(rawEntry).toAbsolutePath().normalize();
                String normalized = entry.toString().replace('\\', '/').toLowerCase(java.util.Locale.ROOT);
                if (normalized.contains("/mods/") || normalized.contains("/.fabric/processedmods/")) continue;
                ModCallSiteTransformer.trustPlatformOrigin(entry.toUri());
            } catch (RuntimeException ignored) {
                // An invalid class-path entry is not a reason to make a broad trust decision.
            }
        }
    }

    /**
     * Activates broad post-startup coverage and closes classes loaded before dynamic attachment.
     *
     * <p>The supplied domain is the Fabric/Knot copy of AntiRat. A premain agent is loaded by the
     * system class loader, so passing this domain across that class-loader boundary is essential:
     * otherwise the agent can mistake the Knot copy of RuntimeHooks for an untrusted delayed
     * helper and instrument its own guard methods.</p>
     */
    public static void activateRuntimeProtection(ProtectionDomain runtimeOrigin) {
        ModCallSiteTransformer.trustAgentOrigin(runtimeOrigin);
        trustIndexedPlatformOrigins();
        Instrumentation active = instrumentation;
        if (active != null) {
            for (Class<?> type : active.getAllLoadedClasses()) {
                if (TRUSTED_RUNTIME_CLASSES.contains(type.getName())) {
                    ModCallSiteTransformer.trustAgentOrigin(type.getProtectionDomain());
                }
                if (TRUSTED_PLATFORM_ANCHORS.contains(type.getName())) {
                    ModCallSiteTransformer.trustPlatformOrigin(type.getProtectionDomain());
                }
            }
        }
        System.setProperty(RUNTIME_READY_PROPERTY, "true");
        retransformLoadedModClasses();
    }

    public static void activateRuntimeProtection() {
        activateRuntimeProtection(AntiRatAgent.class.getProtectionDomain());
    }

    private static void trustIndexedPlatformOrigins() {
        try {
            for (java.net.URI origin : ModIndex.trustedOriginUris()) {
                ModCallSiteTransformer.trustPlatformOrigin(origin);
            }
        } catch (Throwable ignored) {
            // StartupCoordinator will still supply exact mod-origin instrumentation; failure to enumerate
            // platform roots must never cause a broad trust decision.
        }
    }

    /** Dynamic attachment must relaunch under premain if any already-loaded eligible class was unmodifiable. */
    public static boolean requiresPremainRelaunch() {
        return Boolean.getBoolean(ACTIVE_PROPERTY) && !installedByPremain && RETRANSFORM_FAILED.get();
    }

    private static void retransformLoadedModClasses() {
        Instrumentation active = instrumentation;
        if (active == null || !active.isRetransformClassesSupported()) return;
        for (Class<?> type : active.getAllLoadedClasses()) {
            try {
                if (!ModCallSiteTransformer.shouldRetransform(type)) continue;
                if (!active.isModifiableClass(type)) {
                    RETRANSFORM_FAILED.set(true);
                    continue;
                }
                active.retransformClasses(type);
            } catch (Throwable failure) {
                RETRANSFORM_FAILED.set(true);
            }
        }
    }
}
