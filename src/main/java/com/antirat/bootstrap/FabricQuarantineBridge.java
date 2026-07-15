package com.antirat.bootstrap;

import net.fabricmc.loader.impl.FabricLoaderImpl;
import net.fabricmc.loader.impl.ModContainerImpl;

import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/** Removes already-discovered quarantined containers before Fabric registers their entrypoints. */
final class FabricQuarantineBridge {
    private FabricQuarantineBridge() {
    }

    static boolean suppressBeforeEntrypointRegistration(Set<String> blockedModIds) {
        if (blockedModIds == null || blockedModIds.isEmpty()) return true;
        Set<String> normalized = blockedModIds.stream()
                .filter(value -> value != null && !value.isBlank())
                .map(value -> value.toLowerCase(Locale.ROOT))
                .collect(java.util.stream.Collectors.toUnmodifiableSet());
        if (normalized.isEmpty()) return true;

        try {
            FabricLoaderImpl loader = FabricLoaderImpl.INSTANCE;
            List<ModContainerImpl> current = loader.getModsInternal();
            List<ModContainerImpl> filtered = new ArrayList<>(current.size());
            int suppressed = 0;
            for (ModContainerImpl container : current) {
                if (!normalized.contains(container.getMetadata().getId().toLowerCase(Locale.ROOT))) {
                    filtered.add(container);
                    continue;
                }
                suppressPendingLanguageAdapters(container);
                suppressed++;
            }
            if (suppressed == 0) return false;

            // AntiRat runs while Fabric is iterating the original list in setupLanguageAdapters().
            // Replacing the field (rather than mutating that list) avoids a fail-fast iterator.
            Field mods = FabricLoaderImpl.class.getDeclaredField("mods");
            mods.setAccessible(true);
            mods.set(loader, filtered);

            // Optional integrations must not see a physically removed mod as active.
            Field modMap = FabricLoaderImpl.class.getDeclaredField("modMap");
            modMap.setAccessible(true);
            Object rawMap = modMap.get(loader);
            if (rawMap instanceof Map<?, ?> map) {
                @SuppressWarnings("unchecked")
                Map<String, ModContainerImpl> mutable = (Map<String, ModContainerImpl>) map;
                mutable.entrySet().removeIf(entry -> normalized.contains(entry.getKey().toLowerCase(Locale.ROOT))
                        || normalized.contains(entry.getValue().getMetadata().getId().toLowerCase(Locale.ROOT)));
            }
            return true;
        } catch (ReflectiveOperationException | RuntimeException failure) {
            System.err.println("[AntiRat] Could not suppress quarantined Fabric entrypoints: "
                    + failure.getClass().getSimpleName() + ": " + failure.getMessage());
            return false;
        }
    }

    private static void suppressPendingLanguageAdapters(ModContainerImpl container)
            throws ReflectiveOperationException {
        Map<String, String> adapters = container.getInfo().getLanguageAdapterDefinitions();
        if (adapters.isEmpty()) return;
        Object metadata = container.getInfo();
        Field field = findField(metadata.getClass(), "languageAdapters");
        field.setAccessible(true);
        field.set(metadata, Map.of());
        if (!container.getInfo().getLanguageAdapterDefinitions().isEmpty()) {
            throw new IllegalStateException("language adapters remained active for "
                    + container.getMetadata().getId());
        }
    }

    private static Field findField(Class<?> type, String name) throws NoSuchFieldException {
        for (Class<?> current = type; current != null; current = current.getSuperclass()) {
            try {
                return current.getDeclaredField(name);
            } catch (NoSuchFieldException ignored) {
            }
        }
        throw new NoSuchFieldException(type.getName() + '.' + name);
    }
}
