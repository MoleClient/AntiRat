package com.antirat.bootstrap;

import net.fabricmc.loader.api.LanguageAdapter;
import net.fabricmc.loader.api.LanguageAdapterException;
import net.fabricmc.loader.api.ModContainer;

/**
 * Fabric constructs language adapters during Loader freeze, before mixin configuration plugins
 * and preLaunch entrypoints. Defining this otherwise-unused adapter gives AntiRat the earliest
 * executable hook available to a normal drop-in Fabric mod.
 */
public final class AntiRatLanguageAdapter implements LanguageAdapter {
    public AntiRatLanguageAdapter() {
        StartupCoordinator.runOnce("language-adapter");
    }

    @Override
    public <T> T create(ModContainer mod, String value, Class<T> type) throws LanguageAdapterException {
        return LanguageAdapter.getDefault().create(mod, value, type);
    }
}
