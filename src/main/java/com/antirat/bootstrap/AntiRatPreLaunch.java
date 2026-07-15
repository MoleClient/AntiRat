package com.antirat.bootstrap;

import net.fabricmc.loader.api.entrypoint.PreLaunchEntrypoint;

public final class AntiRatPreLaunch implements PreLaunchEntrypoint {
    @Override
    public void onPreLaunch() {
        StartupCoordinator.runOnce("preLaunch");
    }
}
