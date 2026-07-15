package com.antirat.guard;

import com.antirat.AntiRatRuntime;

import java.net.CookieHandler;
import java.net.ProxySelector;
public final class NetworkGuard {
    private NetworkGuard() {
    }

    public static synchronized void install() {
        ensureInstalled();
        AntiRatRuntime.LOGGER.info("AntiRat network guard installed");
    }

    public static synchronized void ensureInstalled() {
        ProxySelector currentProxySelector = ProxySelector.getDefault();
        if (!(currentProxySelector instanceof GuardedProxySelector)) {
            ProxySelector.setDefault(new GuardedProxySelector(currentProxySelector));
        }
        CookieHandler currentCookieHandler = CookieHandler.getDefault();
        if (!(currentCookieHandler instanceof GuardedCookieHandler)) {
            CookieHandler.setDefault(new GuardedCookieHandler(currentCookieHandler));
        }
    }
}
