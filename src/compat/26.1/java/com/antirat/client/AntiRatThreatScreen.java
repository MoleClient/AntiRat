package com.antirat.client;

import com.antirat.model.ThreatEvent;
import net.minecraft.client.Minecraft;
import net.minecraft.client.gui.screens.AlertScreen;
import net.minecraft.client.gui.screens.Screen;
import net.minecraft.network.chat.Component;

/** Popup adapter for Minecraft 26.1 through 26.1.2. */
public final class AntiRatThreatScreen extends AlertScreen {
    public AntiRatThreatScreen(ThreatEvent event, Screen parent) {
        super(() -> Minecraft.getInstance().setScreen(parent),
                Component.literal(event.blocked() ? "AntiRat — Threat prevented" : "AntiRat — Threat flagged"),
                Component.literal(details(event)), Component.literal("Close"), false);
    }

    private static String details(ThreatEvent event) {
        return event.type().label() + " | " + event.sourceLabel() + " | Risk: "
                + event.riskLevel().label() + " | " + event.summary();
    }
}
