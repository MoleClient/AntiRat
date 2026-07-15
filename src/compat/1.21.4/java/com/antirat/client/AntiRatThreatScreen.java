package com.antirat.client;

import com.antirat.model.ThreatEvent;
import net.minecraft.client.MinecraftClient;
import net.minecraft.client.gui.screen.NoticeScreen;
import net.minecraft.client.gui.screen.Screen;
import net.minecraft.text.Text;

/** Stable built-in popup adapter for Minecraft 1.21.4. */
public final class AntiRatThreatScreen extends NoticeScreen {
    public AntiRatThreatScreen(ThreatEvent event, Screen parent) {
        super(() -> MinecraftClient.getInstance().setScreen(parent),
                Text.literal(event.blocked() ? "AntiRat — Threat prevented" : "AntiRat — Threat flagged"),
                Text.literal(details(event)), Text.literal("Close"), false);
    }

    private static String details(ThreatEvent event) {
        return event.type().label() + " | " + event.sourceLabel() + " | Risk: "
                + event.riskLevel().label() + " | " + event.summary();
    }
}
