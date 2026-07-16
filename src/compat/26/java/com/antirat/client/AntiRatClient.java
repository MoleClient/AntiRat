package com.antirat.client;

import com.antirat.AntiRatRuntime;
import com.antirat.guard.NetworkGuard;
import com.antirat.model.RiskLevel;
import com.antirat.model.ThreatEvent;
import com.antirat.model.ThreatType;
import net.fabricmc.api.ClientModInitializer;
import net.minecraft.ChatFormatting;
import net.minecraft.client.Minecraft;
import net.minecraft.client.resources.sounds.SimpleSoundInstance;
import net.minecraft.network.chat.ClickEvent;
import net.minecraft.network.chat.Component;
import net.minecraft.network.chat.HoverEvent;
import net.minecraft.network.chat.MutableComponent;
import net.minecraft.sounds.SoundEvents;

import java.util.ArrayDeque;
import java.util.Deque;

/** Minecraft 26.x unobfuscated client adapter. */
public final class AntiRatClient implements ClientModInitializer {
    private static final Deque<ThreatEvent> WAITING_FOR_WORLD = new ArrayDeque<>();
    private static ThreatEvent startupPopup;
    private static int guardCheckTicks;

    @Override
    public void onInitializeClient() {
        AntiRatRuntime.initializeClient();
        NetworkGuard.install();
    }

    public static void onEndClientTick(Minecraft client) {
        WAITING_FOR_WORLD.addAll(AntiRatRuntime.drainClientEvents());
        if (++guardCheckTicks >= 100) {
            guardCheckTicks = 0;
            NetworkGuard.ensureInstalled();
        }
        if (client == null || client.level == null || client.player == null || client.gui == null) return;
        while (!WAITING_FOR_WORLD.isEmpty()) {
            ThreatEvent event = WAITING_FOR_WORLD.removeFirst();
            notifyClient(client, event);
            if (event.type() == ThreatType.MOD_QUARANTINED && event.blocked()) startupPopup = event;
            else if (startupPopup == null && event.blocked() && event.riskLevel().atLeast(RiskLevel.HIGH)) {
                startupPopup = event;
            }
        }
        if (startupPopup != null && client.gui.screen() == null) {
            ThreatEvent event = startupPopup;
            startupPopup = null;
            client.gui.setScreen(new AntiRatThreatScreen(event, null));
            if (event.type() == ThreatType.MOD_QUARANTINED
                    || event.type() == ThreatType.MOD_DEPENDENCY_DISABLED) {
                AntiRatRuntime.acknowledgePendingStartupNotice();
            }
        }
    }

    public static void openEvent(String eventId) {
        ThreatEvent event = AntiRatRuntime.eventById(eventId);
        if (event == null) {
            postSystemMessage("Event not found: " + eventId, UiColor.RED);
            return;
        }
        openPreview(event);
    }

    /** Opens a transient UI preview without publishing it as a security event. */
    public static void openPreview(ThreatEvent event) {
        Minecraft client = Minecraft.getInstance();
        if (client == null || event == null) return;
        client.execute(() -> client.gui.setScreen(new AntiRatThreatScreen(event, client.gui.screen())));
    }

    public static void postSystemMessage(String value, UiColor color) {
        Minecraft client = Minecraft.getInstance();
        if (client == null) return;
        client.execute(() -> client.gui.hud.getChat().addClientSystemMessage(Component.literal("[AntiRat] ")
                .withStyle(ChatFormatting.DARK_GRAY)
                .append(Component.literal(value).withStyle(formatting(color)))));
    }

    private static void notifyClient(Minecraft client, ThreatEvent event) {
        client.gui.hud.getChat().addClientSystemMessage(chatMessage(event));
        if (event.blocked()) {
            client.gui.hud.setOverlayMessage(Component.literal("AntiRat blocked: " + event.title())
                    .withStyle(ChatFormatting.RED), false);
            float pitch = event.riskLevel() == RiskLevel.CRITICAL ? 0.72F : 0.88F;
            client.getSoundManager().play(SimpleSoundInstance.forUI(SoundEvents.NOTE_BLOCK_BIT, pitch));
            client.getSoundManager().play(SimpleSoundInstance.forUI(SoundEvents.NOTE_BLOCK_PLING, 1.45F));
        } else if (event.riskLevel().atLeast(RiskLevel.HIGH)) {
            client.getSoundManager().play(SimpleSoundInstance.forUI(SoundEvents.NOTE_BLOCK_BELL, 1.1F));
        }
    }

    static MutableComponent chatMessage(ThreatEvent event) {
        ChatFormatting risk = switch (event.riskLevel()) {
            case CRITICAL -> ChatFormatting.DARK_RED;
            case HIGH -> ChatFormatting.RED;
            case MEDIUM -> ChatFormatting.GOLD;
            case LOW -> ChatFormatting.YELLOW;
            case INFO -> ChatFormatting.GRAY;
        };
        MutableComponent details = Component.literal(event.type() == ThreatType.MOD_QUARANTINED
                        ? " [Open threat popup]" : " [Open AntiRat log]")
                .withStyle(style -> style.withColor(ChatFormatting.AQUA).withUnderlined(true)
                        .withClickEvent(new ClickEvent.RunCommand("/antirat show " + event.id()))
                        .withHoverEvent(new HoverEvent.ShowText(Component.literal("Open this AntiRat event"))));
        return Component.literal("[AntiRat] ").withStyle(ChatFormatting.DARK_GRAY)
                .append(Component.literal((event.blocked() ? "prevented " : "flagged ")
                                + event.type().label() + " from ")
                        .withStyle(event.blocked() ? ChatFormatting.RED : ChatFormatting.GRAY))
                .append(Component.literal(event.sourceLabel()).withStyle(ChatFormatting.GRAY))
                .append(Component.literal(" | Risk: ").withStyle(ChatFormatting.DARK_GRAY))
                .append(Component.literal(event.riskLevel().label()).withStyle(risk)).append(details);
    }

    private static ChatFormatting formatting(UiColor color) {
        return switch (color) {
            case AQUA -> ChatFormatting.AQUA;
            case DARK_GRAY -> ChatFormatting.DARK_GRAY;
            case GOLD -> ChatFormatting.GOLD;
            case GRAY -> ChatFormatting.GRAY;
            case GREEN -> ChatFormatting.GREEN;
            case RED -> ChatFormatting.RED;
            case YELLOW -> ChatFormatting.YELLOW;
        };
    }
}
