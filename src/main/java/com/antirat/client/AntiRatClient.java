package com.antirat.client;

import com.antirat.AntiRatRuntime;
import com.antirat.guard.NetworkGuard;
import com.antirat.model.RiskLevel;
import com.antirat.model.ThreatEvent;
import com.antirat.model.ThreatType;
import net.fabricmc.api.ClientModInitializer;
import net.minecraft.client.MinecraftClient;
import net.minecraft.client.sound.PositionedSoundInstance;
import net.minecraft.sound.SoundEvents;
import net.minecraft.text.ClickEvent;
import net.minecraft.text.HoverEvent;
import net.minecraft.text.MutableText;
import net.minecraft.text.Text;
import net.minecraft.util.Formatting;

import java.util.ArrayDeque;
import java.util.Deque;

public final class AntiRatClient implements ClientModInitializer {
    private static final Deque<ThreatEvent> WAITING_FOR_WORLD = new ArrayDeque<>();
    private static ThreatEvent startupPopup;
    private static int guardCheckTicks;

    @Override
    public void onInitializeClient() {
        AntiRatRuntime.initializeClient();
        NetworkGuard.install();

    }

    public static void onEndClientTick(MinecraftClient client) {
        WAITING_FOR_WORLD.addAll(AntiRatRuntime.drainClientEvents());
        if (++guardCheckTicks >= 100) {
            guardCheckTicks = 0;
            NetworkGuard.ensureInstalled();
        }
        if (client == null || client.world == null || client.player == null || client.inGameHud == null) return;

        while (!WAITING_FOR_WORLD.isEmpty()) {
            ThreatEvent event = WAITING_FOR_WORLD.removeFirst();
            notifyClient(client, event);
            if (event.type() == ThreatType.MOD_QUARANTINED && event.blocked()) {
                startupPopup = event;
            } else if (startupPopup == null && event.blocked()
                    && event.riskLevel().atLeast(RiskLevel.HIGH)) {
                startupPopup = event;
            }
        }

        if (startupPopup != null && client.currentScreen == null) {
            ThreatEvent event = startupPopup;
            startupPopup = null;
            client.setScreen(new AntiRatThreatScreen(event, null));
            if (event.type() == ThreatType.MOD_QUARANTINED
                    || event.type() == ThreatType.MOD_DEPENDENCY_DISABLED) {
                AntiRatRuntime.acknowledgePendingStartupNotice();
            }
        }
    }

    public static void openEvent(String eventId) {
        MinecraftClient client = MinecraftClient.getInstance();
        ThreatEvent event = AntiRatRuntime.eventById(eventId);
        if (event == null) {
            if (client.inGameHud != null) {
                client.inGameHud.getChatHud().addMessage(Text.literal("[AntiRat] Event not found: " + eventId)
                        .formatted(Formatting.RED));
            }
            return;
        }

        client.execute(() -> client.setScreen(new AntiRatThreatScreen(event, client.currentScreen)));
    }

    public static void postSystemMessage(String value, UiColor color) {
        MinecraftClient client = MinecraftClient.getInstance();
        if (client == null) return;
        client.execute(() -> {
            if (client.inGameHud != null) {
                client.inGameHud.getChatHud().addMessage(Text.literal("[AntiRat] ")
                        .formatted(Formatting.DARK_GRAY)
                        .append(Text.literal(value).formatted(formatting(color))));
            }
        });
    }

    private static Formatting formatting(UiColor color) {
        return switch (color) {
            case AQUA -> Formatting.AQUA;
            case DARK_GRAY -> Formatting.DARK_GRAY;
            case GOLD -> Formatting.GOLD;
            case GRAY -> Formatting.GRAY;
            case GREEN -> Formatting.GREEN;
            case RED -> Formatting.RED;
            case YELLOW -> Formatting.YELLOW;
        };
    }

    private static void notifyClient(MinecraftClient client, ThreatEvent event) {
        if (client == null || client.inGameHud == null) {
            return;
        }

        client.inGameHud.getChatHud().addMessage(chatMessage(event));

        if (event.blocked()) {
            client.inGameHud.setOverlayMessage(Text.literal("AntiRat blocked: " + event.title())
                    .formatted(Formatting.RED), false);
            playBlockedSound(client, event.riskLevel());
        } else if (event.riskLevel().atLeast(RiskLevel.HIGH)) {
            playWarningSound(client);
        }
    }

    static MutableText chatMessage(ThreatEvent event) {
        Formatting riskColor = switch (event.riskLevel()) {
            case CRITICAL -> Formatting.DARK_RED;
            case HIGH -> Formatting.RED;
            case MEDIUM -> Formatting.GOLD;
            case LOW -> Formatting.YELLOW;
            case INFO -> Formatting.GRAY;
        };

        String verb = event.blocked() ? "prevented" : "flagged";
        MutableText details = Text.literal(event.type() == ThreatType.MOD_QUARANTINED
                        ? " [Open threat popup]" : " [Open AntiRat log]")
                .styled(style -> style
                        .withColor(Formatting.AQUA)
                        .withUnderline(true)
                        .withClickEvent(new ClickEvent.RunCommand("/antirat show " + event.id()))
                        .withHoverEvent(new HoverEvent.ShowText(Text.literal("Open this AntiRat event"))));

        return Text.literal("[AntiRat] ")
                .formatted(Formatting.DARK_GRAY)
                .append(Text.literal(verb + " " + event.type().label() + " from ")
                        .formatted(event.blocked() ? Formatting.RED : Formatting.GRAY))
                .append(Text.literal(event.sourceLabel()).formatted(Formatting.GRAY))
                .append(Text.literal(" | Risk: ").formatted(Formatting.DARK_GRAY))
                .append(Text.literal(event.riskLevel().label()).formatted(riskColor))
                .append(details);
    }

    private static void playBlockedSound(MinecraftClient client, RiskLevel riskLevel) {
        float pitch = riskLevel == RiskLevel.CRITICAL ? 0.72F : 0.88F;
        client.getSoundManager().play(PositionedSoundInstance.ui(SoundEvents.BLOCK_NOTE_BLOCK_BIT, pitch));
        client.getSoundManager().play(PositionedSoundInstance.ui(SoundEvents.BLOCK_NOTE_BLOCK_PLING, 1.45F));
    }

    private static void playWarningSound(MinecraftClient client) {
        client.getSoundManager().play(PositionedSoundInstance.ui(SoundEvents.BLOCK_NOTE_BLOCK_BELL, 1.1F));
    }
}
