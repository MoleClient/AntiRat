package com.antirat.client;

import com.antirat.model.RiskLevel;
import com.antirat.model.ThreatEvent;
import net.minecraft.client.font.TextRenderer;
import net.minecraft.client.gl.RenderPipelines;
import net.minecraft.client.gui.DrawContext;
import net.minecraft.client.gui.screen.Screen;
import net.minecraft.client.input.KeyInput;
import net.minecraft.text.Text;
import net.minecraft.util.Identifier;

import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.List;

public final class AntiRatThreatScreen extends Screen {
    private static final Identifier LOGO = Identifier.of("antirat", "textures/gui/icon.png");
    private static final DateTimeFormatter TIME_FORMAT = DateTimeFormatter.ofPattern("HH:mm:ss")
            .withZone(ZoneId.systemDefault());
    private static volatile String lastRenderedEventId = "";
    private static volatile boolean logoRegistered;

    private final ThreatEvent event;
    private final Screen parent;
    private long openedAt;
    private boolean closing;

    public AntiRatThreatScreen(ThreatEvent event, Screen parent) {
        super(Text.literal("AntiRat"));
        this.event = event;
        this.parent = parent;
    }

    @Override
    protected void init() {
        openedAt = System.currentTimeMillis();
    }

    @Override
    public boolean shouldPause() {
        return false;
    }

    @Override
    public boolean shouldCloseOnEsc() {
        return false;
    }

    @Override
    public boolean keyPressed(KeyInput input) {
        if (input.isEscape()) {
            closing = true;
            openedAt = System.currentTimeMillis();
            return true;
        }
        return super.keyPressed(input);
    }

    @Override
    public void render(DrawContext context, int mouseX, int mouseY, float deltaTicks) {
        boolean logoReady = ensureLogoRegistered();
        float progress = animationProgress();
        if (closing) {
            progress = 1.0F - progress;
            if (progress <= 0.01F) {
                close();
                return;
            }
        }

        int panelWidth = Math.min(768, width - 32);
        int panelHeight = Math.min(432, height - 32);
        if (panelWidth < 320) {
            panelWidth = width - 16;
        }
        if (panelHeight < 260) {
            panelHeight = height - 16;
        }

        int targetX = (width - panelWidth) / 2;
        int targetY = (height - panelHeight) / 2;
        int hiddenY = height + 24;
        int panelY = (int) lerp(hiddenY, targetY, easeOutCubic(progress));

        // Do not call Screen.renderBackground here. Minecraft and screen-wrapper mods may have
        // already applied the once-per-frame blur before this overlay is rendered, and a second
        // attempt throws "Can only blur once per frame". The dim layer is deliberately sufficient.
        context.fill(RenderPipelines.GUI, 0, 0, width, height, ((int) (145 * progress) << 24));
        context.fill(RenderPipelines.GUI, targetX, panelY, targetX + panelWidth, panelY + panelHeight, 0xF2171920);
        context.fill(RenderPipelines.GUI, targetX, panelY, targetX + 5, panelY + panelHeight,
                event.blocked() ? 0xFFFF3354 : 0xFFFFB547);
        context.fill(RenderPipelines.GUI, targetX, panelY, targetX + panelWidth, panelY + 1, 0xFF343844);
        context.fill(RenderPipelines.GUI, targetX, panelY + panelHeight - 1, targetX + panelWidth,
                panelY + panelHeight, 0xFF343844);

        int pad = Math.max(22, panelWidth / 28);
        int contentX = targetX + pad;
        int contentY = panelY + pad;
        int badgeSize = Math.max(42, Math.min(72, panelWidth / 10));
        int badgeColor = event.blocked() ? 0xFFFF3354 : 0xFFFFB547;
        context.fill(RenderPipelines.GUI, contentX, contentY, contentX + badgeSize, contentY + badgeSize, badgeColor);
        // Keep a visible frame around the artwork. Drawing it nearly edge-to-edge made the ant
        // look cropped inside the small placeholder badge even though the full texture was used.
        int logoInset = Math.max(6, badgeSize / 8);
        int renderedLogoSize = badgeSize - logoInset * 2;
        if (logoReady) {
            context.drawTexture(RenderPipelines.GUI_TEXTURED, LOGO, contentX + logoInset, contentY + logoInset,
                    0.0F, 0.0F, renderedLogoSize, renderedLogoSize, 256, 256, 256, 256);
        }

        TextRenderer renderer = textRenderer;
        int titleX = contentX + badgeSize + 22;
        drawText(context, renderer, "AntiRat", titleX, contentY + 5, 0xFFE2E4E8, 1.0F);
        drawText(context, renderer, event.blocked() ? "Threat prevented" : "Threat flagged",
                titleX, contentY + 23, riskColor(event.riskLevel()), 1.0F);

        int topLineY = contentY + Math.max(78, badgeSize + 18);
        int labelColor = 0xFF9EA3AD;
        int valueColor = 0xFFF4F5F7;
        int line = 0;
        line = drawPair(context, renderer, "Type", event.type().label(), contentX, topLineY, panelWidth - pad * 2, line, labelColor, valueColor);
        line = drawPair(context, renderer, "Mod", event.sourceLabel(), contentX, topLineY, panelWidth - pad * 2, line, labelColor, valueColor);
        line = drawPair(context, renderer, "Risk", event.riskLevel().label(), contentX, topLineY, panelWidth - pad * 2, line, labelColor, riskColor(event.riskLevel()));
        line = drawPair(context, renderer, "Confidence", event.accuracy() + "%", contentX, topLineY, panelWidth - pad * 2, line, labelColor, accuracyColor(event.accuracy()));
        line = drawPair(context, renderer, "Target", emptyDash(event.target()), contentX, topLineY, panelWidth - pad * 2, line, labelColor, valueColor);
        line = drawPair(context, renderer, "Time", TIME_FORMAT.format(event.timestamp()), contentX, topLineY, panelWidth - pad * 2, line, labelColor, valueColor);

        int detailY = topLineY + line * 22 + 12;
        int textWidth = panelWidth - pad * 2;
        drawSection(context, renderer, "What AntiRat intercepted", event.summary(), contentX, detailY, textWidth);
        detailY += 48;
        drawSection(context, renderer, "Quick tip", event.tip(), contentX, detailY, textWidth);
        detailY += 48;
        drawEvidence(context, renderer, contentX, detailY, textWidth);

        super.render(context, mouseX, mouseY, deltaTicks);
        if (logoReady) lastRenderedEventId = event.id();
    }

    private int drawPair(DrawContext context, TextRenderer renderer, String label, String value, int x, int y, int width,
                         int line, int labelColor, int valueColor) {
        int rowY = y + line * 22;
        int labelWidth = Math.min(84, Math.max(58, width / 5));
        context.drawText(renderer, label.toUpperCase(), x, rowY, labelColor, false);
        drawClippedText(context, renderer, value, x + labelWidth, rowY, width - labelWidth, valueColor);
        return line + 1;
    }

    private void drawSection(DrawContext context, TextRenderer renderer, String heading, String body, int x, int y, int width) {
        context.drawText(renderer, heading, x, y, 0xFFE9EAEE, false);
        context.drawWrappedText(renderer, Text.literal(emptyDash(body)), x, y + 14, width, 0xFFC6CAD3, false);
    }

    private void drawEvidence(DrawContext context, TextRenderer renderer, int x, int y, int width) {
        context.drawText(renderer, "Evidence", x, y, 0xFFE9EAEE, false);
        List<String> evidence = event.evidence();
        if (evidence.isEmpty()) {
            context.drawText(renderer, "-", x, y + 14, 0xFFC6CAD3, false);
            return;
        }

        int rowY = y + 14;
        for (int index = 0; index < Math.min(4, evidence.size()); index++) {
            drawClippedText(context, renderer, "- " + evidence.get(index), x, rowY, width, 0xFFC6CAD3);
            rowY += 12;
        }
    }

    private void drawText(DrawContext context, TextRenderer renderer, String text, int x, int y, int color, float scale) {
        if (scale == 1.0F) {
            context.drawText(renderer, text, x, y, color, false);
            return;
        }

        context.getMatrices().pushMatrix();
        context.getMatrices().translate(x, y);
        context.getMatrices().scale(scale, scale);
        context.drawText(renderer, text, 0, 0, color, false);
        context.getMatrices().popMatrix();
    }

    private void drawClippedText(DrawContext context, TextRenderer renderer, String text, int x, int y, int width, int color) {
        String clipped = renderer.trimToWidth(text, width);
        if (renderer.getWidth(text) > width && clipped.length() > 3) {
            clipped = clipped.substring(0, Math.max(0, clipped.length() - 3)) + "...";
        }
        context.drawText(renderer, clipped, x, y, color, false);
    }

    private float animationProgress() {
        return Math.min(1.0F, (System.currentTimeMillis() - openedAt) / 280.0F);
    }

    private static float easeOutCubic(float value) {
        float inverse = 1.0F - value;
        return 1.0F - inverse * inverse * inverse;
    }

    private static float lerp(float start, float end, float progress) {
        return start + (end - start) * progress;
    }

    private static int riskColor(RiskLevel riskLevel) {
        return switch (riskLevel) {
            case CRITICAL -> 0xFFFF3354;
            case HIGH -> 0xFFFF6B4A;
            case MEDIUM -> 0xFFFFB547;
            case LOW -> 0xFFFFD166;
            case INFO -> 0xFFB8C1CC;
        };
    }

    private static int accuracyColor(int accuracy) {
        if (accuracy >= 90) {
            return 0xFF7CFFB2;
        }
        if (accuracy >= 75) {
            return 0xFFFFD166;
        }
        return 0xFFFFA057;
    }

    private static String emptyDash(String value) {
        return value == null || value.isBlank() ? "-" : value;
    }

    private boolean ensureLogoRegistered() {
        if (logoRegistered) return true;
        if (client == null) return false;
        try (var input = AntiRatThreatScreen.class.getResourceAsStream(
                "/assets/antirat/textures/gui/icon.png")) {
            if (input == null) return false;
            var image = net.minecraft.client.texture.NativeImage.read(input);
            var texture = new net.minecraft.client.texture.NativeImageBackedTexture(
                    () -> "AntiRat logo", image);
            client.getTextureManager().registerTexture(LOGO, texture);
            texture.upload();
            logoRegistered = true;
            return true;
        } catch (Exception ignored) {
            return false;
        }
    }

    public static boolean wasRendered(String eventId) {
        return eventId != null && eventId.equals(lastRenderedEventId);
    }

    @Override
    public void close() {
        if (client != null) client.setScreen(parent);
    }
}
