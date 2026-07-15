package com.antirat.client;

import com.antirat.model.RiskLevel;
import com.antirat.model.ThreatEvent;
import com.antirat.model.ThreatType;
import net.minecraft.text.ClickEvent;
import net.minecraft.text.HoverEvent;
import net.minecraft.text.Text;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AntiRatClientTest {
    @Test
    void threatChatLinkOpensTheExactEventThroughALocalCommand() {
        ThreatEvent event = ThreatEvent.create(ThreatType.MOD_QUARANTINED, RiskLevel.CRITICAL,
                "Threat prevented", "Test event", "fixture", "Fixture", "fixture.jar",
                "quarantine/fixture.jar.disabled", true, 100, "Contained", List.of("test"));

        Text link = AntiRatClient.chatMessage(event).getSiblings().getLast();

        ClickEvent.RunCommand click = assertInstanceOf(ClickEvent.RunCommand.class,
                link.getStyle().getClickEvent());
        assertEquals("/antirat show " + event.id(), click.command());
        assertInstanceOf(HoverEvent.ShowText.class, link.getStyle().getHoverEvent());
        assertTrue(link.getStyle().isUnderlined());
    }
}
