package com.antirat.bootstrap;

import com.mojang.brigadier.CommandDispatcher;
import net.minecraft.client.network.ClientCommandSource;
import org.junit.jupiter.api.Test;

import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class AntiRatCommandsTest {
    @Test
    void clientCommandTreeContainsEverySupportedCommand() {
        CommandDispatcher<ClientCommandSource> dispatcher = new CommandDispatcher<>();

        AntiRatCommands.registerSuggestions(dispatcher);

        var root = dispatcher.getRoot().getChild("antirat");
        assertNotNull(root);
        Set<String> children = root.getChildren().stream().map(node -> node.getName()).collect(Collectors.toSet());
        assertEquals(Set.of("help", "list", "placeholder", "show", "see", "info", "scan", "quarantine", "unquarantine"),
                children);
        assertNotNull(root.getChild("show").getChild("event-id"));
        assertNotNull(root.getChild("see").getChild("event-id"));
        assertNotNull(root.getChild("scan").getChild("mod-id"));
        assertNotNull(root.getChild("unquarantine").getChild("mod-id").getChild("confirm"));
    }
}
