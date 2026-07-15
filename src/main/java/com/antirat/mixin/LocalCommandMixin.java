package com.antirat.mixin;

import com.antirat.bootstrap.AntiRatCommands;
import net.minecraft.client.network.ClientPlayNetworkHandler;
import net.minecraft.network.packet.s2c.play.CommandTreeS2CPacket;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.Inject;
import org.spongepowered.asm.mixin.injection.callback.CallbackInfo;

/** Consumes AntiRat's commands locally before Minecraft can send them to a server. */
@Mixin(ClientPlayNetworkHandler.class)
public abstract class LocalCommandMixin {
    @Inject(method = "sendChatCommand", at = @At("HEAD"), cancellable = true)
    private void antirat$handleLocalCommand(String command, CallbackInfo callback) {
        if (AntiRatCommands.handle(command)) callback.cancel();
    }

    @Inject(method = "onCommandTree", at = @At("TAIL"))
    private void antirat$registerLocalCommandSuggestions(CommandTreeS2CPacket packet, CallbackInfo callback) {
        ClientPlayNetworkHandler self = (ClientPlayNetworkHandler) (Object) this;
        AntiRatCommands.registerSuggestions(self.getCommandDispatcher());
    }
}
