package com.antirat.mixin;

import com.antirat.bootstrap.AntiRatCommands;
import net.minecraft.client.multiplayer.ClientPacketListener;
import net.minecraft.network.protocol.game.ClientboundCommandsPacket;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.Inject;
import org.spongepowered.asm.mixin.injection.callback.CallbackInfo;

/** Consumes AntiRat's commands locally before Minecraft can send them to a server. */
@Mixin(ClientPacketListener.class)
public abstract class LocalCommandMixin {
    @Inject(method = "sendCommand", at = @At("HEAD"), cancellable = true)
    private void antirat$handleLocalCommand(String command, CallbackInfo callback) {
        if (AntiRatCommands.handle(command)) callback.cancel();
    }

    @Inject(method = "handleCommands", at = @At("TAIL"))
    private void antirat$registerLocalCommandSuggestions(ClientboundCommandsPacket packet, CallbackInfo callback) {
        ClientPacketListener self = (ClientPacketListener) (Object) this;
        AntiRatCommands.registerSuggestions(self.getCommands());
    }
}
