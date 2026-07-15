package com.antirat.mixin;

import com.antirat.guard.TokenGuard;
import net.minecraft.client.session.Session;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.Inject;
import org.spongepowered.asm.mixin.injection.callback.CallbackInfoReturnable;

@Mixin(Session.class)
public abstract class SessionMixin {
    @Inject(method = {"getAccessToken", "getSessionId"}, at = @At("HEAD"), cancellable = true)
    private void antirat$guardAccessToken(CallbackInfoReturnable<String> callback) {
        if (TokenGuard.shouldDenySessionToken(getClass())) callback.setReturnValue("");
    }
}
