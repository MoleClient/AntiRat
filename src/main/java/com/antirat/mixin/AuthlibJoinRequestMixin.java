package com.antirat.mixin;

import com.antirat.guard.TokenGuard;
import com.mojang.authlib.yggdrasil.request.JoinMinecraftServerRequest;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.Inject;
import org.spongepowered.asm.mixin.injection.callback.CallbackInfoReturnable;

/** Guards Authlib's secondary access-token carrier, including its record-generated toString. */
@Mixin(value = JoinMinecraftServerRequest.class, remap = false)
public abstract class AuthlibJoinRequestMixin {
    @Inject(method = {"accessToken", "toString"}, at = @At("HEAD"), cancellable = true)
    private void antirat$guardAuthlibToken(CallbackInfoReturnable<String> callback) {
        if (TokenGuard.shouldDenySessionToken(getClass())) callback.setReturnValue("");
    }
}
