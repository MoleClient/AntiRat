package com.antirat.guard;

import org.junit.jupiter.api.Test;

import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SensitivePathPolicyTest {
    @Test
    void blocksMinecraftDiscordBrowserAndFirefoxCredentialStores() {
        assertTrue(SensitivePathPolicy.classify(Path.of("/home/test/.minecraft/launcher_accounts.json")).block());
        assertTrue(SensitivePathPolicy.classify(Path.of("/home/test/.config/discord/Local Storage/leveldb/0001.ldb")).block());
        assertTrue(SensitivePathPolicy.classify(Path.of("C:/Users/Test/AppData/Local/Google/Chrome/User Data/Default/Login Data")).block());
        assertTrue(SensitivePathPolicy.classify(Path.of("/home/test/.mozilla/firefox/x.default/logins.json")).block());
        assertTrue(SensitivePathPolicy.classify(Path.of("/home/test/.config/vesktop/Local State")).block());
        assertTrue(SensitivePathPolicy.classify(Path.of("/home/test/.local/share/PrismLauncher/accounts.json")).block());
        assertTrue(SensitivePathPolicy.classify(Path.of("/home/test/.config/google-chrome/Default/Login Data For Account")).block());
        assertTrue(SensitivePathPolicy.classify(Path.of("/home/test/.mozilla/firefox/x.default/storage/default/https+++discord.com/ls/data.sqlite")).block());
        assertTrue(SensitivePathPolicy.classify(Path.of("/proc/self/cmdline")).block());
        assertTrue(SensitivePathPolicy.classify(Path.of("/proc/1234/environ")).block());
        assertTrue(SensitivePathPolicy.classify(Path.of("C:/Users/Test/AppData/Roaming/Equicord/Local Storage/leveldb/0001.ldb")).block());
        assertTrue(SensitivePathPolicy.classify(Path.of("C:/Users/Test/AppData/Local/BraveSoftware/Brave-Browser-Nightly/User Data/Default/Cookies")).block());
        assertTrue(SensitivePathPolicy.classify(Path.of("/home/test/.librewolf/abc.default/key4.db")).block());
        assertTrue(SensitivePathPolicy.classify(Path.of("C:/Users/Test/AppData/Roaming/Microsoft/Credentials/secret")).block());
        assertTrue(SensitivePathPolicy.classify(Path.of("/home/test/passwords.kdbx")).block());
    }

    @Test
    void doesNotBlockUnrelatedFilesWithGenericNames() {
        assertFalse(SensitivePathPolicy.classify(Path.of("/game/config/accounts.json")).block());
        assertFalse(SensitivePathPolicy.classify(Path.of("/game/mods/cache/local-state.json")).block());
        assertFalse(SensitivePathPolicy.classify(Path.of("/game/screenshots/cookies.png")).block());
    }
}
