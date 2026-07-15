package com.antirat.guard;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Locale;

final class SensitivePathPolicy {
    private SensitivePathPolicy() {
    }

    static Decision classify(Path input) {
        if (input == null) return Decision.allow();
        String normalized = normalize(input.toAbsolutePath().normalize());
        String real = normalized;
        try {
            if (Files.exists(input)) real = normalize(input.toRealPath());
        } catch (IOException | SecurityException ignored) {
        }

        Decision direct = classifyNormalized(normalized);
        if (direct.block()) return direct;
        return real.equals(normalized) ? Decision.allow() : classifyNormalized(real);
    }

    private static Decision classifyNormalized(String path) {
        String leaf = leaf(path);
        if (path.matches(".*/proc/(?:self|[0-9]+)/(?:cmdline|environ)$")) {
            return block("process credential metadata",
                    List.of("Process arguments and environment data can contain launcher authentication material"));
        }
        if (leaf.startsWith("launcher_accounts") || leaf.startsWith("launcher_profiles")
                || leaf.equals("msa_credentials.json")
                || (leaf.equals("accounts.json") && containsAny(path, "/.minecraft/", "/minecraft/launcher/",
                "/prismlauncher/", "/prism launcher/", "/multimc/", "/polymc/", "/gdlauncher/",
                "/lunarclient/", "/.lunarclient/", "/feather/", "/atlauncher/", "/technic/",
                "/modrinthapp/", "/modrinth app/", "/curseforge/", "/ftb app/", "/sklauncher/",
                "/badlion client/"))) {
            return block("Minecraft launcher account store",
                    List.of("Launcher account files may contain reusable authentication material"));
        }

        boolean discordRoot = containsAny(path, "/discord/", "/discordcanary/", "/discordptb/",
                "/discorddevelopment/", "/vesktop/", "/armcord/", "/lightcord/", "/legcord/",
                "/equicord/", "/webcord/", "/discord-screenaudio/");
        if (discordRoot && (path.contains("/local storage/leveldb/") || path.contains("/session storage/")
                || leaf.equals("cookies") || leaf.equals("cookies-journal") || leaf.equals("local state"))) {
            return block("Discord credential store",
                    List.of("Discord client storage is not required for normal Minecraft mod operation"));
        }

        boolean chromiumRoot = containsAny(path, "/google/chrome/", "/chromium/",
                "/google/chrome sxs/", "/google-chrome/", "/google-chrome-beta/", "/arc/user data/", "/yandexbrowser/",
                "/microsoft edge/", "/microsoft/edge/", "/bravesoftware/brave-browser/",
                "/bravesoftware/brave-browser-beta/", "/bravesoftware/brave-browser-nightly/",
                "/opera software/", "/opera gx stable/", "/vivaldi/", "/iridium/", "/centbrowser/",
                "/epic privacy browser/", "/comodo/dragon/", "/torch/user data/");
        if (chromiumRoot && (leaf.startsWith("login data") || leaf.equals("cookies")
                || leaf.equals("local state") || leaf.equals("web data") || leaf.endsWith(".ldb"))) {
            return block("Browser credential store",
                    List.of("Chromium-family credential and cookie databases are protected from mod access"));
        }

        boolean firefoxProfile = containsAny(path, "/mozilla/firefox/", "/.mozilla/firefox/",
                "/firefox/profiles/", "/librewolf/", "/.librewolf/", "/waterfox/", "/.waterfox/",
                "/floorp/", "/.floorp/");
        if (firefoxProfile && (leaf.equals("logins.json") || leaf.equals("key4.db") || leaf.equals("key3.db")
                || leaf.equals("signons.sqlite") || leaf.equals("cookies.sqlite") || leaf.equals("places.sqlite")
                || (leaf.equals("data.sqlite") && path.contains("discord")))) {
            return block("Firefox credential store",
                    List.of("Firefox credential and cookie databases are protected from mod access"));
        }

        if ((path.contains("/keychains/") && (leaf.endsWith(".keychain-db") || leaf.endsWith(".keychain")))
                || path.contains("/microsoft/credentials/") || path.contains("/microsoft/protect/")
                || (path.contains("/keyrings/") && (leaf.endsWith(".keyring") || leaf.endsWith(".keyrings")))
                || leaf.equals("wallet.dat") || leaf.equals("credentials.db") || leaf.endsWith(".kdbx")) {
            return block("Operating-system or wallet credential store",
                    List.of("The target is a credential-bearing store outside Minecraft"));
        }
        return Decision.allow();
    }

    private static Decision block(String category, List<String> evidence) {
        return new Decision(true, category, evidence);
    }

    private static boolean containsAny(String value, String... needles) {
        for (String needle : needles) if (value.contains(needle)) return true;
        return false;
    }

    private static String normalize(Path path) {
        return path.toString().replace('\\', '/').toLowerCase(Locale.ROOT);
    }

    private static String leaf(String path) {
        int slash = path.lastIndexOf('/');
        return slash >= 0 ? path.substring(slash + 1) : path;
    }

    record Decision(boolean block, String category, List<String> evidence) {
        Decision {
            evidence = List.copyOf(evidence);
        }

        private static Decision allow() {
            return new Decision(false, "", List.of());
        }
    }
}
