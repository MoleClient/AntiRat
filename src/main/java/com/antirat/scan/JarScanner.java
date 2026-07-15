package com.antirat.scan;

import com.antirat.config.AntiRatConfig;
import com.antirat.model.RiskLevel;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

public final class JarScanner {
    private static final int SAMPLE_LIMIT = 512 * 1024;
    private static final Pattern JSON_ID = Pattern.compile("\\\"id\\\"\\s*:\\s*\\\"([a-zA-Z0-9_.-]{1,128})\\\"");
    private static final Pattern JSON_NAME = Pattern.compile("\\\"name\\\"\\s*:\\s*\\\"([^\\\"\\r\\n]{1,160})\\\"");
    private static final Pattern JSON_DEPENDS = Pattern.compile("\\\"depends\\\"\\s*:\\s*\\{([^{}]{0,32768})}", Pattern.DOTALL);
    private static final Pattern JSON_OBJECT_KEY = Pattern.compile("\\\"([a-zA-Z][a-zA-Z0-9_.-]{0,127})\\\"\\s*:");
    private static final Pattern VERSIONED_WEBHOOK_PATH = Pattern.compile("/api/v[0-9]{1,2}/webhooks/");

    private final AntiRatConfig config;

    public JarScanner(AntiRatConfig config) {
        this.config = config;
    }

    public ScanResult scan(Path source) throws IOException {
        Path normalized = source.toAbsolutePath().normalize();
        long size = Files.size(normalized);
        String sha256 = sha256(normalized);
        ScanState state = new ScanState();

        if (size > config.maxJarBytes()) {
            state.limitViolation = true;
            state.evidence.add("Archive exceeds the maximum safe scan size");
        } else {
            try (InputStream input = Files.newInputStream(normalized)) {
                scanArchive(input, 0, state);
            } catch (ScanLimitException | IOException exception) {
                state.limitViolation = true;
                state.evidence.add("Archive structure prevented complete bounded inspection");
            }
        }

        String verifiedSha256 = sha256(normalized);
        if (!sha256.equals(verifiedSha256)) {
            state.limitViolation = true;
            state.evidence.add("Archive changed while it was being inspected (TOCTOU protection)");
            sha256 = verifiedSha256;
        }

        if (state.entries == 0 && size > 0) {
            state.limitViolation = true;
            state.evidence.add("Jar exposes no safely enumerable ZIP entries");
        }

        if (state.classCount == 0 && !state.limitViolation) {
            state.evidence.add("Archive contains no directly inspectable JVM classes");
        }

        assessObfuscation(state);
        assessAssembledIndicators(state);
        Assessment assessment = assess(state);
        String fallback = stripExtension(normalized.getFileName().toString());
        String modId = state.modId == null || state.modId.isBlank() ? fallback.toLowerCase(Locale.ROOT) : state.modId;
        String modName = state.modName == null || state.modName.isBlank() ? normalized.getFileName().toString() : state.modName;
        boolean allowed = config.isHashAllowed(sha256);

        if (allowed) {
            state.evidence.add("Exact SHA-256 is locally allowlisted");
        }

        int score = assessment.score;
        RiskLevel risk = RiskLevel.fromScore(score);
        boolean quarantine = !allowed && assessment.highConfidence && score >= config.quarantineThreshold();
        return new ScanResult(normalized, sha256, modId, modName, score, risk,
                assessment.highConfidence, quarantine, state.requiredModIds, assessment.deniedCapabilities,
                limitedEvidence(state), state.classCount, state.nestedArchives);
    }

    private void scanArchive(InputStream rawInput, int depth, ScanState state) throws IOException, ScanLimitException {
        if (depth > config.maxNestedDepth()) return;
        try (ZipInputStream zip = new ZipInputStream(rawInput)) {
            ZipEntry entry;
            while ((entry = zip.getNextEntry()) != null) {
                if (entry.isDirectory()) continue;
                state.entries++;
                if (state.entries > config.maxEntries()) {
                    throw new ScanLimitException("too many entries");
                }

                String name = safeEntryName(entry.getName());
                String lowerName = name.toLowerCase(Locale.ROOT);
                boolean namedClass = lowerName.endsWith(".class");
                boolean namedArchive = depth < config.maxNestedDepth()
                        && (lowerName.endsWith(".jar") || lowerName.endsWith(".zip"));
                boolean namedNative = isNativeName(lowerName);
                boolean metadata = depth == 0 && lowerName.equals("fabric.mod.json");
                boolean text = metadata || isRelevantText(lowerName);
                boolean captureFully = namedClass || namedArchive || namedNative || text;
                long captureLimit = namedArchive ? Math.min(config.maxJarBytes(), 64L << 20) : config.maxEntryBytes();
                CapturedEntry captured = readEntry(zip, captureFully ? captureLimit : SAMPLE_LIMIT, captureFully, state);
                byte[] bytes = captured.bytes();
                if (isNativeArtifact(lowerName, bytes)) {
                    state.features.add(Feature.NATIVE_CODE);
                    state.nativeArtifacts++;
                    if (state.nativeArtifacts <= 3) {
                        state.evidence.add("Bundled native executable artifact: " + leafName(name));
                    }
                }
                int zipOffset = findZipHeader(bytes);
                int classOffset = findClassHeader(bytes);
                boolean concealedExecutableTruncated = !captured.complete() && (zipOffset >= 0 || classOffset >= 0);
                if (concealedExecutableTruncated) {
                    state.limitViolation = true;
                    state.evidence.add("Executable payload was concealed beyond the bounded resource sample");
                }
                boolean classFile = !concealedExecutableTruncated && (namedClass || classOffset >= 0);
                boolean nestedArchive = !concealedExecutableTruncated && depth < config.maxNestedDepth()
                        && (namedArchive || zipOffset >= 0);
                if (classFile && !namedClass && classOffset > 0) {
                    bytes = java.util.Arrays.copyOfRange(bytes, classOffset, bytes.length);
                } else if (nestedArchive && !namedArchive && zipOffset > 0) {
                    bytes = java.util.Arrays.copyOfRange(bytes, zipOffset, bytes.length);
                }

                if (metadata) readMetadata(bytes, state);
                if (classFile) {
                    if (!namedClass) state.evidence.add("Class bytes concealed in a non-class resource: " + leafName(name));
                    inspectClass(name, bytes, state);
                }
                else if (nestedArchive) {
                    state.nestedArchives++;
                    state.features.add(Feature.NESTED_ARCHIVE);
                    state.evidence.add((namedArchive ? "Inspected nested executable archive: "
                            : "Found archive bytes hidden under a non-archive name: ") + leafName(name));
                    scanArchive(new ByteArrayInputStream(bytes), depth + 1, state);
                } else if (text) {
                    inspectStrings(List.of(new String(bytes, StandardCharsets.ISO_8859_1)), name, state);
                } else {
                    List<String> extracted = looksLikeShortText(bytes)
                            ? List.of(new String(bytes, StandardCharsets.ISO_8859_1)) : extractStrings(bytes);
                    if (!extracted.isEmpty()) inspectStrings(extracted, name, state);
                }

                if (!classFile && !text && bytes.length >= 4096 && shannonEntropy(bytes) >= 7.72) {
                    state.highEntropyEntries++;
                }
                zip.closeEntry();
            }
        }
    }

    private CapturedEntry readEntry(ZipInputStream input, long captureLimit, boolean mustCaptureAll, ScanState state)
            throws IOException, ScanLimitException {
        long activeLimit = captureLimit;
        boolean requireComplete = mustCaptureAll;
        boolean magicChecked = mustCaptureAll;
        ByteArrayOutputStream output = new ByteArrayOutputStream((int) Math.min(activeLimit, 32 * 1024));
        byte[] buffer = new byte[8192];
        long entryBytes = 0;
        int read;
        while ((read = input.read(buffer)) != -1) {
            entryBytes += read;
            state.expandedBytes += read;
            if (state.expandedBytes > config.maxExpandedBytes()) {
                throw new ScanLimitException("expanded byte budget exceeded");
            }
            if (output.size() < activeLimit) {
                int amount = (int) Math.min(read, activeLimit - output.size());
                output.write(buffer, 0, amount);
            }
            if (!magicChecked && output.size() >= 4) {
                byte[] prefix = output.toByteArray();
                magicChecked = true;
                if (hasZipMagic(prefix) || hasClassMagic(prefix)) {
                    requireComplete = true;
                    activeLimit = hasZipMagic(prefix)
                            ? Math.min(config.maxJarBytes(), 64L << 20) : config.maxEntryBytes();
                }
            }
            if (requireComplete && entryBytes > activeLimit) {
                throw new ScanLimitException("executable entry exceeds byte budget");
            }
        }
        byte[] bytes = output.toByteArray();
        return new CapturedEntry(bytes, entryBytes == bytes.length);
    }

    private void inspectClass(String entryName, byte[] bytes, ScanState state) {
        state.classCount++;
        state.classNames.add(classStem(entryName));
        try {
            ClassFileInspector.Result result = ClassFileInspector.inspect(bytes);
            inspectStrings(result.utf8(), entryName, state);
        } catch (IOException exception) {
            state.malformedClasses++;
        }
    }

    private void inspectStrings(List<String> strings, String sourceName, ScanState state) {
        if (isDocumentation(sourceName)) return;
        EnumSet<Feature> local = EnumSet.noneOf(Feature.class);
        for (String raw : strings) {
            if (raw == null || raw.isEmpty()) continue;
            if (raw.length() <= 96 && state.stringFragments.size() < 2_048) {
                rememberFragment(raw.toLowerCase(Locale.ROOT), state);
            }
            if (looksEncoded(raw)) local.add(Feature.ENCODED_PAYLOAD);
            boolean plainRelevant = mightContainIndicator(raw);
            for (DecodedPayloadInspector.Candidate candidate : DecodedPayloadInspector.expand(raw)) {
                if (!candidate.transformed() && !plainRelevant) continue;
                String value = candidate.text().toLowerCase(Locale.ROOT).replace('\\', '/');
                if (candidate.transformed()) rememberFragment(value, state);
                EnumSet<Feature> recovered = featuresFor(value);
                if (candidate.transformed() && !recovered.isEmpty()) {
                    recovered.add(Feature.ENCODED_PAYLOAD);
                    state.evidence.add("Recovered security indicators from " + candidate.kind()
                            + " material in " + leafName(sourceName));
                }
                local.addAll(recovered);
            }
        }

        if (sourceName.toLowerCase(Locale.ROOT).endsWith(".class")
                && local.contains(Feature.MIXIN_FRAMEWORK)
                && ((local.contains(Feature.AUTHLIB_JOIN_REQUEST_TARGET)
                && (local.contains(Feature.MIXIN_INJECTOR) || local.contains(Feature.MIXIN_ACCESSOR)))
                || (local.contains(Feature.SESSION_ACCESS) && local.contains(Feature.TOKEN_MARKER)
                && local.contains(Feature.MIXIN_ACCESSOR)))) {
            local.add(Feature.CREDENTIAL_INTERCEPTOR_MIXIN);
        }

        if (local.contains(Feature.RUNTIME_CLASS) && local.contains(Feature.EXEC_METHOD)) local.add(Feature.PROCESS);

        state.features.addAll(local);
        if (!local.isEmpty()) state.behaviorScopes.add(Set.copyOf(local));
        if (local.contains(Feature.WEBHOOK)) state.evidence.add("Embedded Discord webhook destination");
        if (local.contains(Feature.TELEGRAM_BOT)) state.evidence.add("Embedded Telegram bot endpoint");
        if (local.contains(Feature.SLACK_WEBHOOK)) state.evidence.add("Embedded Slack webhook destination");
        if (local.contains(Feature.REQUEST_COLLECTOR)) state.evidence.add("Embedded temporary request-collection endpoint");
        if (local.contains(Feature.LAUNCHER_ACCOUNTS)) state.evidence.add("Minecraft launcher account-file access indicators");
        if (local.contains(Feature.SESSION_ACCESS)) state.evidence.add("Minecraft session/access-token API indicators");
        if (local.contains(Feature.DISCORD_STORAGE)) state.evidence.add("Discord local credential-store path indicators");
        if (local.contains(Feature.BROWSER_STORAGE)) state.evidence.add("Browser credential-store path indicators");
        if (local.contains(Feature.CREDENTIAL_INTERCEPTOR_MIXIN)) {
            state.evidence.add("Mixin targets a live token-bearing Minecraft/Authlib object");
        }
        if (local.contains(Feature.PROCESS) && local.contains(Feature.NETWORK)) {
            state.evidence.add("Process execution combined with outbound networking");
        }
        if (local.contains(Feature.DYNAMIC_CODE) && local.contains(Feature.ENCODED_PAYLOAD)) {
            state.evidence.add("Dynamic code loading combined with encoded payload material");
        }
    }

    private static EnumSet<Feature> featuresFor(String value) {
        EnumSet<Feature> features = EnumSet.noneOf(Feature.class);
        if (containsAny(value, "net/minecraft/client/session/session", "net/minecraft/class_320",
                "net/minecraft/client/user",
                "getaccesstoken", "method_1674", "getsessionid", "method_1675",
                "getsession", "method_1548")) features.add(Feature.SESSION_ACCESS);
        if (containsAny(value, "launcher_accounts.json", "launcher_profiles.json", "clienttoken",
                "selecteduser", "yggdrasil", "msa_credentials")) features.add(Feature.LAUNCHER_ACCOUNTS);
        if (containsAny(value, "discordcanary/local storage", "discordptb/local storage",
                "discord/local storage", "discord/local storage/leveldb")) features.add(Feature.DISCORD_STORAGE);
        if (containsAny(value, "discord.com", "discordapp.com", "discordcanary", "discordptb")
                || value.equals("discord")) features.add(Feature.DISCORD_MARKER);
        if (value.contains("/api/webhooks/") || VERSIONED_WEBHOOK_PATH.matcher(value).find()) {
            features.add(Feature.WEBHOOK_PATH);
        }
        if (value.contains("local storage")) features.add(Feature.LOCAL_STORAGE);
        if (containsAny(value, "leveldb", ".ldb", "org/iq80/leveldb")) features.add(Feature.LEVELDB);
        if (containsAny(value, "chrome/user data", "bravesoftware/brave-browser/user data",
                "opera software/opera stable", "microsoft/edge/user data", "login data", "local state",
                "cookies.sqlite", "logins.json", "key4.db")) features.add(Feature.BROWSER_STORAGE);
        if (features.contains(Feature.WEBHOOK_PATH) && containsAny(value, "discord", "discordapp")) {
            features.add(Feature.WEBHOOK);
        }
        if (value.contains("hooks.slack.com/services/")) features.add(Feature.SLACK_WEBHOOK);
        if (value.contains("api.telegram.org/bot")) features.add(Feature.TELEGRAM_BOT);
        if (containsAny(value, "webhook.site", "requestbin.net", "beeceptor.com", ".m.pipedream.net")) {
            features.add(Feature.REQUEST_COLLECTOR);
        }
        if (containsAny(value, "java/net/url", "java/net/urlconnection", "java/net/httpurlconnection",
                "javax/net/ssl/httpsurlconnection", "java/net/http/httpclient", "okhttp3/",
                "com/squareup/okhttp", "retrofit2/", "org/apache/http/", "org/asynchttpclient/",
                "kong/unirest/", "java/net/socket", "java/net/datagramsocket",
                "java/nio/channels/socketchannel", "io/netty/bootstrap/bootstrap", "ktor/client")) {
            features.add(Feature.NETWORK);
        }
        if (containsAny(value, "java/lang/processbuilder", "powershell", "cmd.exe",
                "/bin/sh", "osascript", "wscript.shell")) features.add(Feature.PROCESS);
        if (value.equals("java/lang/runtime")) features.add(Feature.RUNTIME_CLASS);
        if (value.equals("exec") || value.equals("exec0")) features.add(Feature.EXEC_METHOD);
        if (containsAny(value, "cryptunprotectdata", "javax/crypto/cipher", "keychain", "os_crypt",
                "dpapi", "secretservice")) features.add(Feature.DECRYPTION);
        if (containsAny(value, "java/util/base64", "base64.getdecoder", "base64.getencoder")) features.add(Feature.BASE64);
        if (containsAny(value, "java/lang/reflect/", "methodhandles$lookup", "definehiddenclass",
                "defineclass", "urlclassloader", "sun/misc/unsafe", "jdk/internal/misc/unsafe")) {
            features.add(Feature.DYNAMIC_CODE);
        }
        if (value.contains("org/spongepowered/asm/mixin/mixin")) features.add(Feature.MIXIN_FRAMEWORK);
        if (containsAny(value, "org/spongepowered/asm/mixin/injection/inject",
                "org/spongepowered/asm/mixin/injection/redirect",
                "org/spongepowered/asm/mixin/injection/modifyarg",
                "org/spongepowered/asm/mixin/injection/modifyvariable")) features.add(Feature.MIXIN_INJECTOR);
        if (containsAny(value, "org/spongepowered/asm/mixin/gen/accessor",
                "org/spongepowered/asm/mixin/gen/invoker")) features.add(Feature.MIXIN_ACCESSOR);
        if (containsAny(value, "com/mojang/authlib/yggdrasil/request/joinminecraftserverrequest",
                "com.mojang.authlib.yggdrasil.request.joinminecraftserverrequest")) {
            features.add(Feature.AUTHLIB_JOIN_REQUEST_TARGET);
        }
        if (containsAny(value, "java/lang/system.load", "java/lang/system.loadlibrary", "com/sun/jna/",
                "jninativeinterface")) features.add(Feature.NATIVE_CODE);
        if (containsAny(value, "/startup/", "currentversion/run", "launchagents", "crontab", "schtasks")) {
            features.add(Feature.PERSISTENCE);
        }
        if (containsAny(value, "authorization", "bearer ", "access_token", "session_token", "discord_token",
                "accesstoken", "refresh_token")) features.add(Feature.TOKEN_MARKER);
        if (containsAny(value, "system.getenv", "java/lang/system", "user.name", "os.name", "computername",
                "java/net/inetaddress")) features.add(Feature.SYSTEM_DISCOVERY);
        if (looksEncoded(value)) features.add(Feature.ENCODED_PAYLOAD);
        return features;
    }

    private static boolean mightContainIndicator(String raw) {
        return SecurityKeywordMatcher.contains(raw);
    }

    private static void rememberFragment(String value, ScanState state) {
        if (state.stringFragments.size() >= 2_048 || value.length() < 2 || value.length() > 192) return;
        StringBuilder builder = new StringBuilder(value.length());
        for (int index = 0; index < value.length(); index++) {
            char c = value.charAt(index);
            if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) builder.append(c);
        }
        String normalized = builder.toString();
        if (normalized.length() >= 2 && normalized.length() <= 160) state.stringFragments.add(normalized);
    }

    private static void assessAssembledIndicators(ScanState state) {
        boolean discord = canAssemble("discordcom", state.stringFragments);
        boolean webhook = canAssemble("apiwebhooks", state.stringFragments);
        boolean session = canAssemble("getaccesstoken", state.stringFragments)
                || canAssemble("method1674", state.stringFragments)
                || canAssemble("getsessionid", state.stringFragments)
                || canAssemble("method1675", state.stringFragments);
        boolean launcher = canAssemble("launcheraccountsjson", state.stringFragments);
        boolean discordStore = canAssemble("localstorageleveldb", state.stringFragments);
        if (discord) state.features.add(Feature.DISCORD_MARKER);
        if (webhook) state.features.add(Feature.WEBHOOK_PATH);
        if (discord && webhook) {
            state.features.add(Feature.WEBHOOK);
            state.evidence.add("Discord webhook destination reconstructed from split constants");
        }
        if (session) {
            state.features.add(Feature.SESSION_ACCESS);
            state.evidence.add("Session-token accessor reconstructed from split constants");
        }
        if (launcher) {
            state.features.add(Feature.LAUNCHER_ACCOUNTS);
            state.evidence.add("Launcher account path reconstructed from split constants");
        }
        if (discordStore && discord) {
            state.features.add(Feature.DISCORD_STORAGE);
            state.evidence.add("Discord credential-store path reconstructed from split constants");
        }
    }

    private static boolean canAssemble(String target, List<String> fragments) {
        int[] pieces = new int[target.length() + 1];
        java.util.Arrays.fill(pieces, Integer.MAX_VALUE);
        pieces[0] = 0;
        for (int position = 0; position < target.length(); position++) {
            if (pieces[position] == Integer.MAX_VALUE || pieces[position] >= 6) continue;
            for (String fragment : fragments) {
                int maximum = Math.min(fragment.length(), target.length() - position);
                for (int length = 2; length <= maximum; length++) {
                    int end = position + length;
                    String segment = target.substring(position, end);
                    boolean matches = position == 0 ? fragment.endsWith(segment)
                            : end == target.length() ? fragment.startsWith(segment)
                            : fragment.equals(segment);
                    if (matches) pieces[end] = Math.min(pieces[end], pieces[position] + 1);
                }
            }
        }
        return pieces[target.length()] >= 2 && pieces[target.length()] <= 6;
    }

    private Assessment assess(ScanState state) {
        EnumSet<Feature> f = state.features;
        if (f.contains(Feature.DISCORD_MARKER) && f.contains(Feature.WEBHOOK_PATH)) {
            f.add(Feature.WEBHOOK);
            state.evidence.add("Discord webhook components assembled across separate constants/classes");
        }
        if (f.contains(Feature.DISCORD_MARKER) && f.contains(Feature.LOCAL_STORAGE)
                && f.contains(Feature.LEVELDB)) {
            f.add(Feature.DISCORD_STORAGE);
            state.evidence.add("Discord LevelDB credential-store components assembled across code paths");
        }
        EnumSet<Capability> denied = EnumSet.noneOf(Capability.class);
        int score = 0;
        boolean highConfidence = false;
        boolean exfilEndpoint = f.contains(Feature.WEBHOOK) || f.contains(Feature.TELEGRAM_BOT)
                || f.contains(Feature.SLACK_WEBHOOK) || f.contains(Feature.REQUEST_COLLECTOR);
        boolean concealment = f.contains(Feature.DYNAMIC_CODE) || f.contains(Feature.ENCODED_PAYLOAD)
                || f.contains(Feature.OBFUSCATED_NAMES) || f.contains(Feature.DECRYPTION);
        boolean scopedLauncherNetwork = hasScope(state, Feature.LAUNCHER_ACCOUNTS, Feature.NETWORK)
                || (hasScope(state, Feature.LAUNCHER_ACCOUNTS, Feature.ENCODED_PAYLOAD) && f.contains(Feature.NETWORK));
        boolean scopedDiscordNetwork = hasScope(state, Feature.DISCORD_STORAGE, Feature.NETWORK)
                || (hasScope(state, Feature.DISCORD_STORAGE, Feature.ENCODED_PAYLOAD) && f.contains(Feature.NETWORK));
        boolean scopedBrowserDecryptNetwork = hasScope(state, Feature.BROWSER_STORAGE, Feature.DECRYPTION, Feature.NETWORK)
                || (hasScope(state, Feature.BROWSER_STORAGE, Feature.ENCODED_PAYLOAD)
                && f.contains(Feature.DECRYPTION) && f.contains(Feature.NETWORK));
        boolean scopedSessionNetwork = hasScope(state, Feature.SESSION_ACCESS, Feature.NETWORK);
        boolean scopedSessionExfilChain = hasScopedSessionExfilChain(state);
        boolean scopedSessionProcessExfilChain = hasScopedSessionProcessExfilChain(state);

        if (f.contains(Feature.OBFUSCATED_NAMES)) score = Math.max(score, 18);
        if (f.contains(Feature.NESTED_ARCHIVE) && concealment) score = Math.max(score, 24);
        if (f.contains(Feature.DYNAMIC_CODE) && f.contains(Feature.ENCODED_PAYLOAD)) score = Math.max(score, 38);
        if (f.contains(Feature.PROCESS) && f.contains(Feature.NETWORK)) score = Math.max(score, 45);
        if (f.contains(Feature.SESSION_ACCESS) && f.contains(Feature.NETWORK)) score = Math.max(score, 48);

        if (exfilEndpoint && f.contains(Feature.NETWORK)) {
            score = Math.max(score, f.contains(Feature.WEBHOOK) ? 98 : 95);
            highConfidence = true;
            denied.add(Capability.WEBHOOK_EXFILTRATION);
            denied.add(Capability.UNTRUSTED_NETWORK);
            state.verdictEvidence.add("High-confidence verdict: explicit exfiltration endpoint with networking code");
        }
        if (scopedLauncherNetwork
                && (f.contains(Feature.TOKEN_MARKER) || concealment)) {
            score = Math.max(score, 68);
            state.evidence.add("Launcher account-store access with networking retained for runtime credential-file enforcement");
        }
        if (scopedDiscordNetwork
                && (f.contains(Feature.DECRYPTION) || f.contains(Feature.TOKEN_MARKER) || concealment)) {
            score = Math.max(score, 68);
            denied.add(Capability.DISCORD_CREDENTIALS);
            state.evidence.add("Discord credential-store access with networking retained for runtime file enforcement");
        }
        if (scopedBrowserDecryptNetwork) {
            score = Math.max(score, 68);
            denied.add(Capability.BROWSER_CREDENTIALS);
            state.evidence.add("Browser credential-store access with networking retained for runtime file enforcement");
        }
        if (f.contains(Feature.SESSION_ACCESS) && f.contains(Feature.NETWORK) && exfilEndpoint) {
            score = Math.max(score, 94);
            highConfidence = true;
            denied.add(Capability.MINECRAFT_SESSION);
            denied.add(Capability.UNTRUSTED_NETWORK);
            state.verdictEvidence.add("High-confidence verdict: session access combined with an explicit exfiltration endpoint");
        }
        if (f.contains(Feature.CREDENTIAL_INTERCEPTOR_MIXIN) && f.contains(Feature.NETWORK)) {
            score = Math.max(score, 96);
            highConfidence = true;
            denied.add(Capability.MINECRAFT_SESSION);
            denied.add(Capability.UNTRUSTED_NETWORK);
            state.verdictEvidence.add("High-confidence verdict: runtime mixin interception of a token-bearing object plus networking");
        } else if (f.contains(Feature.CREDENTIAL_INTERCEPTOR_MIXIN)) {
            score = Math.max(score, 72);
            denied.add(Capability.MINECRAFT_SESSION);
        }
        if (scopedSessionExfilChain && !exfilEndpoint) {
            score = Math.max(score, 68);
            state.evidence.add("Session authentication and concealed networking occur in one code scope; runtime monitoring retained");
        }
        if (scopedSessionProcessExfilChain) {
            score = Math.max(score, 97);
            highConfidence = true;
            denied.add(Capability.MINECRAFT_SESSION);
            denied.add(Capability.PROCESS_EXECUTION);
            denied.add(Capability.UNTRUSTED_NETWORK);
            state.verdictEvidence.add("High-confidence verdict: concealed session-token handling, outbound networking, and process execution in one scope");
        }
        if (scopedSessionNetwork && f.contains(Feature.OBFUSCATED_NAMES)
                && hasScope(state, Feature.SESSION_ACCESS, Feature.NETWORK, Feature.SYSTEM_DISCOVERY)
                && hasScopeContainingAny(state, Set.of(Feature.SESSION_ACCESS), Feature.DECRYPTION, Feature.BASE64)) {
            score = Math.max(score, 68);
            state.evidence.add("Obfuscated session-aware networking retained for runtime enforcement rather than automatic quarantine");
        }
        if (hasScopeContainingAny(state, Set.of(Feature.PROCESS),
                Feature.LAUNCHER_ACCOUNTS, Feature.DISCORD_STORAGE, Feature.BROWSER_STORAGE)) {
            score = Math.max(score, 93);
            highConfidence = true;
            denied.add(Capability.PROCESS_EXECUTION);
            state.verdictEvidence.add("High-confidence verdict: external credential-store access combined with process execution");
        } else if (hasScope(state, Feature.PROCESS, Feature.SESSION_ACCESS)) {
            score = Math.max(score, 60);
            denied.add(Capability.PROCESS_EXECUTION);
        }
        if (hasScope(state, Feature.PERSISTENCE, Feature.PROCESS, Feature.NETWORK)) {
            score = Math.max(score, 91);
            highConfidence = true;
            denied.add(Capability.PROCESS_EXECUTION);
            denied.add(Capability.UNTRUSTED_NETWORK);
            state.verdictEvidence.add("High-confidence verdict: persistence, process execution, and networking in one scope");
        }
        if (hasScopedExternalCredentialDynamicNetwork(state)
                && (state.highEntropyEntries > 0 || f.contains(Feature.ENCODED_PAYLOAD))) {
            score = Math.max(score, 96);
            highConfidence = true;
            denied.add(Capability.DYNAMIC_CODE);
            denied.add(Capability.UNTRUSTED_NETWORK);
            state.verdictEvidence.add("High-confidence verdict: concealed dynamic code plus external credential-store access and networking");
        } else if (hasScopedSessionDynamicNetwork(state)
                && (state.highEntropyEntries > 0 || f.contains(Feature.ENCODED_PAYLOAD))) {
            score = Math.max(score, 68);
            state.evidence.add("Session-aware dynamic networking retained for runtime enforcement");
        }
        if (hasScope(state, Feature.DYNAMIC_CODE, Feature.DECRYPTION, Feature.NETWORK)
                && (state.highEntropyEntries > 0
                || (f.contains(Feature.NESTED_ARCHIVE) && f.contains(Feature.ENCODED_PAYLOAD)))) {
            score = Math.max(score, 68);
            state.evidence.add("Encrypted runtime code loader combined with outbound networking (runtime-restricted warning)");
        }
        if (hasScopeContainingAny(state, Set.of(Feature.NATIVE_CODE, Feature.NETWORK),
                Feature.SESSION_ACCESS, Feature.LAUNCHER_ACCOUNTS, Feature.DISCORD_STORAGE, Feature.BROWSER_STORAGE)
                && (f.contains(Feature.DECRYPTION) || f.contains(Feature.DYNAMIC_CODE)
                || state.highEntropyEntries > 0)) {
            score = Math.max(score, 97);
            highConfidence = true;
            denied.add(Capability.UNTRUSTED_NETWORK);
            denied.add(Capability.DYNAMIC_CODE);
            state.evidence.add("Credential access combined with concealed native execution and networking");
            state.verdictEvidence.add("High-confidence verdict: credential access, native execution, and networking in one scope");
        }
        if (state.limitViolation) {
            score = Math.max(score, 90);
            highConfidence = true;
            state.evidence.add("Fail-closed: executable archive could not be inspected within safety limits");
            state.verdictEvidence.add("High-confidence verdict: bounded inspection could not complete safely");
        }
        if (state.malformedClasses > 0) {
            score = Math.max(score, Math.min(55, 20 + state.malformedClasses * 5));
            state.evidence.add("Malformed or deliberately confusing class-file structure");
        }
        if (state.highEntropyEntries > 0 && concealment) {
            score = Math.max(score, 42);
            state.evidence.add("High-entropy payload data combined with runtime decoding/loading");
        }
        if (state.nativeArtifacts > 0) {
            score = Math.max(score, 35);
            state.evidence.add("Bundled native code retained as a correlated risk signal because JVM scanning cannot inspect it");
            if (f.contains(Feature.PROCESS)) denied.add(Capability.PROCESS_EXECUTION);
        }

        if (score >= config.warningThreshold() && highConfidence && f.contains(Feature.SESSION_ACCESS)) {
            denied.add(Capability.MINECRAFT_SESSION);
        }
        if (highConfidence && f.contains(Feature.DYNAMIC_CODE)) denied.add(Capability.DYNAMIC_CODE);
        // Low/Medium observations are telemetry for later correlation, never a static punishment.
        // Actual sensitive operations remain guarded at runtime and can establish stronger evidence.
        if (!highConfidence) denied.clear();
        return new Assessment(Math.min(score, 100), highConfidence, Set.copyOf(denied));
    }

    private static boolean hasScope(ScanState state, Feature... required) {
        for (Set<Feature> scope : state.behaviorScopes) {
            boolean matches = true;
            for (Feature feature : required) {
                if (!scope.contains(feature)) {
                    matches = false;
                    break;
                }
            }
            if (matches) return true;
        }
        return false;
    }

    private static boolean hasScopeContainingAny(
            ScanState state, Set<Feature> required, Feature... alternatives
    ) {
        for (Set<Feature> scope : state.behaviorScopes) {
            if (!scope.containsAll(required)) continue;
            for (Feature alternative : alternatives) if (scope.contains(alternative)) return true;
        }
        return false;
    }

    private static boolean hasScopedSessionExfilChain(ScanState state) {
        for (Set<Feature> scope : state.behaviorScopes) {
            if (!scope.containsAll(Set.of(Feature.SESSION_ACCESS, Feature.NETWORK, Feature.TOKEN_MARKER))) continue;
            if (scope.contains(Feature.SYSTEM_DISCOVERY) || scope.contains(Feature.ENCODED_PAYLOAD)
                    || scope.contains(Feature.DYNAMIC_CODE) || scope.contains(Feature.DECRYPTION)) return true;
        }
        return false;
    }

    private static boolean hasScopedSessionProcessExfilChain(ScanState state) {
        for (Set<Feature> scope : state.behaviorScopes) {
            if (!scope.containsAll(Set.of(Feature.SESSION_ACCESS, Feature.NETWORK,
                    Feature.PROCESS, Feature.DYNAMIC_CODE))) continue;
            if (scope.contains(Feature.ENCODED_PAYLOAD) || scope.contains(Feature.DECRYPTION)
                    || scope.contains(Feature.BASE64)) return true;
        }
        return false;
    }

    private static boolean hasScopedExternalCredentialDynamicNetwork(ScanState state) {
        for (Set<Feature> scope : state.behaviorScopes) {
            if (!scope.containsAll(Set.of(Feature.DYNAMIC_CODE, Feature.NETWORK))) continue;
            boolean credential = scope.contains(Feature.LAUNCHER_ACCOUNTS)
                    || scope.contains(Feature.DISCORD_STORAGE) || scope.contains(Feature.BROWSER_STORAGE);
            boolean concealed = scope.contains(Feature.ENCODED_PAYLOAD) || scope.contains(Feature.DECRYPTION);
            if (credential && concealed) return true;
        }
        return false;
    }

    private static boolean hasScopedSessionDynamicNetwork(ScanState state) {
        for (Set<Feature> scope : state.behaviorScopes) {
            if (scope.containsAll(Set.of(Feature.SESSION_ACCESS, Feature.DYNAMIC_CODE, Feature.NETWORK))
                    && (scope.contains(Feature.ENCODED_PAYLOAD) || scope.contains(Feature.DECRYPTION))) return true;
        }
        return false;
    }

    private void assessObfuscation(ScanState state) {
        if (state.classNames.size() < 12) return;
        int suspicious = 0;
        for (String name : state.classNames) {
            if (isSuspiciousClassName(name)) suspicious++;
        }
        double ratio = suspicious / (double) state.classNames.size();
        if (ratio >= 0.58) {
            state.features.add(Feature.OBFUSCATED_NAMES);
            state.evidence.add("Extreme class-name obfuscation across " + Math.round(ratio * 100) + "% of classes");
        }
    }

    private static void readMetadata(byte[] bytes, ScanState state) {
        String json = new String(bytes, StandardCharsets.UTF_8);
        Matcher id = JSON_ID.matcher(json);
        Matcher name = JSON_NAME.matcher(json);
        if (id.find()) state.modId = id.group(1);
        if (name.find()) state.modName = name.group(1);
        Matcher depends = JSON_DEPENDS.matcher(json);
        if (depends.find()) {
            Matcher key = JSON_OBJECT_KEY.matcher(depends.group(1));
            while (key.find()) {
                String dependency = key.group(1).toLowerCase(Locale.ROOT);
                if (!dependency.equals("minecraft") && !dependency.equals("java")
                        && !dependency.equals("fabricloader") && !dependency.equals("a-")) {
                    state.requiredModIds.add(dependency);
                }
            }
        }
    }

    private static boolean isRelevantText(String name) {
        return name.endsWith(".json") || name.endsWith(".properties") || name.endsWith(".toml")
                || name.endsWith(".yml") || name.endsWith(".yaml") || name.endsWith(".txt")
                || name.endsWith(".cfg") || name.endsWith(".js") || name.endsWith(".ps1")
                || name.endsWith(".bat") || name.endsWith(".vbs") || name.endsWith(".sh")
                || name.startsWith("meta-inf/services/");
    }

    private static boolean isDocumentation(String name) {
        String lower = name == null ? "" : name.toLowerCase(Locale.ROOT).replace('\\', '/');
        String leaf = leafName(lower);
        if (leaf.endsWith(".class") || leaf.endsWith(".jar") || leaf.endsWith(".zip")) return false;
        return lower.startsWith("docs/") || lower.contains("/docs/")
                || leaf.endsWith(".md") || leaf.endsWith(".markdown")
                || leaf.startsWith("readme") || leaf.startsWith("changelog")
                || leaf.startsWith("license") || leaf.startsWith("notice");
    }

    private static boolean hasZipMagic(byte[] bytes) {
        return findZipHeader(bytes) == 0;
    }

    private static boolean hasClassMagic(byte[] bytes) {
        return findClassHeader(bytes) == 0;
    }

    private static boolean isNativeArtifact(String name, byte[] bytes) {
        String lower = name == null ? "" : name.toLowerCase(Locale.ROOT);
        if (isNativeName(lower)) return true;
        if (bytes.length < 4) return false;
        if (bytes[0] == 'M' && bytes[1] == 'Z') return true;
        if ((bytes[0] & 0xff) == 0x7f && bytes[1] == 'E' && bytes[2] == 'L' && bytes[3] == 'F') return true;
        int magic = ((bytes[0] & 0xff) << 24) | ((bytes[1] & 0xff) << 16)
                | ((bytes[2] & 0xff) << 8) | (bytes[3] & 0xff);
        return magic == 0xfeedface || magic == 0xcefaedfe || magic == 0xfeedfacf || magic == 0xcffaedfe;
    }

    private static boolean isNativeName(String lower) {
        return lower.endsWith(".exe") || lower.endsWith(".dll") || lower.endsWith(".so")
                || lower.endsWith(".dylib") || lower.endsWith(".jnilib") || lower.endsWith(".node")
                || lower.endsWith(".pyd") || lower.endsWith(".bundle");
    }

    private static int findZipHeader(byte[] bytes) {
        for (int index = 0; index + 30 <= bytes.length; index++) {
            if (bytes[index] != 'P' || bytes[index + 1] != 'K' || bytes[index + 2] != 3 || bytes[index + 3] != 4) continue;
            int version = bytes[index + 4] & 0xff;
            int method = (bytes[index + 8] & 0xff) | ((bytes[index + 9] & 0xff) << 8);
            int nameLength = (bytes[index + 26] & 0xff) | ((bytes[index + 27] & 0xff) << 8);
            if (version <= 63 && (method == 0 || method == 8) && nameLength > 0 && nameLength <= 4096
                    && index + 30 + nameLength <= bytes.length) return index;
        }
        return -1;
    }

    private static int findClassHeader(byte[] bytes) {
        for (int index = 0; index + 10 <= bytes.length; index++) {
            if ((bytes[index] & 0xff) != 0xca || (bytes[index + 1] & 0xff) != 0xfe
                    || (bytes[index + 2] & 0xff) != 0xba || (bytes[index + 3] & 0xff) != 0xbe) continue;
            int major = ((bytes[index + 6] & 0xff) << 8) | (bytes[index + 7] & 0xff);
            int constantPoolCount = ((bytes[index + 8] & 0xff) << 8) | (bytes[index + 9] & 0xff);
            if (major >= 45 && major <= 80 && constantPoolCount > 1) return index;
        }
        return -1;
    }

    private static List<String> extractStrings(byte[] bytes) {
        List<String> strings = new ArrayList<>();
        StringBuilder ascii = new StringBuilder();
        for (byte raw : bytes) {
            int value = raw & 0xff;
            if (value >= 32 && value <= 126) {
                if (ascii.length() < 4096) ascii.append((char) value);
            } else {
                addExtracted(strings, ascii);
                if (strings.size() >= 512) return strings;
            }
        }
        addExtracted(strings, ascii);

        StringBuilder utf16 = new StringBuilder();
        for (int index = 0; index + 1 < bytes.length; index += 2) {
            int low = bytes[index] & 0xff;
            int high = bytes[index + 1] & 0xff;
            if (high == 0 && low >= 32 && low <= 126) {
                if (utf16.length() < 4096) utf16.append((char) low);
            } else {
                addExtracted(strings, utf16);
                if (strings.size() >= 512) return strings;
            }
        }
        addExtracted(strings, utf16);
        return strings;
    }

    private static boolean looksLikeShortText(byte[] bytes) {
        if (bytes.length < 2 || bytes.length > 4_096) return false;
        int printable = 0;
        for (byte raw : bytes) {
            int value = raw & 0xff;
            if ((value >= 32 && value <= 126) || value == '\n' || value == '\r' || value == '\t') printable++;
        }
        return printable >= bytes.length * 0.92;
    }

    private static void addExtracted(List<String> strings, StringBuilder builder) {
        if (builder.length() >= 6) strings.add(builder.toString());
        builder.setLength(0);
    }

    static String sha256(Path path) throws IOException {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            try (InputStream input = new DigestInputStream(Files.newInputStream(path), digest)) {
                input.transferTo(java.io.OutputStream.nullOutputStream());
            }
            return hex(digest.digest());
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 unavailable", impossible);
        }
    }

    private static String hex(byte[] bytes) {
        StringBuilder builder = new StringBuilder(bytes.length * 2);
        for (byte value : bytes) builder.append(String.format(Locale.ROOT, "%02x", value & 0xff));
        return builder.toString();
    }

    private static boolean looksEncoded(String value) {
        if (value.length() < 48 || value.length() > 16_384) return false;
        if ((value.length() & 3) == 1) return false;
        boolean upper = false;
        boolean lower = false;
        boolean digit = false;
        for (int index = 0; index < value.length(); index++) {
            char c = value.charAt(index);
            if (c >= 'A' && c <= 'Z') upper = true;
            else if (c >= 'a' && c <= 'z') lower = true;
            else if (c >= '0' && c <= '9') digit = true;
            boolean valid = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
                    || c == '+' || c == '/' || c == '=' || c == '-' || c == '_';
            if (!valid || (c == '=' && index < value.length() - 2)) return false;
        }
        int classes = (upper ? 1 : 0) + (lower ? 1 : 0) + (digit ? 1 : 0);
        return classes >= 2 || value.endsWith("=");
    }

    private static double shannonEntropy(byte[] bytes) {
        int[] counts = new int[256];
        for (byte value : bytes) counts[value & 0xff]++;
        double entropy = 0.0;
        for (int count : counts) {
            if (count == 0) continue;
            double probability = count / (double) bytes.length;
            entropy -= probability * (Math.log(probability) / Math.log(2.0));
        }
        return entropy;
    }

    private static boolean isSuspiciousClassName(String name) {
        if (name.length() <= 2) return true;
        if (name.length() < 16) return false;
        int vowels = 0;
        int transitions = 0;
        char previous = 0;
        for (char c : name.toCharArray()) {
            if ("aeiouAEIOU".indexOf(c) >= 0) vowels++;
            if (previous != 0 && Character.isDigit(c) != Character.isDigit(previous)) transitions++;
            previous = c;
        }
        return vowels * 12 < name.length() || transitions > name.length() / 3;
    }

    private static boolean containsAny(String value, String... needles) {
        for (String needle : needles) if (value.contains(needle)) return true;
        return false;
    }

    private static String safeEntryName(String value) {
        if (value == null) return "<unnamed>";
        return value.length() <= 512 ? value : value.substring(value.length() - 512);
    }

    private static String classStem(String entryName) {
        String leaf = leafName(entryName);
        int dollar = leaf.indexOf('$');
        int dot = leaf.lastIndexOf('.');
        int end = dollar >= 0 ? dollar : dot >= 0 ? dot : leaf.length();
        return leaf.substring(0, Math.max(0, end));
    }

    private static String leafName(String value) {
        int slash = Math.max(value.lastIndexOf('/'), value.lastIndexOf('\\'));
        return slash >= 0 ? value.substring(slash + 1) : value;
    }

    private static String stripExtension(String value) {
        int dot = value.lastIndexOf('.');
        return dot > 0 ? value.substring(0, dot) : value;
    }

    private static List<String> limitedEvidence(ScanState state) {
        LinkedHashSet<String> prioritized = new LinkedHashSet<>(state.verdictEvidence);
        prioritized.addAll(state.evidence);
        return prioritized.stream().limit(20).toList();
    }

    private enum Feature {
        SESSION_ACCESS,
        LAUNCHER_ACCOUNTS,
        DISCORD_STORAGE,
        DISCORD_MARKER,
        WEBHOOK_PATH,
        LOCAL_STORAGE,
        LEVELDB,
        BROWSER_STORAGE,
        WEBHOOK,
        SLACK_WEBHOOK,
        TELEGRAM_BOT,
        REQUEST_COLLECTOR,
        NETWORK,
        PROCESS,
        RUNTIME_CLASS,
        EXEC_METHOD,
        DECRYPTION,
        BASE64,
        DYNAMIC_CODE,
        NATIVE_CODE,
        PERSISTENCE,
        TOKEN_MARKER,
        SYSTEM_DISCOVERY,
        ENCODED_PAYLOAD,
        NESTED_ARCHIVE,
        OBFUSCATED_NAMES,
        MIXIN_FRAMEWORK,
        MIXIN_INJECTOR,
        MIXIN_ACCESSOR,
        AUTHLIB_JOIN_REQUEST_TARGET,
        CREDENTIAL_INTERCEPTOR_MIXIN
    }

    private static final class ScanState {
        private final EnumSet<Feature> features = EnumSet.noneOf(Feature.class);
        private final LinkedHashSet<String> evidence = new LinkedHashSet<>();
        private final LinkedHashSet<String> verdictEvidence = new LinkedHashSet<>();
        private final List<String> classNames = new ArrayList<>();
        private final List<String> stringFragments = new ArrayList<>();
        private final List<Set<Feature>> behaviorScopes = new ArrayList<>();
        private final Set<String> requiredModIds = new HashSet<>();
        private String modId;
        private String modName;
        private int entries;
        private int classCount;
        private int nestedArchives;
        private int malformedClasses;
        private int highEntropyEntries;
        private int nativeArtifacts;
        private long expandedBytes;
        private boolean limitViolation;
    }

    private record Assessment(int score, boolean highConfidence, Set<Capability> deniedCapabilities) {
    }

    private record CapturedEntry(byte[] bytes, boolean complete) {
    }

    private static final class ScanLimitException extends Exception {
        private ScanLimitException(String message) {
            super(message);
        }
    }

}
