package com.antirat.scan;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.zip.GZIPInputStream;
import java.util.zip.InflaterInputStream;

/**
 * Performs bounded, non-executing recovery of common string concealment used by commodity stealers.
 * Candidates are returned only when the recovered text contains a security-relevant anchor, keeping
 * ordinary encoded assets out of the behavioral score.
 */
final class DecodedPayloadInspector {
    private static final int MAX_INPUT_CHARS = 128 * 1024;
    private static final int MAX_DECODED_BYTES = 256 * 1024;
    private static final String[] SECURITY_ANCHORS = {
            "discord", "webhook", "telegram", "hooks.slack", "requestbin", "pipedream", "beeceptor",
            "getaccesstoken", "method_1674", "getsessionid", "method_1675", "net/minecraft/client/user",
            "launcher_accounts", "launcher_profiles", "msa_credentials",
            "local storage", "leveldb", "login data", "cookies.sqlite", "logins.json", "key4.db",
            "access_token", "session_token", "discord_token", "authorization", "bearer ",
            "java/net/", "httpclient", "okhttp", "processbuilder", "runtime.exec", "javax/crypto/cipher",
            "definehiddenclass", "defineclass", "loadlibrary", "cryptunprotectdata"
    };

    private DecodedPayloadInspector() {
    }

    static List<Candidate> expand(String raw) {
        if (raw == null || raw.isBlank() || raw.length() > MAX_INPUT_CHARS) return List.of();
        boolean percent = raw.indexOf('%') >= 0;
        boolean unicodeEscapes = raw.contains("\\u") || raw.contains("\\x");
        String trimmed = raw.trim();
        boolean hex = trimmed.length() >= 32 && firstCharactersHex(trimmed, 12) && looksHex(trimmed);
        boolean base64 = trimmed.length() >= 48 && (trimmed.indexOf('=') >= 0 || containsDigit(trimmed))
                && looksBase64(trimmed);
        boolean wordTransform = raw.length() >= 8 && raw.length() <= 4_096
                && (raw.contains("://") || raw.contains("//:") || (raw.indexOf('_') >= 0 && raw.indexOf('.') >= 0));
        String lowered = wordTransform ? raw.toLowerCase(Locale.ROOT) : "";
        boolean reversed = wordTransform && mightBeReversedLower(lowered);
        boolean rot13 = wordTransform && mightBeRot13Lower(lowered);
        boolean caesar = wordTransform && raw.contains("://")
                && !lowered.contains("http://") && !lowered.contains("https://")
                && !lowered.contains("ftp://") && !lowered.contains("ws://") && !lowered.contains("wss://");
        if (!percent && !unicodeEscapes && !hex && !base64 && !caesar && !reversed && !rot13) {
            return List.of(new Candidate(raw, "plain", false));
        }
        Map<String, Candidate> candidates = new LinkedHashMap<>();
        add(candidates, raw, "plain", false);

        String compact = compactWhitespace(raw);
        if (base64 && compact.length() >= 12 && looksBase64(compact)) {
            tryBase64(candidates, compact, Base64.getDecoder(), "Base64");
            tryBase64(candidates, compact, Base64.getUrlDecoder(), "URL-safe Base64");
            String reversedBase64 = new StringBuilder(compact).reverse().toString();
            tryBase64(candidates, reversedBase64, Base64.getDecoder(), "reversed Base64");
            tryBase64(candidates, reversedBase64, Base64.getUrlDecoder(), "reversed URL-safe Base64");
        }

        if (hex && looksHex(compact)) {
            byte[] decoded = new byte[compact.length() / 2];
            for (int index = 0; index < decoded.length; index++) {
                decoded[index] = (byte) Integer.parseInt(compact.substring(index * 2, index * 2 + 2), 16);
            }
            inspectDecodedBytes(candidates, decoded, "hex", 0);
        }

        if (reversed) {
            String reversedText = new StringBuilder(raw).reverse().toString();
            addIfRelevant(candidates, reversedText, "reversed");
        }
        if (rot13) {
            addIfRelevant(candidates, rot13(raw), "ROT13");
        }
        if (caesar && raw.length() <= 4_096) {
            for (int shift = 1; shift < 26; shift++) {
                addIfRelevant(candidates, caesar(raw, shift), "Caesar shift");
            }
        }
        if (percent && raw.length() <= 16_384) {
            addIfRelevant(candidates, percentDecode(raw), "percent-encoded");
        }
        if (unicodeEscapes && raw.length() <= 16_384) {
            addIfRelevant(candidates, escapedCharacterDecode(raw), "escaped characters");
        }

        return List.copyOf(candidates.values());
    }

    private static void tryBase64(Map<String, Candidate> candidates, String value, Base64.Decoder decoder, String kind) {
        if (!looksBase64(value)) return;
        String padded = switch (value.length() & 3) {
            case 2 -> value + "==";
            case 3 -> value + "=";
            default -> value;
        };
        try {
            byte[] decoded = decoder.decode(padded);
            if (decoded.length > 0 && decoded.length <= MAX_DECODED_BYTES) {
                inspectDecodedBytes(candidates, decoded, kind, 0);
            }
        } catch (IllegalArgumentException ignored) {
        }
    }

    private static void inspectDecodedBytes(
            Map<String, Candidate> candidates, byte[] bytes, String kind, int depth
    ) {
        byte[] expanded = decompressIfPresent(bytes);
        String direct = new String(expanded, StandardCharsets.UTF_8);
        addIfRelevant(candidates, direct, kind);

        // Single-byte XOR is common in small droppers. Only retain a result if an anchor appears.
        if (expanded.length >= 8 && expanded.length <= 64 * 1024 && !containsSecurityAnchor(direct)) {
            byte[] decoded = new byte[expanded.length];
            for (int key = 1; key <= 255; key++) {
                for (int index = 0; index < expanded.length; index++) decoded[index] = (byte) (expanded[index] ^ key);
                String candidate = new String(decoded, StandardCharsets.ISO_8859_1);
                if (containsSecurityAnchor(candidate)) {
                    addIfRelevant(candidates, candidate, kind + " + single-byte XOR");
                    break;
                }
            }
        }
        if (depth >= 2) return;
        String compact = compactWhitespace(direct);
        if (looksBase64(compact)) {
            tryNestedBase64(candidates, compact, Base64.getDecoder(), kind + " + Base64", depth + 1);
            tryNestedBase64(candidates, compact, Base64.getUrlDecoder(), kind + " + URL-safe Base64", depth + 1);
        }
        if (looksHex(compact)) {
            byte[] decoded = new byte[compact.length() / 2];
            for (int index = 0; index < decoded.length; index++) {
                decoded[index] = (byte) Integer.parseInt(compact.substring(index * 2, index * 2 + 2), 16);
            }
            inspectDecodedBytes(candidates, decoded, kind + " + hex", depth + 1);
        }
    }

    private static void tryNestedBase64(
            Map<String, Candidate> candidates, String value, Base64.Decoder decoder, String kind, int depth
    ) {
        String padded = switch (value.length() & 3) {
            case 2 -> value + "==";
            case 3 -> value + "=";
            default -> value;
        };
        try {
            byte[] decoded = decoder.decode(padded);
            if (decoded.length > 0 && decoded.length <= MAX_DECODED_BYTES) {
                inspectDecodedBytes(candidates, decoded, kind, depth);
            }
        } catch (IllegalArgumentException ignored) {
        }
    }

    private static byte[] decompressIfPresent(byte[] bytes) {
        if (bytes.length < 2) return bytes;
        boolean gzip = (bytes[0] & 0xff) == 0x1f && (bytes[1] & 0xff) == 0x8b;
        int header = ((bytes[0] & 0xff) << 8) | (bytes[1] & 0xff);
        boolean zlib = header == 0x7801 || header == 0x785e || header == 0x789c || header == 0x78da;
        if (!gzip && !zlib) return bytes;
        try (java.io.InputStream input = gzip
                ? new GZIPInputStream(new ByteArrayInputStream(bytes))
                : new InflaterInputStream(new ByteArrayInputStream(bytes));
             ByteArrayOutputStream output = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[4096];
            int read;
            while ((read = input.read(buffer)) != -1) {
                if (output.size() + read > MAX_DECODED_BYTES) return bytes;
                output.write(buffer, 0, read);
            }
            return output.toByteArray();
        } catch (IOException ignored) {
            return bytes;
        }
    }

    private static void addIfRelevant(Map<String, Candidate> candidates, String value, String kind) {
        if (containsSecurityAnchor(value)) add(candidates, value, kind, true);
    }

    private static void add(Map<String, Candidate> candidates, String value, String kind, boolean transformed) {
        if (value == null || value.isBlank() || value.length() > MAX_INPUT_CHARS) return;
        candidates.putIfAbsent(value, new Candidate(value, kind, transformed));
    }

    private static boolean containsSecurityAnchor(String value) {
        String lower = value.toLowerCase(Locale.ROOT).replace('\\', '/');
        for (String anchor : SECURITY_ANCHORS) {
            if (lower.contains(anchor)) return true;
        }
        return false;
    }

    private static boolean looksBase64(String value) {
        if (value.length() < 12 || value.length() > MAX_INPUT_CHARS || (value.length() & 3) == 1) return false;
        if (value.indexOf('.') >= 0 || value.indexOf(';') >= 0 || value.indexOf('(') >= 0
                || value.indexOf(')') >= 0 || value.indexOf(':') >= 0) return false;
        int valid = 0;
        boolean upper = false;
        boolean lower = false;
        boolean digit = false;
        for (int index = 0; index < value.length(); index++) {
            char c = value.charAt(index);
            if (c >= 'A' && c <= 'Z') upper = true;
            else if (c >= 'a' && c <= 'z') lower = true;
            else if (c >= '0' && c <= '9') digit = true;
            if (Character.isLetterOrDigit(c) || c == '+' || c == '/' || c == '-' || c == '_' || c == '=') valid++;
        }
        int classes = (upper ? 1 : 0) + (lower ? 1 : 0) + (digit ? 1 : 0);
        return valid >= value.length() * 0.98 && (classes >= 2 || value.endsWith("="));
    }

    private static String compactWhitespace(String value) {
        String trimmed = value.trim();
        boolean whitespace = false;
        for (int index = 0; index < trimmed.length(); index++) {
            if (Character.isWhitespace(trimmed.charAt(index))) {
                whitespace = true;
                break;
            }
        }
        if (!whitespace) return trimmed;
        StringBuilder compact = new StringBuilder(trimmed.length());
        for (int index = 0; index < trimmed.length(); index++) {
            char c = trimmed.charAt(index);
            if (!Character.isWhitespace(c)) compact.append(c);
        }
        return compact.toString();
    }

    private static boolean mightBeReversedLower(String lower) {
        return lower.contains("drocsid") || lower.contains("koohbew") || lower.contains("margelet")
                || lower.contains("kcals") || lower.contains("stnuocca_rehcnual")
                || lower.contains("nekot_ssecca") || lower.contains("atad nigol");
    }

    private static boolean mightBeRot13Lower(String lower) {
        return lower.contains("qvfpbeq") || lower.contains("jroubbx") || lower.contains("gryrtenz")
                || lower.contains("fynpx") || lower.contains("ynhapure_nppbhagf")
                || lower.contains("trgnpprffgbxra");
    }

    private static boolean looksHex(String value) {
        if (value.length() < 16 || value.length() > MAX_DECODED_BYTES * 2 || (value.length() & 1) != 0) return false;
        for (int index = 0; index < value.length(); index++) {
            if (Character.digit(value.charAt(index), 16) < 0) return false;
        }
        return true;
    }

    private static boolean firstCharactersHex(String value, int count) {
        int limit = Math.min(value.length(), count);
        for (int index = 0; index < limit; index++) if (Character.digit(value.charAt(index), 16) < 0) return false;
        return true;
    }

    private static boolean containsDigit(String value) {
        for (int index = 0; index < value.length(); index++) if (Character.isDigit(value.charAt(index))) return true;
        return false;
    }

    private static String rot13(String value) {
        StringBuilder result = new StringBuilder(value.length());
        for (int index = 0; index < value.length(); index++) {
            char c = value.charAt(index);
            if (c >= 'a' && c <= 'z') c = (char) ('a' + (c - 'a' + 13) % 26);
            else if (c >= 'A' && c <= 'Z') c = (char) ('A' + (c - 'A' + 13) % 26);
            result.append(c);
        }
        return result.toString();
    }

    private static String caesar(String value, int shift) {
        StringBuilder result = new StringBuilder(value.length());
        for (int index = 0; index < value.length(); index++) {
            char c = value.charAt(index);
            if (c >= 'a' && c <= 'z') c = (char) ('a' + (c - 'a' + shift) % 26);
            else if (c >= 'A' && c <= 'Z') c = (char) ('A' + (c - 'A' + shift) % 26);
            result.append(c);
        }
        return result.toString();
    }

    private static String percentDecode(String value) {
        String current = value;
        for (int pass = 0; pass < 3; pass++) {
            StringBuilder decoded = new StringBuilder(current.length());
            boolean changed = false;
            for (int index = 0; index < current.length(); index++) {
                char c = current.charAt(index);
                if (c == '%' && index + 2 < current.length()) {
                    int high = Character.digit(current.charAt(index + 1), 16);
                    int low = Character.digit(current.charAt(index + 2), 16);
                    if (high >= 0 && low >= 0) {
                        decoded.append((char) ((high << 4) | low));
                        index += 2;
                        changed = true;
                        continue;
                    }
                }
                decoded.append(c);
            }
            current = decoded.toString();
            if (!changed) break;
        }
        return current;
    }

    private static String escapedCharacterDecode(String value) {
        StringBuilder decoded = new StringBuilder(value.length());
        for (int index = 0; index < value.length(); index++) {
            char c = value.charAt(index);
            if (c == '\\' && index + 3 < value.length()
                    && (value.charAt(index + 1) == 'x' || value.charAt(index + 1) == 'X')) {
                int high = Character.digit(value.charAt(index + 2), 16);
                int low = Character.digit(value.charAt(index + 3), 16);
                if (high >= 0 && low >= 0) {
                    decoded.append((char) ((high << 4) | low));
                    index += 3;
                    continue;
                }
            }
            if (c == '\\' && index + 5 < value.length() && value.charAt(index + 1) == 'u') {
                int code = 0;
                boolean valid = true;
                for (int offset = 2; offset <= 5; offset++) {
                    int digit = Character.digit(value.charAt(index + offset), 16);
                    if (digit < 0) {
                        valid = false;
                        break;
                    }
                    code = (code << 4) | digit;
                }
                if (valid) {
                    decoded.append((char) code);
                    index += 5;
                    continue;
                }
            }
            decoded.append(c);
        }
        return decoded.toString();
    }

    record Candidate(String text, String kind, boolean transformed) {
    }
}
