package com.antirat.scan;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/** Small ASCII Aho-Corasick matcher used as a fast gate before expensive feature classification. */
final class SecurityKeywordMatcher {
    private static final String[] KEYWORDS = {
            "token", "session", "minecraft", "launcher", "yggdrasil", "msa_", "selecteduser",
            "discord", "webhook", "telegram", "slack", "requestbin", "pipedream", "beeceptor",
            "storage", "leveldb", "chrome", "brave", "opera", "edge", "login", "cookie", "firefox",
            "java/net", "javax/net", "http", "okhttp", "retrofit", "socket", "netty", "ktor",
            "process", "powershell", "cmd.exe", "/bin/sh", "osascript", "wscript", "runtime", "exec",
            "cipher", "crypt", "keychain", "dpapi", "secretservice", "base64", "reflect", "methodhandles",
            "mixin", "inject", "accessor", "invoker",
            "defineclass", "urlclassloader", "unsafe", "loadlibrary", "system.load", "com/sun/jna", "jni",
            "startup", "currentversion", "launchagents", "crontab", "schtasks", "authorization", "bearer",
            "access_", "refresh_", "getenv", "java/lang/system", "user.name", "os.name", "computername",
            "inetaddress"
    };
    private static final int[][] NEXT;
    private static final boolean[] OUTPUT;

    static {
        List<int[]> transitions = new ArrayList<>();
        List<Boolean> outputs = new ArrayList<>();
        transitions.add(emptyTransitions());
        outputs.add(false);
        for (String keyword : KEYWORDS) {
            int state = 0;
            for (int index = 0; index < keyword.length(); index++) {
                int c = keyword.charAt(index);
                int next = transitions.get(state)[c];
                if (next < 0) {
                    next = transitions.size();
                    transitions.get(state)[c] = next;
                    transitions.add(emptyTransitions());
                    outputs.add(false);
                }
                state = next;
            }
            outputs.set(state, true);
        }

        int[] failure = new int[transitions.size()];
        ArrayDeque<Integer> queue = new ArrayDeque<>();
        for (int c = 0; c < 128; c++) {
            int child = transitions.getFirst()[c];
            if (child < 0) transitions.getFirst()[c] = 0;
            else if (child != 0) queue.add(child);
        }
        while (!queue.isEmpty()) {
            int state = queue.removeFirst();
            outputs.set(state, outputs.get(state) || outputs.get(failure[state]));
            for (int c = 0; c < 128; c++) {
                int child = transitions.get(state)[c];
                if (child < 0) {
                    transitions.get(state)[c] = transitions.get(failure[state])[c];
                } else {
                    failure[child] = transitions.get(failure[state])[c];
                    queue.add(child);
                }
            }
        }
        NEXT = transitions.toArray(int[][]::new);
        OUTPUT = new boolean[outputs.size()];
        for (int index = 0; index < outputs.size(); index++) OUTPUT[index] = outputs.get(index);
    }

    private SecurityKeywordMatcher() {
    }

    static boolean contains(String value) {
        int state = 0;
        for (int index = 0; index < value.length(); index++) {
            char c = value.charAt(index);
            if (c >= 'A' && c <= 'Z') c = (char) (c + ('a' - 'A'));
            if (c >= 128) {
                state = 0;
                continue;
            }
            state = NEXT[state][c];
            if (OUTPUT[state]) return true;
        }
        return false;
    }

    private static int[] emptyTransitions() {
        int[] transitions = new int[128];
        Arrays.fill(transitions, -1);
        return transitions;
    }
}
