package com.antirat.model;

public enum ThreatType {
    MOD_QUARANTINED("malicious mod"),
    MOD_DEPENDENCY_DISABLED("dependent mod"),
    STARTUP_SCAN("suspicious mod"),
    SESSION_TOKEN_ACCESS("session-token access"),
    DISCORD_CREDENTIAL_ACCESS("Discord credential access"),
    SENSITIVE_FILE_ACCESS("credential-store access"),
    NETWORK_REQUEST("network request"),
    COOKIE_ACCESS("cookie access"),
    PROCESS_EXECUTION("process execution"),
    DYNAMIC_CODE_EXECUTION("dynamic code execution"),
    PROTECTION_STATUS("protection issue"),
    QUARANTINE_FAILURE("quarantine failure");

    private final String label;

    ThreatType(String label) {
        this.label = label;
    }

    public String label() {
        return label;
    }
}
