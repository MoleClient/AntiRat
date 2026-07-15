package com.antirat.scan;

public record ModIdentity(String id, String name) {
    public static final ModIdentity UNKNOWN = new ModIdentity("unknown", "unknown source");

    public ModIdentity {
        id = id == null || id.isBlank() ? "unknown" : id;
        name = name == null || name.isBlank() ? id : name;
    }

    public boolean known() {
        return !id.equals("unknown");
    }
}
