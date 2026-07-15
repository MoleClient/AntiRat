package com.antirat.model;

public enum RiskLevel {
    INFO(0, "Info"),
    LOW(1, "Low"),
    MEDIUM(2, "Medium"),
    HIGH(3, "High"),
    CRITICAL(4, "Critical");

    private final int rank;
    private final String label;

    RiskLevel(int rank, String label) {
        this.rank = rank;
        this.label = label;
    }

    public boolean atLeast(RiskLevel other) {
        return rank >= other.rank;
    }

    public String label() {
        return label;
    }

    public static RiskLevel fromScore(int score) {
        if (score >= 90) return CRITICAL;
        if (score >= 70) return HIGH;
        if (score >= 40) return MEDIUM;
        if (score >= 15) return LOW;
        return INFO;
    }
}
