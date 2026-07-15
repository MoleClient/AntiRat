package com.antirat.guard;

import com.antirat.model.RiskLevel;

import java.util.List;

record NetworkDecision(
        boolean report,
        boolean block,
        RiskLevel riskLevel,
        int accuracy,
        String title,
        String summary,
        String tip,
        List<String> evidence
) {
    static NetworkDecision allow() {
        return new NetworkDecision(false, false, RiskLevel.INFO, 0, "", "", "", List.of());
    }
}
