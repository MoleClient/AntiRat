package com.antirat.scan;

public enum ScanStatus {
    CLEAN,
    WARNED,
    ALLOWLISTED,
    QUARANTINED,
    DEPENDENCY_QUARANTINED,
    QUARANTINE_FAILED
}
