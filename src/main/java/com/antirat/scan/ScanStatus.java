package com.antirat.scan;

public enum ScanStatus {
    CLEAN,
    WARNED,
    ALLOWLISTED,
    QUARANTINED,
    QUARANTINE_PENDING,
    DEPENDENCY_QUARANTINED,
    QUARANTINE_FAILED
}
