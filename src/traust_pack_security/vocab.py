"""Existing worklist vocabulary; contract registration belongs to XWING-2228."""

from enum import StrEnum


class Lane(StrEnum):
    FULL_AUDIT_VALIDATE = "full-audit+validate"
    FULL_AUDIT = "full-audit"
    IMPACT = "impact-lane"
    IAC = "iac-lane"
    IAC_BASELINE = "iac-baseline"
    RELEASE_PASSTHROUGH = "release-passthrough"
    THREAT_MODEL_REVIEW = "threat-model-review"
    DEPENDENCIES = "deps-lane"
    DIFF_SCAN = "diff-scan"
    DIFF_SCAN_QUARTERLY = "diff-scan-quarterly"
    THREAT_MODEL_QUARTERLY = "threat-model-quarterly"
    NONE = "none"


class EventSource(StrEnum):
    EXTERNAL_REPORT = "external-report"
    METHODOLOGY = "methodology"
    CVE = "cve"
    RELEASE = "release"
