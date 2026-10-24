"""``traust admin …`` — operator tooling and attestation."""

from __future__ import annotations

from traust.cli.groups._registry import passthrough_op

_ENTRIES: tuple[tuple[str, str, str], ...] = (
    ("doctor", "doctor", "Environment preflight: traust-core, tools, auth, network, gates."),
    (
        "toolchain",
        "toolchain",
        "Toolchain management — install, check, and populate external tool pins.",
    ),
    (
        "checkpoint",
        "checkpoint",
        "Checkpoint helper for the runbook skills (vuln-scan, triage, verify).",
    ),
    (
        "scan-internal-refs",
        "scan_internal_refs",
        "Pre-publication scrub: organization-internal references in a report tree.",
    ),
    (
        "query-index",
        "query_index",
        "Query the per-run symbol index built by build_symbol_index.py.",
    ),
    (
        "attest-target",
        "attest_target",
        "Pre-flight target attestation — validation-improvement-plan P1.",
    ),
)

ADMIN: dict[str, object] = {name: passthrough_op(module, help) for name, module, help in _ENTRIES}
