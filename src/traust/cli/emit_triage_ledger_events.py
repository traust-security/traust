#!/usr/bin/env python3
"""
Emit track-findings disposition-ledger events from a validated TRIAGE.json.

Deterministic transform (design: docs/disposition-ledger.md §6b).
Verdict -> ledger mapping:

  true_positive  -> validity `confirmed` (machine event; skipped when
                    verify_verdict == needs_manual_test — an unconfident
                    confirmation emits nothing)
  hardening      -> validity `hardening`, with the category-aware risk
                    weight (lambda) resolved from
                    $TRAUST_CONFIG_HOME/hardening-risk-weights.json and RECORDED into
                    the event so replays never re-derive it
  false_positive -> machine false_positive event. Auto-accept tier
                    (unanimous + verdict-citation-lint clean + mean
                    confidence >= 8 + claimed severity low/informational)
                    is marked `auto_accept_tier: true` and may set validity
                    without countersign; a deterministic 10% sample is
                    queued for human audit (`fp_audit_valve`). Everything
                    else remains countersign-gated evidence.
  undetermined   -> NO validity event; a needs_review queue item
                    (`undetermined_finding`) so it cannot silently age out
  duplicate      -> nothing (the canonical finding's event covers it)

Also emits a REFUTED REGISTER (<layer-base>-refuted-register.json): every
false positive — machine or awaiting countersign — stays visible as input
to fuzz-harness target selection and live-validation scoping. An FP is a
falsifiable claim, never a shield against future assessment.

Finding refs resolve in order: canonical orig_id ({REPO_SLUG}-{SHORTSHA}-
{NNN}); else the `source` fragment ("…-security-audit.md#<id>") when it
matches an audit finding id (legacy-campaign triage); else the triage id
itself when it matches an audit finding id. Unresolvable findings are
skipped with a warning. Event ids use the layer schema's canonical sha256,
so re-emitting the same triage is idempotent (existing events are never
duplicated on append).

This tool routes and records; it never decides state — the track-findings
merge engine (evidence-class precedence, countersign rules) does.

Usage:
  python3 -m traust.cli.emit_triage_ledger_events TRIAGE.json \\
      --audit <repo>-security-audit.json \\
      [--layer <repo>-findings-layer.json]   # append (created if absent)
      [--weights $TRAUST_CONFIG_HOME/hardening-risk-weights.json]
      [--lint verdict-lint.json]             # enables the auto-accept tier
      [--tenancy-profile multi_tenant|single_tenant]
      [--recorded-at ISO8601]                # reproducible runs
"""

import argparse
import hashlib
import json
import os
import re
import sys
from datetime import UTC, datetime
from pathlib import Path

from traust_engine.ledger import LedgerService

from traust.cli.emit_validation_ledger_events import merge_register
from traust.context import (
    add_config_home_arg,
    add_ledger_binding_args,
    bind_ledger,
    default_findings_roots,
    load_engine,
)
from traust.lib.event_time import recorded_at_arg, report_occurred_at
from traust.paths import optional_config_path

CANONICAL_FINDING_ID = re.compile(r"^[A-Z][A-Z0-9_]{0,23}-[a-f0-9]{7}-\d{3}$")
RATIONALE_CAP = 500
AUDIT_VALVE_MOD = 10  # 1-in-10 salted sample of auto-accepted FPs


def _valve_sampled(event: dict) -> bool:
    """Decide whether an auto-accepted FP event is queued for human audit.

    The sample key is a content hash of the immutable event fields plus a
    SECRET salt (env HARNESS_VALVE_SALT, provisioned by the operator and
    never visible to the triage agent). The previous key — the event_id,
    a pure function of agent-authored fields — was grindable: renumbering
    findings re-rolled the sample until every event escaped audit
    (self-audit AI_SECURITY_HARNESS-d686348-004). With a secret salt the
    agent cannot predict which events sample.

    FAIL CLOSED: when the salt is unset, EVERY auto-accepted FP is queued
    for human review — auto-accept without an audit valve is not a tier.
    """
    salt = os.environ.get("HARNESS_VALVE_SALT")
    if not salt:
        return True
    core = {
        k: event.get(k)
        for k in ("finding_ref", "occurred_at", "disposition", "rationale", "evidence_refs")
    }
    payload = salt + "\n" + json.dumps(core, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    return int(digest, 16) % AUDIT_VALVE_MOD == 0


def _confine_path(candidate: str, roots: list[Path], what: str) -> Path:
    """Resolve candidate and require it under one of roots (realpath
    containment). Relative candidates resolve against the cwd (matching
    the documented CLI usage)."""
    resolved = Path(candidate).resolve()
    checked = []
    for root in roots:
        root_r = root.resolve()
        checked.append(str(root_r))
        try:
            resolved.relative_to(root_r)
            return resolved
        except ValueError:
            continue
    print(
        f"ERROR: {what} path {candidate!r} resolves to {resolved}, "
        f"outside the allowed root(s) {checked} — refusing (pass "
        "--findings-root if your results tree lives elsewhere)",
        file=sys.stderr,
    )
    sys.exit(2)


def harness_version(triage: dict) -> str:
    return str(triage.get("triage_context", {}).get("harness_version", "0.0.0"))


def resolve_tenancy_profile(audit: dict, override: str | None) -> tuple[str, str]:
    """Return (profile, source). Derived from artifacts, never inferred live."""
    if override:
        return override, "override"
    peach = audit.get("peach_isolation_review") or {}
    if isinstance(peach, dict) and "applicable" in peach:
        profile = "multi_tenant" if peach.get("applicable") else "single_tenant"
        return profile, "peach_isolation_review.applicable"
    return "single_tenant", "default(no peach_isolation_review)"


def resolve_lambda(weights: dict, category: str | None, profile: str) -> float:
    lam = weights.get("weights", {}).get(
        (category or "").strip().lower(), weights.get("default", 0.3)
    )
    if profile == "single_tenant":
        lam = lam * weights.get("single_tenant_dampening", 0.5)
    return round(float(lam), 3)


def is_auto_accept(f: dict, lint_by_id: dict | None) -> bool:
    """Owner-accepted bar: >=2 concurring FP votes with zero dissent,
    lint clean, conf >= 8, low/info claim.

    Tightened 2026-07-31 (docs-verification P0-2): a single FP vote
    used to qualify — including findings routed to a reduced one-vote
    tier precisely because their citation looked fabricated
    (anchor_absent). One model vote is not corroboration; a lone-vote
    dismissal now goes to the countersign queue like any other.
    """
    if lint_by_id is None:
        return False  # no lint results supplied -> conservative: countersign
    lint = lint_by_id.get(f.get("id"))
    if not lint or lint.get("status") != "ok":
        return False
    vb = f.get("vote_breakdown") or {}
    if vb.get("true_positive", 0) or vb.get("hardening", 0):
        return False  # dissent -> countersign
    if vb.get("false_positive", 0) < 2:
        return False  # a lone FP vote is not corroboration (P0-2)
    if (f.get("confidence") or 0) < 8:
        return False
    claimed = str(f.get("claimed_severity") or "").strip().lower()
    return claimed in ("low", "informational")


def _rationale(f: dict, suffix: str = "") -> str:
    text = " ".join(str(f.get("rationale") or "").split())[:RATIONALE_CAP]
    out = (text + (" " + suffix if suffix else "")).strip()
    return out if len(out) >= 10 else (out + " (triage verdict)").strip()


def build_events(
    triage: dict,
    audit: dict,
    weights: dict,
    lint_by_id: dict | None,
    source_ref: str,
    recorded_at: str,
    tenancy_override: str | None,
) -> dict:
    """Return {events, needs_review, register, skipped}."""
    hv = harness_version(triage)
    profile, profile_source = resolve_tenancy_profile(audit, tenancy_override)
    occurred_at = report_occurred_at(
        triage.get("triage_completed"), recorded_at, field="triage_completed"
    )
    actor = {"kind": "machine", "identity": f"triage/{hv}", "ldap_verified": False}
    source = {"type": "triage_report", "ref": source_ref, "actor": actor}

    # Legacy-campaign triage (pre canonical orig_id) names its audit finding
    # via the `source` fragment: "<repo>-security-audit.md#<finding-id>".
    # Resolve against the audit's actual finding ids so those events land on
    # the right finding_ref instead of being skipped.
    audit_ids = {str(af.get("id")) for af in (audit.get("findings") or [])}

    def resolve_ref(f: dict) -> str | None:
        orig = str(f.get("orig_id") or "")
        if CANONICAL_FINDING_ID.match(orig):
            return orig
        src = str(f.get("source") or "")
        if "#" in src:
            frag = src.rsplit("#", 1)[1].strip()
            if frag in audit_ids:
                return frag
        if str(f.get("id") or "") in audit_ids:
            return str(f["id"])
        return None

    events, needs_review, register, skipped = [], [], [], []
    for f in triage.get("findings", []):
        verdict = f.get("verdict")
        if verdict == "duplicate":
            continue
        orig = resolve_ref(f)
        if orig is None:
            skipped.append(
                {
                    "id": f.get("id"),
                    "verdict": verdict,
                    "reason": "no canonical orig_id, and neither the "
                    "source fragment nor the triage id "
                    "matches an audit finding id",
                }
            )
            continue

        if verdict == "undetermined":
            needs_review.append(
                {
                    "queued_at": recorded_at,
                    "source_ref": source_ref,
                    "quote": _rationale(
                        f,
                        "(triage: undetermined — nothing proven or refuted; human review required)",
                    ),
                    "author": actor["identity"],
                    "suggested_finding_ref": orig,
                    "queue_reason": "undetermined_finding",
                    "status": "pending",
                }
            )
            continue

        if verdict == "true_positive":
            if f.get("verify_verdict") == "needs_manual_test":
                # An unconfident confirmation emits no validity event, but
                # it must not evaporate: queue it so a human (or live
                # validation) picks it up from the countersign inbox.
                needs_review.append(
                    {
                        "queued_at": recorded_at,
                        "source_ref": source_ref,
                        "quote": _rationale(
                            f,
                            "(triage: true_positive but "
                            "needs_manual_test — static "
                            "reasoning hit its limit; a "
                            "human PoC or live validation "
                            "should decide)",
                        ),
                        "author": actor["identity"],
                        "suggested_finding_ref": orig,
                        "suggested_disposition": {"validity": "confirmed"},
                        "queue_reason": "needs_manual_test",
                        "status": "pending",
                    }
                )
                continue
            validity = "confirmed"
        elif verdict == "hardening":
            validity = "hardening"
        elif verdict == "false_positive":
            validity = "false_positive"
        else:
            skipped.append({"id": f.get("id"), "verdict": verdict, "reason": "unknown verdict"})
            continue

        event = {
            "finding_ref": orig,
            "recorded_at": recorded_at,
            "occurred_at": occurred_at,
            "source": source,
            "disposition": {"validity": validity},
            "rationale": _rationale(
                f,
                {
                    "confirmed": "",
                    "hardening": "(triage: hardening, exclusion rule 13 — "
                    "accurate gap, no concrete exploit path)",
                    "false_positive": f"(triage: refuted — "
                    f"{', '.join(f.get('refute_reasons') or []) or 'see rationale'}"
                    f"; exclusion rule {f.get('exclusion_rule') or 'none'})",
                }[validity],
            ),
            "evidence_refs": list(f.get("first_links") or []),
            "harness_version": hv,
        }

        if validity == "hardening":
            event["risk_weight"] = {
                "lambda": resolve_lambda(weights, f.get("category"), profile),
                "weights_version": str(weights.get("version", "0")),
                "tenancy_profile": profile,
                "profile_source": profile_source,
            }

        if validity == "false_positive":
            auto = is_auto_accept(f, lint_by_id)
            if auto:
                event["auto_accept_tier"] = True
                if _valve_sampled(event):
                    needs_review.append(
                        {
                            "queued_at": recorded_at,
                            "source_ref": source_ref,
                            "quote": _rationale(
                                f,
                                "(audit-valve sample of an "
                                "auto-accepted machine false "
                                "positive — please verify)",
                            ),
                            "author": actor["identity"],
                            "suggested_finding_ref": orig,
                            "queue_reason": "fp_audit_valve",
                            "status": "pending",
                        }
                    )
            register.append(
                {
                    "finding_ref": orig,
                    "triage_id": f.get("id"),
                    "title": f.get("title"),
                    "file": f.get("file"),
                    "line": f.get("line"),
                    "category": f.get("category"),
                    "claimed_severity": f.get("claimed_severity"),
                    "refute_reasons": f.get("refute_reasons") or [],
                    "exclusion_rule": f.get("exclusion_rule"),
                    "tier": "auto_accept" if auto else "countersign",
                    "evidence_refs": list(f.get("first_links") or []),
                    "asserted_at": recorded_at,
                    "asserted_by": actor["identity"],
                    "note": "Falsifiable claim: remains in fuzzing and "
                    "live-validation scope; execution evidence "
                    "overrides (evidence-class precedence).",
                }
            )

        events.append(event)

    return {
        "events": events,
        "needs_review": needs_review,
        "register": register,
        "skipped": skipped,
    }


def append_to_layer(
    layer_path: Path,
    audit_path: Path,
    audit: dict,
    out: dict,
    recorded_at: str,
    hv: str,
    *,
    engine=None,
) -> dict:
    """Create or idempotently append to the layer file. Returns counts."""
    shell = {
        "metadata": {
            "audit_report": str(Path(audit_path.name)),
            "repository": str(
                (audit.get("metadata") or {}).get("repository") or "https://unknown.invalid/"
            ),
            "created": recorded_at,
            "harness_version": hv,
        },
        "events": [],
        "needs_review": [],
    }
    commit = str((audit.get("metadata") or {}).get("commit") or "")
    if re.match(r"^[0-9a-f]{7,40}$", commit):
        shell["metadata"]["audit_commit"] = commit

    ledger = (
        engine.ledger.service(data_dir=layer_path.parent)
        if engine is not None
        else LedgerService(data_dir=layer_path.parent)
    )
    ledger.ensure_layer_file(layer_path, shell=shell)
    submitted = len(out["events"])
    # RESOLVED by LedgerService.submit_events: report-reference stamping
    # (plan §4.4.0 step 1), deduplication, Merkle finalization, and signing
    # are now internal to the service — callers no longer manage these concerns.
    result = ledger.submit_events(
        layer_path,
        out["events"],
        report_path=audit_path,
        queue_items=out.get("needs_review"),
    )
    appended = len(result.event_ids) if result.event_ids is not None else submitted
    return {
        "appended": appended,
        "duplicates_skipped": submitted - appended,
        "queued": result.queue_added,
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    add_config_home_arg(parser)
    add_ledger_binding_args(parser)
    parser.add_argument("triage", help="validated TRIAGE.json / *-triage.json")
    parser.add_argument(
        "--audit", required=True, help="the *-security-audit.json the triage annotates"
    )
    parser.add_argument(
        "--layer",
        help="ledger to append to (default: alongside the "
        "audit, <base>-findings-layer.json; created if "
        "absent)",
    )
    parser.add_argument("--weights", type=Path, default=None)
    parser.add_argument(
        "--lint",
        help="verdict-citation lint JSON (lint_verdict_"
        "citations.py --json-out). Required for the FP "
        "auto-accept tier; without it every FP is "
        "countersign-gated",
    )
    parser.add_argument(
        "--tenancy-profile",
        choices=("multi_tenant", "single_tenant"),
        help="override the artifact-derived tenancy profile",
    )
    parser.add_argument(
        "--recorded-at",
        type=recorded_at_arg,
        help="override the append timestamp (RFC 3339)",
    )
    parser.add_argument(
        "--findings-root",
        help="findings tree that --layer, --lint and "
        "--register-out must resolve under "
        "(default: configured analysis-results/findings)",
    )
    parser.add_argument(
        "--register-out", help="refuted-register path (default: <layer-base>-refuted-register.json)"
    )
    args = parser.parse_args(argv)

    engine = load_engine(args.config_home)
    bind_ledger(engine, args)
    weights_path = args.weights or optional_config_path("hardening-risk-weights.json")

    try:
        triage = json.loads(Path(args.triage).read_text(encoding="utf-8"))
        audit = json.loads(Path(args.audit).read_text(encoding="utf-8"))
        if weights_path is None:
            print(
                "ERROR: hardening-risk-weights.json not found in "
                "$TRAUST_CONFIG_HOME; pass --weights",
                file=sys.stderr,
            )
            return 2
        weights = json.loads(Path(weights_path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        print(f"ERROR: cannot read inputs: {e}", file=sys.stderr)
        return 2

    lint_by_id = None
    audit_path = Path(args.audit)
    # --lint gates the auto-accept tier and --layer is a ledger write
    # target — neither may be a free path (self-audit -013 class). Confine
    # both under configured analysis-results/findings (or --findings-root).
    if args.findings_root:
        findings_roots = [Path(args.findings_root)]
        if not findings_roots[0].is_dir():
            print(f"ERROR: findings root {findings_roots[0]} not found", file=sys.stderr)
            return 2
    else:
        findings_roots = default_findings_roots(engine, audit_path)

    if args.lint:
        try:
            lint_path = _confine_path(args.lint, findings_roots, "--lint")
            lint_doc = json.loads(lint_path.read_text(encoding="utf-8"))
            lint_by_id = {r["id"]: r for r in lint_doc.get("results", [])}
        except (OSError, json.JSONDecodeError) as e:
            print(f"ERROR: cannot read lint results: {e}", file=sys.stderr)
            return 2

    if args.layer:
        layer_path = _confine_path(args.layer, findings_roots, "--layer")
    else:
        stem = audit_path.name
        # Naming rules (docs-verification 2026-07-31 P0-4, emitter leg;
        # keep in sync with emit_validation_ledger_events.layer_path_for):
        # cloud-config audits use the SHORT name like code audits — the
        # production cloud-config tree's ledgers all do — unless a code
        # audit shares the directory (companion IaC baseline), where
        # the short name would clobber the code audit's ledger.
        # Container reports always share the code audit's directory, so
        # their ledger artifacts keep the full stem (".json" fallback).
        if stem.endswith("-cloud-config-audit.json"):
            short = stem[: -len("-cloud-config-audit.json")]
            if (audit_path.parent / f"{short}-security-audit.json").is_file():
                short = stem[: -len(".json")]  # companion -> full stem
            layer_path = audit_path.parent / f"{short}-findings-layer.json"
        else:
            for suffix in ("-security-audit.json", ".json"):
                if stem.endswith(suffix):
                    stem = stem[: -len(suffix)]
                    break
            layer_path = audit_path.parent / f"{stem}-findings-layer.json"

    recorded_at = args.recorded_at or datetime.now(UTC).isoformat(timespec="seconds")
    source_ref = str(Path(args.triage).name)

    out = build_events(
        triage, audit, weights, lint_by_id, source_ref, recorded_at, args.tenancy_profile
    )
    counts = append_to_layer(
        layer_path, audit_path, audit, out, recorded_at, harness_version(triage), engine=engine
    )

    register_path = (
        _confine_path(args.register_out, findings_roots, "--register-out")
        if args.register_out
        else layer_path.with_name(
            layer_path.name.replace("-findings-layer.json", "-refuted-register.json")
        )
    )
    register_added = 0
    if out["register"]:
        # Same merge-append semantics as the validation emitter: the register
        # is shared between sources, so a triage emission must never clobber
        # validation-sourced entries (merge_register dedupes by
        # (finding_ref, asserted_by) and preserves the sources list).
        register_added = merge_register(register_path, source_ref, out["register"], recorded_at)

    by_validity = {}
    for e in out["events"]:
        v = e["disposition"]["validity"]
        by_validity[v] = by_validity.get(v, 0) + 1
    print(
        f"Ledger emission: {len(out['events'])} event(s) {by_validity} — "
        f"{counts['appended']} appended, "
        f"{counts['duplicates_skipped']} already present (idempotent), "
        f"{counts['queued']} review item(s) queued"
    )
    auto = sum(1 for e in out["events"] if e.get("auto_accept_tier"))
    fp_total = by_validity.get("false_positive", 0)
    if fp_total:
        print(f"  false positives: {auto} auto-accept tier, {fp_total - auto} countersign-gated")
    if (fp_total - auto) or counts["queued"]:
        print(
            "  NEXT: pending human decisions — run /countersign "
            "(`traust admin countersign queue`) to review and sign"
        )
    if out["register"]:
        print(f"  refuted register: {register_added} added -> {register_path}")
    for s in out["skipped"]:
        print(f"  skipped {s['id']} ({s['verdict']}): {s['reason']}")
    print(f"Layer: {layer_path}")
    return 0


if __name__ == "__main__":
    import sys

    from traust.cli.__main__ import main

    raise SystemExit(main(["ledger", "emit-triage", *sys.argv[1:]]))
