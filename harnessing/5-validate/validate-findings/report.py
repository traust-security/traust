#!/usr/bin/env python3
"""
Emit *-validation.{json,md} from execution results.
"""

from __future__ import annotations

import datetime as _dt
import json
import subprocess
import sys
from collections import Counter
from pathlib import Path

from traust_core.v1.models.artifacts import ValidationArtifact

if __package__:
    from . import soundness
    from .adapters import Fingerprint, StepResult
    from .chain import Chain
    from .ingest import Normalized
    from .scope import Scope
else:
    sys.path.insert(0, str(Path(__file__).parent))
    import soundness
    from adapters import Fingerprint, StepResult
    from chain import Chain
    from ingest import Normalized
    from scope import Scope


def harness_version() -> str:
    """Return '<VERSION>-<short-sha>' for the traust checkout."""
    here = Path(__file__).resolve()
    for p in here.parents:
        vf = p / "VERSION"
        if vf.is_file():
            ver = vf.read_text(encoding="utf-8").strip()
            try:
                sha = subprocess.run(
                    ["git", "-C", str(p), "rev-parse", "--short", "HEAD"],
                    capture_output=True,
                    text=True,
                    check=True,
                ).stdout.strip()
                return f"{ver}-{sha}"
            except (subprocess.CalledProcessError, FileNotFoundError):
                return ver
    return "unknown"


# ---------------------------------------------------------------------------
# JSON
# ---------------------------------------------------------------------------


def build_validation_json(
    n: Normalized,
    scope: Scope,
    results: list[StepResult],
    chains: list[Chain],
    fingerprints: list[Fingerprint],
    *,
    audit_path: str,
    audit_sha256: str,
    flags: list[str],
    approval: dict,
    novel_findings: list[dict] | None = None,
    target_attestation: dict | None = None,
    finding_assessments: dict[str, dict] | None = None,
) -> dict:
    allowed_assessments = {
        "evidence_grade",
        "grade_rationale",
        "severity_validation",
        "chain_context",
    }
    finding_ids = {finding.id for finding in n.findings}
    for finding_id, assessment in (finding_assessments or {}).items():
        if finding_id not in finding_ids:
            raise ValueError("finding assessment references an unknown planner finding")
        if set(assessment) - allowed_assessments:
            raise ValueError("finding assessments may only supply grade and review proposals")
    by_technique = Counter()
    for r in results:
        # technique is on the plan step, not StepResult; infer from refs
        if r.novel_ref:
            by_technique["novel"] += 1
        elif r.finding_ref:
            by_technique["replay"] += 1

    # roll up per source finding
    #
    # A finding's verdict is driven by its PRIMARY step(s) — the
    # replay/adapted step(s) that actually attempt the PoC.  Secondary
    # steps (chain glue, novel placeholders) are recorded for
    # traceability but do NOT set the verdict.  Without this
    # distinction a finding with no PoC (primary verdict
    # ``not_attempted: no-poc-no-adapter``) would be promoted to
    # ``blocked_by_scope`` by an unrelated chain-glue step, which
    # mis-categorises it on the dashboard.
    PRIMARY_VERBS = {
        "apply-manifest",
        "raw",
        "exec",
        "port-forward+http",
        "invoke-export",
        "network-probe",
        "noop",
        "rbac-can-i",
        "get",
        "describe",
        "create-cr",
        "patch-cr",
    }
    SKIP_VERBS = {"noop", "placeholder"}
    GLUE_VERBS = {"glue"}
    prec = {
        "confirmed": 0,
        "refuted": 1,
        "inconclusive": 2,
        "blocked_by_scope": 3,
        "not_attempted": 4,
    }

    validated: dict[str, dict] = {}
    audit_sources = [sr["path"] for sr in n.source_reports if sr["kind"] == "security-audit"]
    sole_source = (
        audit_sources[0]
        if len(audit_sources) == 1
        else n.source_reports[0]["path"]
        if len(n.source_reports) == 1
        else None
    )
    for f in n.findings:
        source_report = getattr(f, "source_report_path", None) or sole_source
        if source_report is None:
            raise ValueError("finding requires explicit unambiguous source report context")
        if f.id in validated:
            raise ValueError("duplicate planner finding identity")
        validated[f.id] = {
            "source_id": getattr(f, "source_id", None) or f.id,
            "source_report": source_report,
            "title": f.title,
            "claimed_severity": f.severity,
            "verdict": "not_attempted",
            "not_attempted_reason": None,
            "soundness_flag": None,  # set when a refutation was gated
            "technique": "skip",
            "steps": [],
            "evidence": [],
            "observed_impact": "",
            "deviation_from_claim": "",
            "rollback_performed": None,
            "evidence_grade": None,
            **(finding_assessments or {}).get(f.id, {}),
        }
    for r in results:
        if not r.finding_ref or r.finding_ref not in validated:
            continue
        vf = validated[r.finding_ref]
        rd = r.to_dict()
        vf["steps"].append(rd)
        vf["evidence"].extend(r.evidence)
        if r.rollback_performed is not None:
            vf["rollback_performed"] = r.rollback_performed

        verb = rd.get("verb", "")
        is_primary = verb in PRIMARY_VERBS and verb not in GLUE_VERBS
        if not is_primary:
            # Secondary (chain-glue / novel placeholder) — record but
            # do not drive the verdict.
            continue

        # Primary step.  noop/skip steps carry the planner's skip
        # reason (triage-FP, wrong-surface, needs-credential,
        # no-poc-no-adapter) — surface it so the dashboard can
        # categorise not_attempted correctly.
        reason = rd.get("scope_reason") or rd.get("reason") or rd.get("skip")
        if verb in SKIP_VERBS and r.verdict == "not_attempted":
            if vf["not_attempted_reason"] is None:
                vf["not_attempted_reason"] = reason
            continue

        # Real attempt — apply precedence among primary steps only.
        if prec.get(r.verdict, 5) < prec.get(vf["verdict"], 5):
            vf["verdict"] = r.verdict
            vf["observed_impact"] = r.observed
            vf["not_attempted_reason"] = (
                reason if r.verdict in ("not_attempted", "blocked_by_scope") else None
            )
            # The driving step's soundness flag travels with the verdict
            # (a soundness-gated step is `inconclusive` + flag).
            vf["soundness_flag"] = rd.get("soundness_flag")
        if vf["technique"] == "skip":
            vf["technique"] = "replay" if not r.novel_ref else "novel"

    # Refutation-soundness backstop (soundness.py): even when results
    # arrive from a path that bypassed the execute-time gate, a rolled-up
    # `refuted` whose every refuting probe is unsound downgrades to
    # `inconclusive` with the machine-readable flag.
    for vf in validated.values():
        if vf["verdict"] != "refuted" or vf.get("soundness_flag"):
            continue
        flag = soundness.flag_validated_finding(vf)
        if flag:
            vf["verdict"] = "inconclusive"
            vf["soundness_flag"] = flag

    # by_verdict counts rolled-up findings, not individual steps.
    # Also bucket not_attempted by skip_reason category so the report
    # can distinguish intentional skips from environment failures.
    by_verdict = Counter(vf["verdict"] for vf in validated.values())
    for k in ("confirmed", "refuted", "inconclusive", "blocked_by_scope", "not_attempted"):
        by_verdict.setdefault(k, 0)

    def _na_cat(reason: str | None) -> str:
        r = (reason or "").lower()
        if "false-positive" in r:
            return "triage_fp"
        if r.startswith("wrong-surface"):
            return "wrong_surface"
        if r.startswith("needs-credential"):
            return "needs_credential"
        if "no-poc" in r or "no-adapter" in r:
            return "no_poc"
        if r.startswith("precondition") or "not-found" in r or "missing" in r:
            return "env"
        if r.startswith("destructive"):
            return "policy"
        return "other"

    not_attempted_by_reason = Counter(
        _na_cat(vf["not_attempted_reason"])
        for vf in validated.values()
        if vf["verdict"] == "not_attempted"
    )

    # Findings deferred to the second (real-credential) pass.
    needs_credential = [
        {
            "source_id": vf["source_id"],
            "title": vf["title"],
            "severity": vf["claimed_severity"],
            "credential_ref": (vf["not_attempted_reason"] or "").split(":", 1)[-1],
        }
        for vf in validated.values()
        if (vf["not_attempted_reason"] or "").startswith("needs-credential")
    ]

    # chains → schema shape.
    # Keep chain entries bounded references, with the required step context.
    # Transcripts/evidence remain on validated_findings, not copied per chain.
    results_by_fid: dict[str, list] = {}
    for r in results:
        if r.finding_ref:
            results_by_fid.setdefault(r.finding_ref, []).append(r)

    chain_results = []
    for c in chains:
        c_steps = []
        c_verdict = "not_attempted"
        # A chain is a PATH: entry point to terminal asset, one step per
        # finding actually attempted along it.
        #
        # Two filters, both load-bearing. Their absence once produced a
        # multi-gigabyte artifact: hundreds of steps per chain where a
        # healthy chain carries a handful.
        #
        #   GLUE steps are connectors, not path steps. The verdict logic
        #   above already excludes them for exactly this reason; chain
        #   assembly never applied the same rule. Glue carried the bulk
        #   of the blowup, most of it a single cascaded
        #   `precondition-failed` repeated against the same finding_ref.
        #
        #   DE-DUPLICATION by step_id. results_by_fid holds every result
        #   recorded for a finding, so each chain re-appended all of them
        #   -- the cartesian product of chains x findings x results.
        #
        # Both are one-line `continue`s that nothing would have caught
        # being removed, so tests/test_validation_chain_blowup.py now
        # holds the guard: a comment cannot fail a build.
        seen_steps: set = set()
        for fid in c.finding_ids:
            for r in results_by_fid.get(fid, ()):
                if getattr(r, "verb", "") in GLUE_VERBS:
                    continue
                step_id = getattr(r, "step_id", None)
                if step_id is not None and step_id in seen_steps:
                    continue
                if step_id is not None:
                    seen_steps.add(step_id)
                c_steps.append(
                    {
                        "step_id": step_id,
                        "finding_ref": r.finding_ref,
                        "verdict": r.verdict,
                        "verb": r.verb,
                        **{
                            field: getattr(r, field)
                            for field in ("adapter", "classification")
                            if hasattr(r, field)
                        },
                    }
                )
                if r.verdict == "confirmed":
                    c_verdict = "confirmed"
                elif c_verdict == "not_attempted":
                    c_verdict = r.verdict
        if len(c_steps) < 2:
            continue
        chain_results.append(
            {
                "chain_id": c.chain_id,
                "name": c.name or f"{c.entry_point} → {c.terminal_asset}",
                "entry_point": c.entry_point,
                "terminal_asset": c.terminal_asset,
                "mitre_attack_refs": c.mitre,
                "steps": c_steps,
                "verdict": c_verdict,
                "narrative": c.narrative,
            }
        )

    highest = None
    for c in chain_results:
        if c["verdict"] == "confirmed":
            highest = c["chain_id"]
            break

    return {
        "title": f"Live Validation Report — {n.target_name}",
        "metadata": {
            "date": _dt.date.today().isoformat(),
            "harness_version": harness_version(),
            "scope_binding_mode": scope.binding_mode,
            "scope_source": scope.engagement or "(inline/inferred)",
            "engagement": scope.engagement,
            "authorized_by": scope.authorized_by,
            "expires": scope.expires.isoformat() if scope.expires else None,
            "target_fingerprint": [fp.to_dict() for fp in fingerprints],
            # Runs against different targets are distinct statements.
            "target_environment": scope.target_environment(),
            "approval": approval,
            "flags": flags,
            "target_attestation": target_attestation,
            "additional": {
                "validation_producer": {
                    **({"expires_at": scope.expires_at.isoformat()} if scope.expires_at else {}),
                    "not_attempted_by_reason": dict(not_attempted_by_reason),
                    "by_surface": dict(
                        Counter(getattr(f, "surface", "runtime") for f in n.findings)
                    ),
                    "needs_credential_count": len(needs_credential),
                    "needs_credential": needs_credential,
                    "findings": [
                        {
                            "source_report": validated[f.id]["source_report"],
                            "source_id": validated[f.id]["source_id"],
                            "planner_id": f.id,
                            "surface": getattr(f, "surface", "runtime"),
                        }
                        for f in n.findings
                    ],
                }
            },
        },
        "source_reports": n.source_reports,
        "summary": {
            "by_verdict": dict(by_verdict),
            "by_technique": dict(by_technique),
            "novel_count": len(novel_findings or []),
            "chain_count": len(chain_results),
            "highest_impact_chain": highest,
        },
        "validated_findings": list(validated.values()),
        "attack_chains": chain_results,
        "novel_findings": novel_findings or [],
        "execution_log_ref": audit_path,
        "execution_log_sha256": audit_sha256,
    }


# ---------------------------------------------------------------------------
# Markdown
# ---------------------------------------------------------------------------

VERDICT_BADGE = {
    "confirmed": "✅ CONFIRMED",
    "refuted": "❌ REFUTED",
    "inconclusive": "❔ INCONCLUSIVE",
    "blocked_by_scope": "🛑 BLOCKED BY SCOPE",
    "not_attempted": "⏭ NOT ATTEMPTED",
}


def render_markdown(doc: dict) -> str:
    L: list[str] = []
    L.append(f"# {doc['title']}\n")
    md = doc["metadata"]
    L.append("| | |")
    L.append("|---|---|")
    L.append(f"| **Date** | {md['date']} |")
    L.append(f"| **Harness version** | `{md['harness_version']}` |")
    L.append(f"| **Scope binding** | {md['scope_binding_mode']} ({md.get('scope_source', '')}) |")
    if md.get("engagement"):
        L.append(f"| **Engagement** | {md['engagement']} |")
    if md.get("authorized_by"):
        L.append(f"| **Authorized by** | {md['authorized_by']} |")
    L.append(f"| **Approval** | {md.get('approval', {}).get('mode', '')} |")
    L.append(
        f"| **Audit log** | `{doc['execution_log_ref']}`"
        f" (`{doc.get('execution_log_sha256', '')[:12]}…`) |"
    )
    L.append("")

    s = doc["summary"]
    L.append("## Summary\n")
    L.append("| Verdict | Count |")
    L.append("|---|---:|")
    for k in ("confirmed", "refuted", "inconclusive", "blocked_by_scope", "not_attempted"):
        L.append(f"| {VERDICT_BADGE[k]} | {s['by_verdict'].get(k, 0)} |")
    L.append("")
    L.append(
        f"**Attack chains:** {s.get('chain_count', 0)} "
        f"(highest-impact confirmed: `{s.get('highest_impact_chain') or '—'}`)  "
    )
    L.append(f"**Novel findings:** {s.get('novel_count', 0)}\n")

    L.append("## Source reports\n")
    for sr in doc["source_reports"]:
        L.append(f"- **{sr['kind']}** — `{sr['path']}` (`{sr.get('sha256', '')[:12]}…`)")
    L.append("")

    L.append("## Validated findings\n")
    for vf in doc["validated_findings"]:
        L.append(
            f"### {vf['source_id']} — {VERDICT_BADGE[vf['verdict']]} — {vf.get('title', '')}\n"
        )
        L.append("| | |")
        L.append("|---|---|")
        L.append(f"| **Claimed severity** | {vf.get('claimed_severity', '')} |")
        L.append(f"| **Technique** | {vf['technique']} |")
        L.append(f"| **Rollback** | {vf.get('rollback_performed')} |")
        if vf.get("soundness_flag"):
            L.append(
                f"| **Soundness gate** | `{vf['soundness_flag']}` — "
                "refutation un-emittable; routed to needs_review |"
            )
        if vf.get("deviation_from_claim"):
            L.append(f"| **Deviation** | {vf['deviation_from_claim']} |")
        L.append("")
        if vf.get("observed_impact"):
            L.append("**Observed:**")
            L.append("```")
            L.append(vf["observed_impact"][:2000])
            L.append("```")
        if vf.get("evidence"):
            L.append("**Evidence:**")
            for ev in vf["evidence"]:
                L.append(f"- `{ev['path']}` — {ev.get('caption', '')}")
        L.append("")

    if doc["attack_chains"]:
        L.append("## Attack chains\n")
        for c in doc["attack_chains"]:
            L.append(f"### {c['chain_id']} — {VERDICT_BADGE[c['verdict']]} — {c['name']}\n")
            L.append(f"**Entry point:** {c['entry_point']}  ")
            L.append(f"**Terminal asset:** {c['terminal_asset']}  ")
            if c.get("mitre_attack_refs"):
                L.append(f"**MITRE ATT&CK:** {', '.join(c['mitre_attack_refs'])}  ")
            L.append("")
            L.append("```")
            L.append(c.get("narrative", ""))
            L.append("```")
            L.append("")

    if doc["novel_findings"]:
        L.append("## Novel findings\n")
        for nf in doc["novel_findings"]:
            L.append(f"### {nf['id']} — {nf.get('severity', '').upper()} — {nf.get('title', '')}\n")
            L.append(f"**Discovery:** {nf.get('discovery_method', '')}  ")
            L.append(f"**CWE:** {', '.join(nf.get('cwes', []))}  ")
            L.append("")
            L.append(nf.get("description", ""))
            L.append("")

    L.append("---")
    L.append(
        f"*Generated by validate-findings harness `{md['harness_version']}`. "
        f"All actions logged to `{doc['execution_log_ref']}`.*"
    )
    return "\n".join(L) + "\n"


# ---------------------------------------------------------------------------
# write
# ---------------------------------------------------------------------------


def write(doc: dict, out_dir: Path, target_name: str) -> tuple[Path, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    jpath = out_dir / f"{target_name}-validation.json"
    mpath = out_dir / f"{target_name}-validation.md"
    # strip None to satisfy schema additionalProperties
    clean = json.loads(json.dumps(doc, default=str))
    _strip_nones(clean)
    for finding in clean["validated_findings"]:
        finding.setdefault("evidence_grade", None)
    payload = (json.dumps(clean, indent=2) + "\n").encode("utf-8")
    artifact = ValidationArtifact.parse(payload)
    jpath.write_bytes(artifact.payload)
    mpath.write_text(render_markdown(doc), encoding="utf-8")
    return jpath, mpath


def _strip_nones(obj):
    if isinstance(obj, dict):
        for k in [k for k, v in obj.items() if v is None]:
            del obj[k]
        for v in obj.values():
            _strip_nones(v)
    elif isinstance(obj, list):
        for v in obj:
            _strip_nones(v)
