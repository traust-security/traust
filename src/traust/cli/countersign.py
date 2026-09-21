#!/usr/bin/env python3
"""
Countersign workbench: the human inbox for the disposition ledger.

`refuted_awaiting_signoff` and pending `needs_review` items are derived,
per-repo state — this tool aggregates them into one place and makes each
decision self-contained, so a reviewer never needs the original report
open to remember what they are signing.

Modes:

  queue   Walk a findings tree (or one repo dir), derive every pending
          decision, and render one DECISION CARD per item: the audit
          claim, the machine refutation with its lint-verified evidence,
          and exactly what signing records. Writes countersign-queue.md
          (annotatable) and optional JSON.

  apply   Ingest an annotated countersign-queue.md: parse each card's
          DECISION/RATIONALE lines, resolve the signer from the ledger
          identity token once, submit the human events through the
          ledger SDK (canonical ids, actor stamped from the token,
          finalized and signed), rebuild the cumulative report(s), and
          print a receipt.

  record  Same recording path for a single decision from the CLI.

Decisions:
  false_positive  countersign the machine refutation (blank rationale
                  adopts the machine rationale, explicitly framed as such)
  keep_open       reject the refutation — records a human `confirmed`
                  validity event; a rationale in your own words is REQUIRED
  confirm_mapping countersign a rebaseline alias proposal (same
                  vulnerability across scans) — the superseded finding's
                  ledger history transfers to the new id at the next merge
  reject_mapping  refuse a rebaseline proposal — recorded with attribution,
                  never re-proposed
  defer           leave it pending (no event)

Human overrides (harness >= 0.128.0 — findings need NOT be in the queue;
rationale in the signer's own words is REQUIRED for all three):
  reopen                   flip a false positive back to confirmed
                           (records a human `confirmed`)
  override_false_positive  flip a confirmed/open finding to false positive;
                           evidence-class precedence still applies — over an
                           execution proof a SECOND independent signer must
                           concur before validity flips
  severity=<level>         severity upgrade/downgrade (critical|high|medium|
                           low|informational). The audit report's severity is
                           never rewritten — the cumulative report carries it
                           as effective_severity + a severity_overrides table
                           (CLI form: --decision severity --severity <level>)

The safeguards: the signer is whoever holds the ledger identity token
(`ledger auth login` against an OIDC provider, or `ledger auth local
--identity <you>`); the SDK verifies the token and stamps that identity on
every event it writes, so nothing this CLI asserts about the signer reaches
the layer. Recording is refused without a verifiable token. Every event
carries a rationale and attribution, and a countersigned FP stays in the
refuted register, overridable by execution evidence.

Usage:
  traust countersign queue
      (defaults to configured findings tree from $TRAUST_CONFIG_HOME/locations.yaml)
  traust countersign queue --root <analysis-results>/findings --out countersign-queue.md
  traust countersign queue --repo-dir <findings>/<prod>/<repo>
  python3 -m traust.cli.countersign apply countersign-queue.md
  python3 -m traust.cli.countersign record --layer <repo>-findings-layer.json \\
      --finding REPO-abc1234-010 --decision false_positive [--rationale "..."]
"""

import argparse
import contextlib
import json
import os
import re
import sys
from datetime import UTC, datetime
from pathlib import Path

from traust_contracts.v1.models.layer import LayerActor
from traust_engine.ledger import (
    LedgerError,
    LedgerService,
)

# --- track-findings import (hardened) --------------------------------------
# The merge engine lives in harnessing/4-triage/track-findings. Fail LOUDLY when it is
# absent, and never fall through to an ambient sys.path lookup: inserting a
# non-existent directory would let a same-named module planted in the CWD (or
# anywhere else on sys.path) silently hijack the recording path.
# The merge engine is a sibling module of the installed package, so it is
# imported normally. This is what the previous vendoring guard was protecting:
# the old code inserted a skill directory onto sys.path and imported by bare
# name, which a same-named module planted earlier on sys.path could hijack to
# forge ledger state. A package-relative import has no such surface.
from traust.cli.build_cumulative import (
    build_cumulative,
    derive_disposition,
    render_markdown,
)
from traust.context import (
    add_config_home_arg,
    findings_tree_dir,
    load_engine,
)
from traust.lib.event_time import recorded_at_arg

DECISIONS = (
    "false_positive",
    "keep_open",
    "confirm_mapping",
    "reject_mapping",
    "defer",
)
SEVERITY_LEVELS = ("critical", "high", "medium", "low", "informational")
# Human-initiated overrides (harness >= 0.128.0) — findings need not be in
# the derived queue: `reopen` flips a false positive back to confirmed,
# `override_false_positive` flips a confirmed/open finding to FP, and
# `severity=<level>` records an up/downgrade. All three REQUIRE a rationale
# in the signer's own words (no adopted-rationale fallback).
OVERRIDE_DECISIONS = ("reopen", "override_false_positive")
CARD_MARK = re.compile(r"<!-- countersign finding=(?P<finding>\S+) layer=(?P<layer>\S+) -->")
# Anchored to line start (re.M): the card template writes its DECISION
# line at column 0, while every piece of untrusted text (titles,
# descriptions, rationales, paths) is embedded mid-line via _clip —
# which additionally neutralizes the DECISION:/[x] tokens themselves.
# Both layers exist because a description that forged a decision line
# was a confirmed attack (harness-security-assessment-2026-07-31 C1).
DECISION_LINE = re.compile(
    r"^DECISION:.*?\[(?P<mark>[xX])\]\s*"
    r"(?P<decision>false_positive|keep_open|confirm_mapping|reject_mapping"
    r"|reopen|override_false_positive"
    r"|severity=(?:critical|high|medium|low|informational)|defer)",
    re.M,
)
RATIONALE_PLACEHOLDER = (
    "(required for keep_open; blank adopts the machine rationale for false_positive)"
)


# A findings layer's baseline is not always a *-security-audit.json:
# container and cloud-config lanes name theirs differently. Resolving
# only the security-audit shape silently skipped those ledgers — their
# queue items never surfaced and findings-current went stale after a
# signature (docs-verification 2026-07-31, P0-4).
BASELINE_SUFFIXES = (
    "-security-audit.json",
    "-container-audit.json",
    "-cloud-config-audit.json",
)


def baseline_for(layer_path: Path) -> Path | None:
    """The audit baseline sitting beside a *-findings-layer.json.

    Two layer-naming conventions exist (emit_triage_ledger_events.py):
    code audits strip their suffix (<repo>-findings-layer.json →
    <repo>-security-audit.json), while container/cloud-config layers
    keep the full audit stem to avoid clobbering the code audit's
    ledger (<x>-container-audit-findings-layer.json →
    <x>-container-audit.json).
    """
    stem = layer_path.name[: -len("-findings-layer.json")]
    candidates = []
    if stem.endswith(("-container-audit", "-cloud-config-audit", "-security-audit")):
        candidates.append(stem + ".json")  # full-stem convention
    candidates.extend(stem + s for s in BASELINE_SUFFIXES)
    for name in candidates:
        cand = layer_path.with_name(name)
        if cand.is_file():
            return cand
    return None


# ---------------------------------------------------------------------------
# discovery
# ---------------------------------------------------------------------------


def discover_pending(roots: list[Path]) -> list[dict]:
    """Every awaiting-signoff finding and pending needs_review item."""
    items = []
    for root in roots:
        layers = (
            [root]
            if root.name.endswith("-findings-layer.json")
            else sorted(root.rglob("*-findings-layer.json"))
        )
        for lj in layers:
            if lj.is_symlink():
                continue
            aj = baseline_for(lj)
            if aj is None:
                continue
            try:
                layer = json.loads(lj.read_text(encoding="utf-8"))
                audit = json.loads(aj.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            tj = lj.with_name(lj.name.replace("-findings-layer.json", "-triage.json"))
            triage_by_orig = {}
            if tj.is_file():
                try:
                    tdoc = json.loads(tj.read_text(encoding="utf-8"))
                    triage_by_orig = {f.get("orig_id"): f for f in tdoc.get("findings", [])}
                except (OSError, json.JSONDecodeError):
                    pass

            events_by = {}
            for e in layer.get("events", []):
                events_by.setdefault(e["finding_ref"], []).append(e)

            for f in audit.get("findings", []):
                evs = events_by.get(f["id"], [])
                if not evs:
                    continue
                disp = derive_disposition(f, evs, "1970-01-01T00:00:00+00:00")
                fp_events = [e for e in evs if e["disposition"].get("validity") == "false_positive"]
                common = {
                    "layer": str(lj),
                    "finding": f,
                    "triage": triage_by_orig.get(f["id"]),
                    "disposition": disp,
                }
                if disp.get("refuted_awaiting_signoff"):
                    items.append(
                        {
                            "kind": "awaiting_signoff",
                            "refutation": fp_events[-1],
                            **common,
                        }
                    )
                # Attention states — one card per finding, worst-first.
                elif disp.get("fp_overridden"):
                    items.append(
                        {
                            "kind": "fp_overridden",
                            "refutation": fp_events[-1] if fp_events else None,
                            **common,
                        }
                    )
                elif disp.get("fp_reassertion_blocked"):
                    items.append(
                        {
                            "kind": "fp_reassertion_blocked",
                            "refutation": fp_events[-1] if fp_events else None,
                            **common,
                        }
                    )
                elif disp.get("conflict"):
                    items.append(
                        {
                            "kind": "conflict",
                            "refutation": fp_events[-1] if fp_events else None,
                            **common,
                        }
                    )
            for item in layer.get("needs_review", []):
                if item.get("status") == "pending":
                    items.append({"kind": "needs_review", "layer": str(lj), "review_item": item})

            # Unconfirmed rebaseline aliases (finding_identity.py): each is
            # a proposed old->new mapping awaiting a human confirm/reject.
            findings_by_id = {f["id"]: f for f in audit.get("findings", [])}
            old_report_cache = {}
            for key, al in ((layer.get("metadata") or {}).get("finding_aliases") or {}).items():
                if al.get("confirmed") or al.get("rejected"):
                    continue
                old_f = None
                rep_name = al.get("from_report")
                if rep_name:
                    if rep_name not in old_report_cache:
                        cand = [
                            lj.parent / rep_name,
                            *lj.parent.parent.glob(f"*/{rep_name}"),
                        ]
                        doc = None
                        for c in cand:
                            if c.is_file():
                                try:
                                    doc = json.loads(c.read_text(encoding="utf-8"))
                                except (OSError, json.JSONDecodeError):
                                    doc = None
                                break
                        old_report_cache[rep_name] = doc
                    doc = old_report_cache[rep_name]
                    old_id = key.rsplit(":", 1)[-1]
                    if doc:
                        old_f = next(
                            (f for f in doc.get("findings", []) if f.get("id") == old_id),
                            None,
                        )
                items.append(
                    {
                        "kind": "rebaseline_alias",
                        "layer": str(lj),
                        "alias_key": key,
                        "alias": al,
                        "old_finding": old_f,
                        "new_finding": findings_by_id.get(al.get("new_id")),
                    }
                )
    return items


# ---------------------------------------------------------------------------
# cards
# ---------------------------------------------------------------------------


def _clip(text, n):
    """Clip AND sanitize untrusted text for embedding in queue markdown.

    Finding titles/rationales come from hostile repository content: strip
    control characters, collapse newlines (a newline in a heading would
    let a title fabricate its own card structure), and neutralize HTML
    comment markers so injected text can never forge or terminate a
    `<!-- countersign ... -->` card marker.
    """
    text = " ".join(str(text or "").split())
    text = "".join(ch for ch in text if ch.isprintable())
    text = text.replace("<!--", "<\\!--").replace("-->", "--\\>")
    # Decision-forgery neutralization (assessment 2026-07-31 C1): a
    # description carrying "DECISION: [x] false_positive RATIONALE: …"
    # must never parse as the human's decision. The parser needs the
    # literal tokens; break them visibly but readably.
    text = re.sub(r"(?i)DECISION\s*:", "DECISION∶", text)
    text = re.sub(r"(?i)RATIONALE\s*:", "RATIONALE∶", text)
    text = re.sub(r"\[\s*[xX]\s*\]", "[×]", text)
    return text[:n] + ("…" if len(text) > n else "")


# ---- raw probe output for machine refutations -----------------------------
# A card for a machine (live-validation) refutation must show the probe's
# raw `observed` output VERBATIM — the squashed rationale alone hid that
# "refuted" often meant `Forbidden: User "<probe-user>" ...` (fp-live-refuted.md).

RAW_OBSERVED_CAP = 1600
_REPORT_CACHE: dict = {}


def _results_root_for(layer_path, rel_ref: str):
    """Walk up from the layer file to the tree that contains rel_ref
    (the validation report path is recorded relative to the results
    root, e.g. `validations/<product>/<product>-validation.json`)."""
    try:
        parents = Path(layer_path).resolve().parents
    except OSError:
        return None
    for parent in parents:
        if (parent / rel_ref).is_file():
            return parent
    return None


def raw_probe_observed(item: dict):
    """(raw_text | None, unavailability_reason) for a machine refutation.

    Resolves the refutation event's validation report, finds the
    validated finding, and returns its probe `observed` output raw
    (observed_impact, else the first refuted step's observed, else the
    first readable evidence artifact)."""
    ref = item.get("refutation") or {}
    src = ref.get("source") or {}
    if src.get("type") != "validation_report":
        return None, ""  # not a live-validation refutation — no probe ran
    rel = str(src.get("ref") or "")
    root = _results_root_for(item.get("layer", ""), rel) if rel else None
    if root is None:
        return None, f"validation report `{rel}` not found near the layer"
    rp = (root / rel).resolve()
    if rp not in _REPORT_CACHE:
        try:
            _REPORT_CACHE[rp] = json.loads(rp.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            _REPORT_CACHE[rp] = None
    doc = _REPORT_CACHE[rp]
    if doc is None:
        return None, f"could not read/parse `{rel}`"
    fid = item["finding"]["id"]
    cands = [
        vf
        for vf in doc.get("validated_findings") or []
        if str(vf.get("source_id") or "").rsplit("/", 1)[-1] == fid
    ]
    refuted = [vf for vf in cands if vf.get("verdict") == "refuted"]
    vf = (refuted or cands or [None])[0]
    if vf is None:
        return None, f"finding {fid} not present in `{rel}`"
    raw = str(vf.get("observed_impact") or "")
    if not raw:
        for step in vf.get("steps") or []:
            if step.get("verdict") == "refuted" and step.get("observed"):
                raw = str(step["observed"])
                break
    if not raw:
        for evref in ref.get("evidence_refs") or []:
            p = root / str(evref).split("#", 1)[0]
            if p.is_file():
                try:
                    raw = p.read_text(encoding="utf-8")
                    break
                except OSError:
                    continue
    if not raw:
        return None, "no observed output recorded for the refuting probe"
    return raw, ""


def _verbatim_block(raw: str, cap: int = RAW_OBSERVED_CAP) -> list[str]:
    """Render raw output as an indented code block — verbatim bytes with a
    uniform 4-space prefix, immune to fences/`---` breaking the card
    parser."""
    text = raw[:cap]
    lines = ["    " + ln for ln in text.splitlines()]
    if len(raw) > cap:
        lines.append(
            f"    … [truncated at {cap} of {len(raw)} chars — full text in the evidence artifacts]"
        )
    return lines


def _confine_layer(layer_path: str, root: Path) -> Path:
    """Resolve a layer= path and require it under the findings root.

    Card markers in an annotated queue (and --layer CLI arguments) are
    untrusted: without confinement a crafted `layer=` path would let the
    apply step write attacker-chosen ledger files anywhere on disk,
    attributed to the human signer.
    """
    root_r = Path(root).resolve()
    lp = Path(layer_path)
    resolved = (lp if lp.is_absolute() else root_r / lp).resolve()
    try:
        resolved.relative_to(root_r)
    except ValueError:
        raise ValueError(
            f"layer path {layer_path!r} resolves outside the findings root "
            f"{root_r} — refusing (pass --root if your findings tree lives "
            "elsewhere)"
        ) from None
    if not resolved.name.endswith("-findings-layer.json"):
        raise ValueError(
            f"layer path {layer_path!r} does not name a *-findings-layer.json file — refusing"
        )
    return resolved


def _safe_id(fid) -> str:
    """Finding ids are embedded in card markers — restrict to marker-safe
    characters so a hostile id can never terminate or forge a marker."""
    return re.sub(r"[^A-Za-z0-9._:-]", "", str(fid or ""))[:128]


def render_card(item: dict, idx: int, total: int, base: Path) -> str:
    f = item["finding"]
    ref = item["refutation"]
    lines = []
    try:
        layer_rel = str(Path(item["layer"]).resolve().relative_to(Path(base).resolve()))
    except (ValueError, TypeError):
        layer_rel = item["layer"]
    lines.append(f"<!-- countersign finding={_safe_id(f['id'])} layer={layer_rel} -->")
    lines.append(f"### {idx}/{total} — `{_safe_id(f['id'])}` — {_clip(f.get('title', ''), 160)}")
    lines.append("")
    loc = (f.get("locations") or [{}])[0]
    lines.append(
        f"**THE CLAIM** (audit · claimed {f.get('severity', '?')} · {f.get('category', '-')})"
    )
    lines.append(
        f"`{_clip(loc.get('path', '?'), 200)}"
        + (f":{_clip(loc.get('lines'), 40)}" if loc.get("lines") else "")
        + "`"
    )
    lines.append("")
    lines.append("> " + _clip(f.get("description"), 450))
    lines.append("")
    tri = item.get("triage") or {}
    vb = tri.get("vote_breakdown") or {}
    vote_s = (
        f"{vb.get('true_positive', 0)}T/{vb.get('hardening', 0)}H/{vb.get('false_positive', 0)}F"
        if vb
        else "n/a"
    )
    actor = ref["source"]["actor"]
    lines.append(
        f"**THE REFUTATION** ({actor.get('identity', 'machine')} · "
        f"{(ref.get('occurred_at') or ref['recorded_at'])[:10]} · "
        f"votes {vote_s}"
        + (f" · confidence {tri.get('confidence')}" if tri.get("confidence") is not None else "")
        + (f" · exclusion rule {tri.get('exclusion_rule')}" if tri.get("exclusion_rule") else "")
        + ")"
    )
    lines.append("")
    lines.append("> " + _clip(ref.get("rationale"), 700))

    # P2: when the refutation came from a validation run, surface the
    # target attestation beside the transcript — an unattested run should
    # never have reached this queue, so its absence on older reports is
    # itself information for the signer.
    src_ref = (ref.get("source") or {}).get("ref") or ""
    if "validation" in src_ref:
        att = None
        att_path = Path(base) / Path(src_ref).parent / "target-attestation.json"
        with contextlib.suppress(OSError, ValueError):
            att = json.loads(att_path.read_text(encoding="utf-8"))
        if att is not None:
            ok = sum(1 for c in att.get("checks", []) if c.get("ok"))
            lines.append("")
            lines.append(
                f"**TARGET ATTESTATION**: "
                f"{'ATTESTED' if att.get('attested') else 'FAILED'} "
                f"({ok}/{len(att.get('checks', []))} checks · "
                f"{(att.get('fingerprint') or {}).get('openshift_version') or 'no fingerprint'})"
            )
        else:
            lines.append("")
            lines.append(
                "**TARGET ATTESTATION**: none recorded "
                "(pre-0.176.0 run — weigh the refutation accordingly)"
            )
    raw, why = raw_probe_observed(item)
    if raw is not None:
        lines.append("")
        lines.append(
            "**RAW PROBE OUTPUT** (`observed`, verbatim — judge the "
            "refutation on THIS, not the rationale):"
        )
        lines.append("")
        lines.extend(_verbatim_block(raw))
    elif why:
        lines.append("")
        lines.append(
            f"**RAW PROBE OUTPUT:** unavailable — {why}. Treat the "
            "refutation with suspicion (keep_open/defer) if the "
            "rationale alone cannot justify signing."
        )
    if ref.get("evidence_refs"):
        lines.append("")
        lines.append(
            "Evidence (lint-verified): " + ", ".join(f"`{e}`" for e in ref["evidence_refs"][:6])
        )
    lines.append("")
    lines.append(
        "**IF YOU SIGN:** validity → false_positive, attributed to "
        "you (identity-verified). The finding stays in the refuted "
        "register — a reproducing exploit from fuzzing or live "
        "validation can still override your signature "
        "(`fp_overridden`)."
    )
    lines.append("")
    lines.append("DECISION: [ ] false_positive   [ ] keep_open   [ ] defer")
    lines.append(f"RATIONALE: {RATIONALE_PLACEHOLDER}")
    lines.append("")
    lines.append("---")
    return "\n".join(lines)


def render_attention_card(item: dict, idx: int, total: int, base: Path) -> str:
    """Cards for derived attention states: fp_overridden (awareness),
    fp_reassertion_blocked (second signer needed), conflict (adjudicate).
    Blocked/conflict cards carry DECISION markers — a human validity
    determination resolves them; overridden cards are informational."""
    f = item["finding"]
    kind = item["kind"]
    try:
        layer_rel = str(Path(item["layer"]).resolve().relative_to(Path(base).resolve()))
    except (ValueError, TypeError):
        layer_rel = item["layer"]
    header = {
        "fp_overridden": "⚡ FP OVERRIDDEN BY EXECUTION EVIDENCE",
        "fp_reassertion_blocked": "🔒 SECOND SIGNER NEEDED (two-person rule)",
        "conflict": "⚠️ CONFLICTING DETERMINATIONS — adjudicate",
    }[kind]
    lines = []
    if kind != "fp_overridden":
        lines.append(f"<!-- countersign finding={_safe_id(f['id'])} layer={layer_rel} -->")
    lines.append(
        f"### {idx}/{total} — {header} — `{_safe_id(f['id'])}` — {_clip(f.get('title', ''), 160)}"
    )
    lines.append("")
    if kind == "fp_overridden":
        lines.append(
            "A reproducing exploit/crash confirmed this finding over a "
            "prior human false-positive assertion (both events remain in "
            "the ledger with attribution). No action is required — validity "
            "is `confirmed`. Re-asserting false positive now requires TWO "
            "independent identity-verified humans addressing the PoC."
        )
    elif kind == "fp_reassertion_blocked":
        lines.append(
            "One human re-asserted false positive AFTER execution-verified "
            "confirmation. The two-person rule holds validity at "
            "`confirmed` until a SECOND independent identity-verified human "
            "concurs. If you are that second reviewer and you concur, mark "
            "false_positive below WITH your own rationale addressing the "
            "PoC; keep_open leaves the confirmation standing."
        )
    else:
        lines.append(
            "The ledger carries both `confirmed` and `false_positive` "
            "determinations for this finding. Adjudicate: your decision "
            "below records a fresh human determination (rationale in your "
            "own words required either way for a conflict)."
        )
    if item.get("refutation"):
        lines.append("")
        lines.append("> Last FP rationale: " + _clip(item["refutation"].get("rationale"), 400))
    if kind != "fp_overridden":
        lines.append("")
        lines.append("DECISION: [ ] false_positive   [ ] keep_open   [ ] defer")
        lines.append(f"RATIONALE: {RATIONALE_PLACEHOLDER}")
    lines.append("")
    lines.append("---")
    return "\n".join(lines)


def render_review_card(item: dict, idx: int, total: int) -> str:
    ri = item["review_item"]
    return "\n".join(
        [
            f"### {idx}/{total} — needs_review "
            f"({_clip(ri.get('queue_reason', '?'), 60)}) — "
            f"`{_safe_id(ri.get('suggested_finding_ref', '?'))}`",
            "",
            f"**Author:** {_clip(ri.get('author'), 80)} · "
            f"**Source:** {_clip(ri.get('source_ref'), 160)}",
            "",
            "> " + _clip(ri.get("quote"), 450),
            "",
            "Resolve via `/track-findings <report> --interactive` (confirm or "
            "reject with a resolution note).",
            "",
            "---",
        ]
    )


def _fmt_finding(f, label):
    if not f:
        return [f"**{label}:** (report not found beside the layer — review from the ids above)"]
    paths = ", ".join(
        sorted({_clip(loc.get("path", "?"), 120) for loc in f.get("locations", [])})[:4]
    )
    return [
        f"**{label}:** `{f.get('id')}` [{f.get('severity')}] {_clip(f.get('title'), 110)}",
        f"  · CWEs {', '.join(f.get('cwes', [])[:3])} · {paths}",
    ]


def render_alias_card(item: dict, idx: int, total: int, base: Path) -> str:
    al, key = item["alias"], item["alias_key"]
    layer_rel = os.path.relpath(item["layer"], base)
    tier = al.get("matched_by")
    extra = " · ".join(f"{k} {al[k]}" for k in ("similarity", "path_overlap") if k in al)
    lines = [
        f"### {idx}/{total} — rebaseline mapping ({_clip(tier, 60)}"
        + (f" · {extra}" if extra else "")
        + ")",
        f"<!-- countersign finding={_safe_id(key)} layer={layer_rel} -->",
        "",
        f"Proposed: `{key}` → `{al.get('new_id')}` "
        f"(from `{al.get('from_report')}`, {al.get('mapped_at', '?')[:10]})",
        "",
        *_fmt_finding(item.get("old_finding"), "OLD (superseded scan)"),
        "",
        *_fmt_finding(item.get("new_finding"), "NEW (current baseline)"),
        "",
        "Same vulnerability? **confirm_mapping** transfers the old finding's "
        "ledger history to the new id at the next merge; **reject_mapping** "
        "records the refusal (the proposal is never re-made).",
        "",
        "DECISION: [ ] confirm_mapping   [ ] reject_mapping   [ ] defer",
        "RATIONALE: (optional for both — recorded verbatim when given)",
        "",
        "---",
    ]
    return "\n".join(lines)


def _resolved_findings_root(args) -> Path:
    if getattr(args, "root", None):
        return Path(args.root).resolve()
    return findings_tree_dir(load_engine(args.config_home)).resolve()


def cmd_queue(args) -> int:
    if args.repo_dir:
        roots = [Path(args.repo_dir)]
    elif args.root:
        roots = [Path(r) for r in args.root]
    else:
        roots = [_resolved_findings_root(args)]
    base = Path(args.base or ".").resolve()
    items = discover_pending(roots)
    signoff = [i for i in items if i["kind"] == "awaiting_signoff"]
    review = [i for i in items if i["kind"] == "needs_review"]
    attention = [
        i for i in items if i["kind"] in ("fp_overridden", "fp_reassertion_blocked", "conflict")
    ]
    mappings = [i for i in items if i["kind"] == "rebaseline_alias"]

    out = [
        "# Countersign Queue",
        "",
        f"Generated {datetime.now(UTC).isoformat(timespec='seconds')} — "
        f"{len(signoff)} awaiting human sign-off, "
        f"{len(review)} needs-review item(s), "
        f"{len(attention)} attention item(s) (overrides / second-signer / "
        f"conflicts), "
        f"{len(mappings)} rebaseline mapping proposal(s).",
        "",
        "Mark ONE box per card ([x]), add a rationale where required, then:",
        "",
        "    traust admin countersign apply countersign-queue.md",
        "",
        "Signing records a false positive attributed to you; `keep_open` "
        "records a human `confirmed` (your rationale required); `defer` "
        "leaves it pending. Every decision remains overridable by "
        "execution evidence.",
        "",
        "---",
    ]
    for i, item in enumerate(signoff, 1):
        out.append(render_card(item, i, len(signoff), base))
    if attention:
        out.append("## Attention: overrides, second-signer requests, conflicts")
        out.append("")
        for i, item in enumerate(attention, 1):
            out.append(render_attention_card(item, i, len(attention), base))
    if review:
        out.append("## Needs review (resolve interactively)")
        out.append("")
        for i, item in enumerate(review, 1):
            out.append(render_review_card(item, i, len(review)))
    if mappings:
        out.append(
            "## Rebaseline mappings (confirm = old finding's ledger "
            "history transfers to the new id)"
        )
        out.append("")
        for i, item in enumerate(mappings, 1):
            out.append(render_alias_card(item, i, len(mappings), base))

    text = "\n".join(out) + "\n"
    Path(args.out).write_text(text, encoding="utf-8")
    print(
        f"Wrote {args.out}: {len(signoff)} card(s), "
        f"{len(mappings)} mapping proposal(s), "
        f"{len(attention)} attention item(s), "
        f"{len(review)} needs-review item(s)"
    )
    if args.json_out:
        Path(args.json_out).write_text(
            json.dumps(
                {
                    "awaiting_signoff": [
                        {
                            "finding": i["finding"]["id"],
                            "layer": i["layer"],
                            "title": i["finding"].get("title"),
                        }
                        for i in signoff
                    ],
                    "attention": [
                        {
                            "kind": i["kind"],
                            "finding": i["finding"]["id"],
                            "layer": i["layer"],
                            "title": i["finding"].get("title"),
                        }
                        for i in attention
                    ],
                    "needs_review": [{"layer": i["layer"], **i["review_item"]} for i in review],
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
    return 0


# ---------------------------------------------------------------------------
# recording
# ---------------------------------------------------------------------------

# Self-minted (`ledger auth local`) tokens verify against a key in the
# signer's own config dir: anyone with a shell can mint one for any name.
# Fine for machine events and for an adopter with no IdP; not fine as the
# human sign-off the two-person rule counts — unless the deployment says so.
LOCAL_PROVIDER = "local"
ALLOW_LOCAL_ENV = "HARNESS_COUNTERSIGN_ALLOW_LOCAL"


def resolve_actor() -> dict:
    """The signer, as the ledger identity token proves them (``whoami``).

    Until 2026-09-08 this CLI ran its own LDAP check (a corporate script)
    and wrote the resulting actor into the layer file directly, bypassing the
    SDK's submit path — so the OIDC-verified identity every other write path
    carried never reached a countersign event, and the check itself only
    worked against one organisation's directory. Now the SDK is the only
    authority: ``require_verified_actor`` resolves the token (LAAS_TOKEN,
    LEDGER_TOKEN_PATH, LEDGER_TOKEN, the credential ``ledger auth login``
    stored, or a local token when LEDGER_LOCAL_IDENTITY is set) and
    cryptographically verifies it. The ``countersign`` verb re-derives the
    same actor from the same token and stamps it on every event; the dict
    returned here is for the receipt only.

    Raises RuntimeError when no verifiable token exists, the token is a
    machine identity, the deployment's employee directory
    (``LEDGER_DIRECTORY_COMMAND``) does not report the holder ``active``, or
    the token is self-minted (``identity_provider: local``) without
    ``HARNESS_COUNTERSIGN_ALLOW_LOCAL=1``.
    """
    from traust_ledger.auth.directory import (
        DirectoryRefusedError,
        DirectoryUnavailableError,
        apply_directory,
        load_directory,
    )
    from traust_ledger.cli.identity.actor import require_verified_actor

    actor = require_verified_actor()
    if actor is None:
        raise RuntimeError(
            "no verifiable ledger identity — run `ledger auth login` (OIDC) "
            "or `ledger auth local --identity <you>`; recording refused"
        )
    if actor.kind != "human":
        raise RuntimeError(
            f"ledger identity {actor.identity!r} is a {actor.kind} identity — "
            "countersignatures require a human signer; recording refused"
        )
    # The deployment's optional employee-directory cross-check
    # (LEDGER_DIRECTORY_COMMAND). The SDK applies the same check again at
    # submit; doing it here refuses before the queue is even parsed.
    try:
        actor = apply_directory(actor, load_directory())
    except (DirectoryRefusedError, DirectoryUnavailableError) as exc:
        raise RuntimeError(f"{exc.detail}; recording refused") from exc
    if (actor.identity_provider or "").lower() == LOCAL_PROVIDER and os.environ.get(
        ALLOW_LOCAL_ENV
    ) != "1":
        raise RuntimeError(
            f"ledger identity {actor.identity!r} was minted by the local "
            "issuer (self-asserted, no identity provider behind it). A "
            "countersignature is the human accountability the ledger's "
            "two-person rule counts, so local tokens are refused unless the "
            f"deployment opts in with {ALLOW_LOCAL_ENV}=1 (solo/offline "
            "adopters without an OIDC provider). Otherwise run "
            "`ledger auth login`; recording refused"
        )
    return actor.to_dict()


# Event construction (canonical id, source.ref, disposition, per-signer-day
# idempotency) now lives in the ledger SDK's `countersign` verb: it builds the
# event, dedupes, runs the human-lane gates, stamps the token-verified actor,
# finalizes the Merkle tree and signs — all in one atomic write. The harness no
# longer assembles or appends ledger events itself.


def default_fp_rationale(layer: dict, finding_ref: str) -> str:
    fp = [
        e
        for e in layer.get("events", [])
        if e["finding_ref"] == finding_ref and e["disposition"].get("validity") == "false_positive"
    ]
    machine = _clip(fp[-1].get("rationale") if fp else "", 300)
    return (
        "Countersigned after reviewing the machine refutation; I adopt "
        f"the verifiers' rationale as my determination: {machine}"
    )


def _close_review_items(
    ledger: LedgerService,
    layer_path: Path,
    layer: dict,
    finding_ref: str,
    note: str | None,
) -> list[str]:
    """Resolve every pending needs_review item this decision answers.

    Matched on ``suggested_finding_ref``. Delegates to
    ``LedgerService.resolve_review_item`` → ``LedgerClient.resolve`` so
    locking and validation stay in the SDK.
    Never raises: a decision that was recorded correctly must not fail because
    its queue entry could not be tidied.
    """
    lines = []
    pending = [
        i
        for i in (layer.get("needs_review") or [])
        if isinstance(i, dict)
        and i.get("status") == "pending"
        and i.get("suggested_finding_ref") == finding_ref
    ]
    for item in pending:
        key = LedgerService.review_item_key(item)
        reason = item.get("queue_reason", "?")
        try:
            ledger.resolve_review_item(layer_path, key, "confirmed", note=note or "")
            status = "confirmed"
        except LedgerError:
            try:
                ledger.resolve_review_item(
                    layer_path,
                    key,
                    "rejected",
                    note=note or "decided at countersign; no event recorded",
                )
                status = "rejected"
            except LedgerError as exc:
                lines.append(f"  queue      {finding_ref} ({reason}) left pending: {exc}")
                continue
        lines.append(f"  queue      {finding_ref} ({reason}) -> {status}")
    return lines


def record_decisions(
    decisions: list[dict],
    actor: dict,
    recorded_at: str,
    root: Path = Path(),
    *,
    engine=None,
) -> list[str]:
    """decisions: [{layer, finding, decision, rationale}]. Returns receipt.

    Every layer path (card marker or CLI) is confined under `root` — see
    _confine_layer.
    """
    receipt = []
    # resolve_actor() returns a dict for the harness's own use (receipts,
    # alias attribution); the SDK countersign verb wants a LayerActor.
    sdk_actor = LayerActor(**actor) if isinstance(actor, dict) else actor
    by_layer: dict[str, list[dict]] = {}
    for d in decisions:
        by_layer.setdefault(d["layer"], []).append(d)

    for layer_path, ds in by_layer.items():
        lp = _confine_layer(layer_path, root)
        ledger = (
            engine.ledger.service(data_dir=lp.parent)
            if engine is not None
            else LedgerService(data_dir=lp.parent)
        )
        # Read-only view for alias state and default rationales. Every write
        # below goes through the SDK (countersign / patch_layer_file), which
        # verifies the token, builds and dedupes the event, runs the human-lane
        # gates, stamps the actor, finalizes (Merkle) and signs atomically —
        # the harness never assembles, appends, or signs layers itself.
        layer = json.loads(lp.read_text(encoding="utf-8"))
        aliases_changed = False
        for d in ds:
            if d["decision"] == "defer":
                receipt.append(f"  defer      {d['finding']} (left pending)")
                continue
            if d["decision"] in ("confirm_mapping", "reject_mapping"):
                aliases = layer.setdefault("metadata", {}).setdefault("finding_aliases", {})
                al = aliases.get(d["finding"])
                if al is None:
                    receipt.append(
                        f"  missing    {d['finding']} (no such alias in this layer — skipped)"
                    )
                    continue
                if al.get("confirmed") or al.get("rejected"):
                    receipt.append(
                        f"  settled    {d['finding']} (already "
                        f"{'confirmed' if al.get('confirmed') else 'rejected'}"
                        " — skipped)"
                    )
                    continue
                note = (d.get("rationale") or "").strip()
                if note and note != RATIONALE_PLACEHOLDER:
                    al["note"] = note
                aliases_changed = True
                if d["decision"] == "confirm_mapping":
                    al["confirmed"] = True
                    al["confirmed_by"] = actor["identity"]
                    al["confirmed_at"] = recorded_at
                    receipt.append(
                        f"  confirm    {d['finding']} → "
                        f"{al.get('new_id')} (history transfers "
                        "at rebuild)"
                    )
                else:
                    al["rejected"] = True
                    al["rejected_by"] = actor["identity"]
                    al["rejected_at"] = recorded_at
                    receipt.append(
                        f"  reject     {d['finding']} ↛ "
                        f"{al.get('new_id')} (mapping refused, "
                        "never re-proposed)"
                    )
                continue
            rationale = (d.get("rationale") or "").strip()
            if not rationale or rationale == RATIONALE_PLACEHOLDER:
                if d["decision"] == "keep_open":
                    raise ValueError(
                        f"{d['finding']}: keep_open requires a rationale in "
                        "your own words — rejecting a refutation without a "
                        "why is not recordable"
                    )
                if d["decision"] in OVERRIDE_DECISIONS or d["decision"].startswith("severity="):
                    raise ValueError(
                        f"{d['finding']}: {d['decision']} is a human "
                        "override — a rationale in your own words is "
                        "required (there is no machine rationale to adopt)"
                    )
                rationale = default_fp_rationale(layer, d["finding"])
            try:
                if d["decision"].startswith("severity="):
                    level = d["decision"].split("=", 1)[1]
                    if level not in SEVERITY_LEVELS:
                        raise ValueError(f"{d['finding']}: unknown severity level {level!r}")
                    ledger.countersign(
                        lp,
                        d["finding"],
                        rationale=rationale,
                        recorded_at=recorded_at,
                        severity=level,
                        actor=sdk_actor,
                    )
                    receipt.append(
                        f"  severity   {d['finding']} → {level} (original "
                        "severity preserved; effective_severity carries the override)"
                    )
                    continue
                # "reopen" is a harness alias for confirming a finding; the SDK
                # only accepts keep_open/false_positive/override_false_positive.
                decision = "keep_open" if d["decision"] == "reopen" else d["decision"]
                ledger.countersign(
                    lp,
                    d["finding"],
                    decision=decision,
                    rationale=rationale,
                    recorded_at=recorded_at,
                    actor=sdk_actor,
                )
            except LedgerError as exc:
                receipt.append(f"  rejected   {d['finding']} ({d['decision']}): {exc}")
                continue
            suffix = ""
            if d["decision"] == "override_false_positive":
                suffix = (
                    " — evidence-class precedence applies: if this "
                    "finding is execution-proven, a SECOND independent "
                    "signer must concur before validity flips"
                )
            elif d["decision"] == "reopen":
                suffix = " — human confirmed; finding re-opened"
            receipt.append(f"  {d['decision']:<10} {d['finding']} recorded{suffix}")
        if aliases_changed:
            ledger.patch_layer_file(lp, {"finding_aliases": layer["metadata"]["finding_aliases"]})
        # Re-read the on-disk layer the SDK just wrote (stamped actors, signed
        # Merkle root); everything downstream (queue close, cumulative rebuild)
        # reads exactly what was signed.
        layer = json.loads(lp.read_text(encoding="utf-8"))

        # Close the queue entries these decisions answer. Until 2026-08-25
        # nothing did: the event was appended and the needs_review item stayed
        # `pending` forever, so a human could work the queue and it would never
        # shrink: the pending queue grew without bound while the
        # confirmed count stayed flat.
        # `confirmed` is tried first; the SDK refuses it unless the event is
        # actually in the layer, which is why the fallback is `rejected`.
        # Resolved via LedgerService → LedgerClient.resolve() (locking +
        # validation in the SDK). Runs AFTER write+sign so events are on disk
        # when "confirmed" checks for them. needs_review sits outside the
        # Merkle tree, so no re-sign is needed.
        for d in ds:
            if d["decision"] == "defer":
                continue
            note = (d.get("rationale") or "").strip() or None
            receipt.extend(_close_review_items(ledger, lp, layer, d["finding"], note))

        # Rebuild the cumulative pair deterministically.
        aj = baseline_for(lp)
        if aj is not None:
            audit = json.loads(aj.read_text(encoding="utf-8"))
            base = lp.with_name(lp.name.replace("-findings-layer.json", "-findings-current"))
            import os

            layer_ref = os.path.relpath(lp, base.parent)
            report = build_cumulative(audit, layer, layer_ref, recorded_at)
            # NOT with_suffix(): dotted repo slugs (3scale.github.io) would
            # have their "extension" replaced, misnaming the outputs.
            (base.parent / (base.name + ".json")).write_text(
                json.dumps(report, indent=2) + "\n", encoding="utf-8"
            )
            (base.parent / (base.name + ".md")).write_text(
                render_markdown(report, layer), encoding="utf-8"
            )
            ds_sum = report["disposition_summary"]["by_validity"]
            receipt.append(f"  rebuilt    {base.name}.{{json,md}} — validity now {ds_sum}")
    return receipt


def parse_annotated_queue(path: Path) -> list[dict]:
    text = path.read_text(encoding="utf-8")
    decisions = []
    blocks = re.split(r"\n---\n?", text)
    for block in blocks:
        m = CARD_MARK.search(block)
        if not m:
            continue
        marks = list(DECISION_LINE.finditer(block))
        if not marks:
            continue  # unmarked card = defer by omission
        if len(marks) > 1:
            raise ValueError(
                f"card for {m.group('finding')} contains "
                f"{len(marks)} DECISION lines — refusing to guess "
                "which is the signer's (possible forgery; assessment "
                "2026-07-31 C1). Remove the extra line and re-run."
            )
        dm = marks[0]
        rationale = ""
        rm = re.search(r"^RATIONALE:\s*(.*?)\s*$", block, re.DOTALL | re.M)
        if rm:
            rationale = rm.group(1).strip()
            if rationale == RATIONALE_PLACEHOLDER:
                rationale = ""
        decisions.append(
            {
                "finding": m.group("finding"),
                "layer": m.group("layer"),
                "decision": dm.group("decision"),
                "rationale": rationale,
            }
        )
    return decisions


def cmd_apply(args) -> int:
    engine = load_engine(args.config_home)
    decisions = parse_annotated_queue(Path(args.queue))
    actionable = [d for d in decisions if d["decision"] != "defer"]
    if not decisions:
        print("No marked decisions found in the queue file.", file=sys.stderr)
        return 1
    try:
        actor = resolve_actor()
    except (RuntimeError, OSError) as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1
    recorded_at = args.recorded_at or datetime.now(UTC).isoformat(timespec="seconds")
    try:
        receipt = record_decisions(
            decisions,
            actor,
            recorded_at,
            root=_resolved_findings_root(args),
            engine=engine,
        )
    except ValueError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1
    print(
        f"Countersign receipt — {actor['identity']} "
        f"(verified via {actor.get('identity_provider') or 'ledger token'}), "
        f"{recorded_at}:"
    )
    print("\n".join(receipt))
    print(f"{len(actionable)} decision(s) recorded, {len(decisions) - len(actionable)} deferred.")
    return 0


def cmd_record(args) -> int:
    engine = load_engine(args.config_home)
    decision = args.decision
    if decision == "severity":
        if not args.severity:
            print(
                "ERROR: --decision severity requires --severity <level>",
                file=sys.stderr,
            )
            return 2
        decision = f"severity={args.severity}"
    try:
        actor = resolve_actor()
    except (RuntimeError, OSError) as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1
    recorded_at = args.recorded_at or datetime.now(UTC).isoformat(timespec="seconds")
    try:
        receipt = record_decisions(
            [
                {
                    "layer": args.layer,
                    "finding": args.finding,
                    "decision": decision,
                    "rationale": args.rationale or "",
                }
            ],
            actor,
            recorded_at,
            root=_resolved_findings_root(args),
            engine=engine,
        )
    except ValueError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1
    print(
        f"Countersign receipt — {actor['identity']} "
        f"(verified via {actor.get('identity_provider') or 'ledger token'}), "
        f"{recorded_at}:"
    )
    print("\n".join(receipt))
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    add_config_home_arg(parser)
    sub = parser.add_subparsers(dest="mode", required=True)

    q = sub.add_parser("queue", help="render pending decisions as cards")
    q.add_argument("--root", action="append", help="findings tree(s) to walk (repeatable)")
    q.add_argument("--repo-dir", help="one repo's findings directory")
    q.add_argument("--out", default="countersign-queue.md")
    q.add_argument("--json-out")
    q.add_argument(
        "--base",
        help="base dir for layer-relative paths in card markers (default: cwd)",
    )
    q.set_defaults(fn=cmd_queue)

    a = sub.add_parser("apply", help="record decisions from an annotated queue")
    a.add_argument("queue", help="annotated countersign-queue.md")
    a.add_argument("--recorded-at", type=recorded_at_arg, help="override timestamp (RFC 3339)")
    a.add_argument(
        "--root",
        help="findings root: every layer path in the "
        "queue must resolve under this directory "
        "(default: configured analysis-results/findings)",
    )
    a.set_defaults(fn=cmd_apply)

    r = sub.add_parser("record", help="record one decision from the CLI")
    r.add_argument("--layer", required=True)
    r.add_argument("--finding", required=True)
    r.add_argument(
        "--decision",
        required=True,
        choices=(
            "false_positive",
            "keep_open",
            "confirm_mapping",
            "reject_mapping",
            "reopen",
            "override_false_positive",
            "severity",
        ),
        help="'severity' requires --severity; reopen/"
        "override_false_positive/severity are human "
        "overrides needing --rationale in your own words",
    )
    r.add_argument(
        "--severity",
        choices=SEVERITY_LEVELS,
        help="target level for --decision severity (upgrade or downgrade)",
    )
    r.add_argument("--rationale")
    r.add_argument("--recorded-at", type=recorded_at_arg)
    r.add_argument(
        "--root",
        help="findings root: --layer must resolve under this directory "
        "(default: configured analysis-results/findings)",
    )
    r.set_defaults(fn=cmd_record)

    args = parser.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    import sys

    from traust.cli.__main__ import main

    raise SystemExit(main(["admin", "countersign", *sys.argv[1:]]))
