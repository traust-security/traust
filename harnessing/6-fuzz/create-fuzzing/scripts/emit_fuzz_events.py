#!/usr/bin/env python3
"""Emit ledger events for fuzz-found bugs.

Fuzzing has been producing crashers for months and recording none of them in
the disposition ledger. The findings existed as prose in a campaign summary
and as reproducer corpora on disk; the ledger, which is supposed to be the
record of what we know about a finding, had nothing.

This follows the event-carried-finding pattern already used by
route_impact_findings.py and route_regressions.py, and emits under gate A15:
the baseline audit report is NEVER written. A finding that has no baseline
entry rides on the event itself.

Why source.type is `fuzz_report` and why that is evidence class 1: a fuzz
finding is a crasher WITH a reproducer. The input that triggers it is on
disk, so the claim is replayable rather than asserted — the same property
that puts live validation in class 1. The converse matters more and is easy
to misread: a fuzz run that finds NOTHING emits no event here. Absence of a
crash is not evidence of correctness, and this tool must never be extended to
record one.

Two shapes of bug, decided by the target's `audit_ref`:

  * a clean FIND-NNN  — the fuzzer confirmed a finding an audit already
    raised. The event attaches to that finding_ref and carries no finding.
  * anything else     — prose, or empty. The fuzzer found something no audit
    had. The event carries a new finding, minted at the target's commit.

Dry-run is the DEFAULT. `--apply` is required to write, because these are
append-only ledger events: a wrong one is corrected by a later event, never
removed.

Usage:
    python3 emit_fuzz_events.py                       # dry run, prints the mapping
    python3 emit_fuzz_events.py --apply
    python3 emit_fuzz_events.py --summary PATH --targets PATH --corpus DIR
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from datetime import UTC, datetime
from pathlib import Path

from traust_engine.ledger import (
    ALGO_VERSION,
    compute_event_id,
    fingerprint,
)

from traust.context import (
    add_config_home_arg,
    analysis_results_dir,
    load_engine,
)
from traust.paths import HARNESS_ROOT

FIND_ID_RE = re.compile(r"^FIND-\d+$")
LAYER_SUFFIX = "-findings-layer.json"
# Only these bugs are ours to record. The campaign summary also carries bugs
# found by static review and by grep sweeps; recording those as fuzz results
# would falsify their provenance (plan decision D3).
FUZZ_METHOD = "fuzz"


def _utc_now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def harness_version() -> str:
    from traust_engine.assets import harness_version as _hv

    return _hv()


def _load(path: Path, what: str) -> dict:
    if not path.is_file():
        sys.exit(f"[!] {what} not found: {path}")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        sys.exit(f"[!] {what} is not valid JSON ({e}): {path}")


# Layers and reproducers live only under findings trees. Walking the whole
# corpus instead took 11m30s -- it descends .cache-clones, .verify-cache and
# every scratch tree, which together dwarf the findings themselves.
# Fixed names are the harness's own conventions; engagement trees are whatever
# `*-findings` directories the corpus holds (registered in corpus-config.yaml),
# never a list of estate names baked in here.
_FINDINGS_DIRS = ("findings", "cloud-config", "OpenStack-k8s-ops", "team-reports")


def _findings_roots(corpus: Path) -> list[Path]:
    roots = [corpus / d for d in _FINDINGS_DIRS if (corpus / d).is_dir()]
    roots += sorted(p for p in corpus.glob("*-findings") if p.is_dir() and p not in roots)
    if not roots:  # unknown layout: fall back to the full walk
        return [corpus]
    return roots


def index_layers(corpus: Path) -> dict[str, list[Path]]:
    """repo slug -> EVERY layer with that slug.

    A list, not a single path, because a repo audited under several products
    has one layer per product: kube-rbac-proxy has 88. An index keyed to one
    path silently picks whichever the walk happened to reach last, and a fuzz
    event would land on an arbitrary product's ledger.

    Bounded globs, not rglob. Layers sit at <root>/<product>/<repo>/ or
    <root>/<repo>/; walking the whole tree instead took 10 minutes against
    145k files, versus 0.3s here.
    """
    out: dict[str, list[Path]] = {}
    for root in _findings_roots(corpus):
        for pattern in ("*/*/*" + LAYER_SUFFIX, "*/*" + LAYER_SUFFIX):
            for p in root.glob(pattern):
                out.setdefault(p.name[: -len(LAYER_SUFFIX)], []).append(p)
    return out


def resolve_layers(layers: dict[str, list[Path]], target_id: str, repo_url: str) -> list[Path]:
    slug = repo_url.rstrip("/").split("/")[-1] if repo_url else ""
    return sorted(set(layers.get(slug) or layers.get(target_id) or []), key=str)


def index_reproducers(corpus: Path) -> list[tuple[str, str]]:
    """(path string, corpus-relative path) for every fuzz-corpus dir, indexed ONCE.

    The first cut called rglob per bug: 14 full walks of a 145k-file tree,
    which did not finish inside ten minutes. Bounded globs at the two depths
    reproducers actually occupy do the same job in under a second.
    """
    return [
        (str(d), os.path.relpath(d, corpus))
        for root in _findings_roots(corpus)
        for pattern in ("*/fuzz-corpus", "*/*/fuzz-corpus")
        for d in root.glob(pattern)
    ]


def find_reproducers(index: list[tuple[str, str]], target_id: str, repo_url: str) -> list[str]:
    """Reproducer corpora for a target, as corpus-relative paths.

    A fuzz event's whole claim to evidence class 1 is that the triggering
    input was kept. If none is found the event still records, but says so --
    silently emitting a class-1 event with no reproducer would be a lie.
    """
    slug = repo_url.rstrip("/").split("/")[-1] if repo_url else target_id
    keys = {k for k in (slug, target_id, repo_url.replace("https://", "").replace("/", "-")) if k}
    return sorted(rel for full, rel in index if any(k in full for k in keys))


def existing_fingerprint(layers: list[str], finding_ref: str) -> str | None:
    """The identity an earlier event already gave this finding.

    A fuzz run confirming a finding an audit raised is a SECOND OPINION on
    one bug, not a new one. Recomputing here would risk a different answer
    -- the audit knows locations the fuzz target does not -- and two
    identities for one finding is precisely what distinct-exposure counts
    wrongly.

    Reads the layer's own event stream, which is where the audit's stamp
    already lives. Returns None when no earlier event carried one; the
    event is then emitted unstamped rather than guessing.
    """
    for layer_path in layers:
        try:
            document = json.loads(Path(layer_path).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        for event in reversed(document.get("events") or []):
            if event.get("finding_ref") == finding_ref and event.get("fingerprint"):
                return event["fingerprint"]
    return None


def mint_finding(bug: dict, target: dict, fid: str) -> dict:
    """A finding carried on the event, for a crasher no audit had raised.

    layer.schema.json#/$defs/event_finding REQUIRES id, title, severity, cwes,
    locations, description and remediation. The first cut supplied four of the
    seven, and 20 of the 198 layers failed validation on `locations` -- after
    they had already been written. Every field here is real: locations come
    from the target's own harness declarations, not from a placeholder.
    """
    cwes = [f"CWE-{c.strip()}" for c in str(bug.get("cwe", "")).split("/") if c.strip().isdigit()]
    harnesses = [h for h in (target.get("harnesses") or []) if h.get("dest")]
    # THIS bug's harness, not every harness on the target. A target with
    # several fuzz entry points produced one location set for all of its
    # bugs, so they hashed to a single identity -- measured, sriov bugs 5
    # and 6 collided despite being different functions in different files.
    #
    # The bug record has no location field, but its title names the
    # function under test and the harness declares that symbol, so the
    # match is on real declared data rather than a guess. No match falls
    # back to every harness on the target, which is what this did before.
    matched = [h for h in harnesses if _names_function(bug.get("title", ""), h.get("fuzz", ""))]
    locations = [
        {"path": h["dest"], "symbol": h.get("fuzz", "")} for h in (matched or harnesses)
    ]
    if not locations:
        # The crasher is in this repo but the harness declaration does not say
        # where. Name the repo rather than invent a file.
        locations = [{"path": ".", "note": "repo-scoped: no harness dest declared"}]
    return {
        "id": fid,
        "title": bug["title"],
        "severity": _severity_from_cvss(bug.get("cvss")),
        "cwes": cwes or ["CWE-20"],
        "locations": locations,
        "description": (
            f"Found by fuzzing (campaign bug #{bug['num']}, target "
            f"{bug['target']}). A reproducer is recorded in the event's "
            f"evidence_refs; the crash is replayable."
        ),
        "remediation": (
            "Reproduce with the recorded corpus input, then bound or validate "
            "the input path the fuzzer reached. Re-run the harness to confirm "
            "the crasher no longer triggers before closing."
        ),
        "validation_status": "not_verified",
        "origin": "create-fuzzing",
    }


def stamp_identity(finding: dict, repo_url: str) -> str | None:
    """Stamp the correlation fingerprint, or refuse and say why.

    Without this a fuzz-found bug has no identity: it cannot be counted in
    distinct exposure, cannot be trended or SLA-clocked, and cannot be
    recognised when a later audit finds the same crash. Measured before
    this landed, fuzz_report was the ONLY event source at 0% fingerprint
    coverage -- every other route, including the same event-carried
    pattern used by the impact router, was at 81-100%.

    strict=True is deliberate. When a target declares no harness dest the
    finding's only location is a repo-root marker, and hashing that
    produces an identity shared by every rootless finding in the repo --
    measured on the corpus, hundreds of such fingerprints were each
    shared by several findings. An unstamped finding is honest; a
    colliding one silently
    merges unrelated bugs.
    """
    try:
        value = fingerprint(finding, repo_url, strict=True)
    except Exception:
        return None
    finding["fingerprint"] = value
    finding["fingerprint_algo"] = ALGO_VERSION
    return value


def _names_function(title: str, fuzz_symbol: str) -> bool:
    """Does this bug's title name the function this harness fuzzes?

    Harness symbols are `Fuzz<Name>`; a title refers to the function as
    `<Name>` or `<name>`, usually in backticks. Compared case-insensitively
    on the symbol minus its Fuzz prefix, which is the only part that
    carries meaning.
    """
    name = (fuzz_symbol or "").removeprefix("Fuzz").strip()
    if not name or not title:
        return False
    return name.lower() in title.lower()


def _severity_from_cvss(cvss) -> str:
    try:
        score = float(str(cvss).lstrip("~"))
    except (TypeError, ValueError):
        return "medium"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


def build_event(
    bug: dict,
    target: dict,
    finding_ref: str,
    source_ref: str,
    reproducers: list[str],
    carried: dict | None,
    recorded_at: str,
    hv: str,
    fp: str | None = None,
) -> dict:
    # source.ref points at the BUG RECORD, not the summary file. event_id is
    # computed from (source_ref, finding_ref, validity, resolution) alone, so
    # two crashers confirming the same audit finding -- which is exactly what
    # bugs 1 and 2 do against FIND-019 -- would hash identically and the second
    # would be silently deduped away. The dry run showed both rows; only one
    # would ever have landed.
    bug_ref = f"{source_ref}#bugs/{bug['num']}"
    evidence = [bug_ref, *reproducers]
    note = (
        "reproducer recorded"
        if reproducers
        else "NO reproducer found on disk — the class-1 claim rests on the "
        "campaign record alone; re-run the harness to regenerate one"
    )
    event = {
        "event_id": compute_event_id(bug_ref, finding_ref, None, "open"),
        "finding_ref": finding_ref,
        "recorded_at": recorded_at,
        "occurred_at": recorded_at,
        "source": {
            "type": "fuzz_report",
            "ref": bug_ref,
            "actor": {"kind": "machine", "identity": "create-fuzzing"},
        },
        "disposition": {"resolution": "open"},
        "rationale": (
            f"Fuzz-found crasher (campaign bug #{bug['num']}, "
            f"{bug.get('cvss', 'no cvss')}, CWE {bug.get('cwe', 'n/a')}) on "
            f"target {bug['target']}: {bug['title']}. {note}. Enters at "
            f"validation_status not_verified with resolution open — triage "
            f"and validation adjudicate downstream."
        ),
        "evidence_refs": evidence,
        "harness_version": hv,
    }
    if carried is not None:
        event["finding"] = carried
    # The event carries the identity too: layer_event projects
    # event.fingerprint, and a consumer reading the event stream must not
    # have to open the carried finding to know what this is about.
    if fp:
        event["fingerprint"] = fp
        event["fingerprint_algo"] = ALGO_VERSION
    return event


def plan(
    summary: dict, targets: dict, corpus: Path, source_ref: str, hv: str, all_layers: bool = False
) -> tuple[list[dict], list[dict], list[str]]:
    """Returns (rows-to-emit, ambiguous, problems).

    A repo audited under several products has one layer per product. This
    tool REFUSES to pick one: attaching a crasher to an arbitrary product's
    ledger is a silent misfiling, and ledger events are append-only, so a
    wrong one is corrected by a later event and never removed.

    Ambiguous targets are reported and skipped unless --all-layers is given,
    which emits to every layer for that repo. That is defensible under the
    ledger's own model -- (layer_id, finding_ref) is the disposition key, and
    one finding audited under many parents legitimately appears under each --
    but it is a decision, so it is an explicit flag rather than a default.
    """
    layers = index_layers(corpus)
    repro_index = index_reproducers(corpus)
    by_id = {t["id"]: t for t in targets["targets"]}
    recorded_at = _utc_now()
    rows, ambiguous, problems = [], [], []
    for bug in summary.get("bugs", []):
        if bug.get("method") != FUZZ_METHOD:
            continue
        tid = bug["target"]
        target = by_id.get(tid)
        if target is None:
            problems.append(f"bug #{bug['num']}: target {tid!r} not in targets.json")
            continue
        repo = target.get("repo", "")
        found = resolve_layers(layers, tid, repo)
        if not found:
            problems.append(f"bug #{bug['num']}: no ledger layer for {tid}")
            continue
        if len(found) > 1 and not all_layers:
            ambiguous.append(
                {"bug": bug["num"], "target": tid, "count": len(found), "layers": found}
            )
            continue
        audit_ref = (target.get("audit_ref") or "").strip()
        attach = bool(FIND_ID_RE.fullmatch(audit_ref))
        reproducers = find_reproducers(repro_index, tid, repo)
        if attach:
            # Confirming a finding an audit already raised: its identity is
            # the AUDIT's, so it is looked up rather than recomputed. A
            # second opinion on the same bug must not mint a second identity.
            finding_ref, carried = audit_ref, None
            fp = existing_fingerprint(found, audit_ref)
        else:
            finding_ref = f"FUZZ-{bug['num']:03d}"
            carried = mint_finding(bug, target, finding_ref)
            fp = stamp_identity(carried, repo)
            if fp is None:
                problems.append(
                    f"bug #{bug['num']}: no declared harness dest for {tid}, so the "
                    "finding has no identity -- emitted unstamped rather than "
                    "hashing a repo-root marker that would collide"
                )
        for layer in found:
            rows.append(
                {
                    "bug": bug["num"],
                    "target": tid,
                    "layer": layer,
                    "finding_ref": finding_ref,
                    "mode": "attach" if attach else "carry",
                    "audit_ref": audit_ref,
                    "reproducers": reproducers,
                    "event": build_event(
                        bug, target, finding_ref, source_ref, reproducers, carried,
                        recorded_at, hv, fp
                    ),
                }
            )
    return rows, ambiguous, problems


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    add_config_home_arg(ap)
    # Path("") is Path("."), which is truthy -- an `or` fallback here silently
    # resolves every default to the cwd. Test the string, not the Path.
    _env_summary = os.environ.get("FUZZ_CAMPAIGN_SUMMARY", "").strip()
    ap.add_argument("--summary", type=Path, default=Path(_env_summary) if _env_summary else None)
    ap.add_argument(
        "--targets",
        type=Path,
        default=(HARNESS_ROOT / "harnessing" / "6-fuzz" / "create-fuzzing" / "targets.json"),
    )
    ap.add_argument("--corpus", type=Path, default=None)
    ap.add_argument("--apply", action="store_true", help="write the events (default is a dry run)")
    ap.add_argument(
        "--all-layers",
        action="store_true",
        help="a repo audited under several products has one layer "
        "each; emit to every one instead of skipping it",
    )
    args = ap.parse_args(argv)

    engine = load_engine(args.config_home)
    if args.summary is None:
        args.summary = analysis_results_dir(engine).parent / "FUZZ-CAMPAIGN-SUMMARY.json"
    if args.corpus is None:
        args.corpus = analysis_results_dir(engine)

    summary = _load(args.summary, "campaign summary")
    targets = _load(args.targets, "targets.json")
    if not args.corpus.is_dir():
        sys.exit(f"[!] corpus not found: {args.corpus}")

    source_ref = os.path.relpath(args.summary.resolve(), args.corpus.resolve())
    rows, ambiguous, problems = plan(
        summary, targets, args.corpus, source_ref, harness_version(), args.all_layers
    )

    for p in problems:
        print(f"[!] {p}", file=sys.stderr)
    for a in ambiguous:
        print(
            f"[!] bug #{a['bug']} ({a['target']}): {a['count']} layers — "
            f"SKIPPED. This repo is audited under several products and "
            f"picking one would misfile the crasher. Re-run with "
            f"--all-layers to record it under every product that ships it.",
            file=sys.stderr,
        )
    if not rows:
        print("no fuzz-found bugs to emit")
        return 1 if problems else 0

    print(f"{'bug':>4}  {'target':28} {'mode':6} {'finding_ref':14} repro  layer")
    for r in rows:
        print(
            f"{r['bug']:>4}  {r['target'][:28]:28} {r['mode']:6} "
            f"{r['finding_ref']:14} {len(r['reproducers']):>5}  "
            f"{os.path.relpath(r['layer'], args.corpus)}"
        )
    no_repro = [r["bug"] for r in rows if not r["reproducers"]]
    if no_repro:
        print(
            f"\n[!] {len(no_repro)} bug(s) have NO reproducer on disk: "
            f"{no_repro}. Their events still record, and say so in the "
            f"rationale — a class-1 source type without a replayable input "
            f"is a claim the ledger should not make silently."
        )

    if not args.apply:
        print(
            f"\ndry run — {len(rows)} event(s) would be emitted across "
            f"{len({str(r['layer']) for r in rows})} layer(s). "
            f"Re-run with --apply."
        )
        return 0

    written = skipped = 0
    for layer_path in sorted({r["layer"] for r in rows}, key=str):
        svc = engine.ledger.service(data_dir=layer_path.parent)
        layer = svc.read_layer_file(layer_path)
        existing = {e.get("event_id") for e in (layer.get("events") or [])}
        fresh = [
            r["event"]
            for r in rows
            if r["layer"] == layer_path and r["event"]["event_id"] not in existing
        ]
        skipped += sum(1 for r in rows if r["layer"] == layer_path) - len(fresh)
        if not fresh:
            continue
        svc.submit_events(layer_path, fresh)
        written += len(fresh)
    print(f"\nemitted {written} event(s); {skipped} already present (idempotent)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
