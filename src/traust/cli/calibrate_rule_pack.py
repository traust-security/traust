#!/usr/bin/env python3
"""Calibrate an external opengrep rule pack against campaign ground truth.

WHY GROUND TRUTH IS NEEDED FOR A *DETERMINISTIC* RULE. A pattern rule is
deterministic: it fires or it doesn't, and its own test fixtures prove
that much for free. What determinism cannot tell you is whether a hit is
worth a human's attention — and that is not a property of the rule, it
is a property of the rule INTERSECTED WITH YOUR CODEBASE. `MD5` in a
cache key is fine; `MD5` hashing a password is not. Same pattern,
opposite verdict. A rule can be 100% correct and still be 90% noise
here. The opengrep-ruleset-plan gate (>=3 rediscoveries, precision
>~50%) is therefore an ECONOMICS gate, not a correctness one: "below
that it wastes more judge tokens than it saves." Every finding costs
someone's adjudication time.

A pack's own fixtures cannot answer that, because they are written by
the rule author to trigger the rule — circular. The TP corpus is code
YOUR engineers wrote, in your idioms, and the false-positive risk lives
exactly in the gap between the two.

NOBODY HAND-CONFIRMS THESE, AND THAT IS THE DESIGN. Confirmation comes
from /triage's judge and from live validation, not from a person signing
off each finding — /countersign is the FALSE-positive path (contested
machine refutations), so the confirmed set is overwhelmingly
machine_verified plus execution_proven, hand review is a rounding error,
and false_positive stays small by construction. Ground truth here is a
byproduct of the pipeline already running, not a queue of human work.
Tally your own ledger by `confirmation_source` before reading precision
off it: what you have is a machine-agreement rate, not a human verdict.

WHAT THIS MEASURES, AND WHAT IT DELIBERATELY DOES NOT.

  fixtures     Does the pack work at all? Runs it over its own tests/
               tree. Free, needs no ground truth. A sanity gate — run
               this before spending clone time.
  volume       How much noise would it add? Findings per repo and per
               KLoC. Free, needs no ground truth, and is often the most
               decision-relevant number: a pack that triples finding
               volume is a triage-cost decision regardless of precision.
  rediscovery  Does it find things we already know are real? Scores
               against tp-corpus.jsonl.
  novel        Hits with no corresponding known finding — the bucket
               that would need adjudication. Sampled for manual review.

  precision    NOT COMPUTED HERE, and it does not need to be. Precision
               is already collected automatically: every audit that runs
               the opengrep pre-scan records a `scanner_correlation`
               entry per rule with `result: promoted|dismissed`, and
               /mine-ledger tallies those campaign-wide against the ~50%
               gate, accumulating promoted/dismissed counts per rule id
               as audits run. So precision for this pack accrues as a
               BYPRODUCT of running it in audits — no human review, no
               separate exercise.
               What cannot be done is computing it BEFORE the pack has
               ever run, which is exactly the pre-flight gap this tool
               fills. The novel sample below is an optional shortcut for
               an early read, not the required path.

MATCHING IS PATH-LEVEL, NOT LINE-LEVEL. tp-corpus records `locations` as
file paths with no line numbers, so a "rediscovery" means the rule fired
in a file where a confirmed TP lives — not necessarily on the same
construct. That biases rediscovery counts UP. Treated as a screening
signal, never as proof a rule found the specific bug.

Deterministic, ~$0, no agent. Resumable: per-repo results are cached, so
an interrupted run resumes instead of re-cloning.

Usage:
    # 1. sanity gate — no clones, no ground truth
    python3 -m traust.cli.calibrate_rule_pack --fixtures \\
        --rules https://github.com/smith-xyz/argus-observe-rules

    # 2. corpus calibration over a bounded slice
    python3 -m traust.cli.calibrate_rule_pack \\
        --rules https://github.com/smith-xyz/argus-observe-rules \\
        --cwe-set crypto --limit 25
"""

from __future__ import annotations

import argparse
import collections
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

from traust_engine.sweep.calibration import (
    CACHE_ROOT,
    CWE_SETS,
    PACK_LANGS,
    REDISCOVERY_GATE,
    _norm_path,
    aggregate,
    classify,
    gate_reachability,
    load_corpus,
    novel_sample,
    pack_cwes,
    render,
    select_targets,
)

from traust.context import add_config_home_arg, load_engine, progress_tracker_dir

DEFAULT_OUT = CACHE_ROOT / "reports"


# ---------------------------------------------------------------------------
# scanning (seam: tests inject a fake)
# ---------------------------------------------------------------------------


def clone_at(repo_url: str, commit: str, dest: Path, timeout: int = 300) -> bool:
    """Shallow-fetch one pinned commit. Rule S3: https-only gate,
    GIT_ALLOW_PROTOCOL pinned, `--` separator, argv list."""
    if not re.match(r"^https://", repo_url):
        return False
    if dest.is_dir():
        return True
    dest.mkdir(parents=True, exist_ok=True)
    env = {**os.environ, "GIT_ALLOW_PROTOCOL": "https", "GIT_TERMINAL_PROMPT": "0"}
    try:
        for args in (
            ["git", "-C", str(dest), "init", "-q"],
            ["git", "-C", str(dest), "remote", "add", "origin", "--", repo_url],
            ["git", "-C", str(dest), "fetch", "-q", "--depth", "1", "origin", commit],
            ["git", "-C", str(dest), "checkout", "-q", "FETCH_HEAD"],
        ):
            subprocess.run(args, check=True, capture_output=True, timeout=timeout, env=env)
    except (subprocess.SubprocessError, OSError):
        shutil.rmtree(dest, ignore_errors=True)
        return False
    return True


def scan(target: Path, rules: str, timeout: int = 900) -> tuple[list[dict], str | None]:
    """Run the pack via run_opengrep.py (which owns pack fetch, SHA
    pinning, cache verification and licence notes).

    -> (facts, error). A FAILED scan must never be indistinguishable
    from a clean one: returning [] for both is how a systematically
    broken invocation reads as "the pack finds nothing". This bit during
    development — an unpinned --rules value was rejected by
    run_opengrep, swallowed here, and reported as zero findings."""
    out = target.parent / f"{target.name}-opengrep.json"
    try:
        proc = subprocess.run(
            [
                sys.executable,
                "-m",
                "traust.cli",
                "adapters",
                "opengrep",
                str(target),
                "--rules",
                rules,
                "--out",
                str(out),
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (subprocess.SubprocessError, OSError) as e:
        return [], f"run_opengrep did not execute: {str(e)[:160]}"
    if proc.returncode != 0:
        msg = (proc.stderr or proc.stdout or "").strip().splitlines()
        return [], f"run_opengrep exit {proc.returncode}: " + (
            msg[-1][:200] if msg else "no diagnostic"
        )
    if not out.is_file():
        return [], "run_opengrep produced no output file"
    try:
        doc = json.loads(out.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        return [], f"unreadable scan output: {str(e)[:120]}"
    facts = doc.get("facts") if isinstance(doc, dict) else doc
    norm = []
    for f in facts or []:
        if not isinstance(f, dict):
            continue
        rid = f.get("rule_id") or f.get("check_id") or "?"
        p = f.get("path") or f.get("file") or ""
        norm.append({"rule_id": str(rid), "path": _norm_path(p)})
    return norm, None


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------


def run_fixtures(rules_src: str, out_dir: Path) -> int:
    """Sanity gate: run the pack over its own tests/ tree. Proves the
    rules load and fire, needs no ground truth, costs no clones."""
    m = re.match(r"(https://[^@]+)(?:@([0-9a-f]{7,40}))?$", rules_src)
    if not m:
        print("--fixtures needs a git URL rules source", file=sys.stderr)
        return 2
    url, sha = m.group(1), m.group(2)
    dest = CACHE_ROOT / "fixtures" / url.rstrip("/").rsplit("/", 1)[-1]
    if not dest.is_dir():
        dest.mkdir(parents=True, exist_ok=True)
        env = {**os.environ, "GIT_ALLOW_PROTOCOL": "https", "GIT_TERMINAL_PROMPT": "0"}
        try:
            subprocess.run(
                ["git", "clone", "-q", "--depth", "1", "--", url, str(dest)],
                check=True,
                capture_output=True,
                timeout=600,
                env=env,
            )
        except (subprocess.SubprocessError, OSError) as e:
            print(f"fixture clone failed: {str(e)[:120]}", file=sys.stderr)
            return 1
    # run_opengrep refuses a movable ref ("ref must be a 40-hex commit
    # SHA"), so resolve one rather than handing it a bare URL.
    pinned = rules_src
    if not sha:
        head = subprocess.run(
            ["git", "-C", str(dest), "rev-parse", "HEAD"], capture_output=True, text=True
        ).stdout.strip()
        if not re.fullmatch(r"[0-9a-f]{40}", head):
            print("cannot resolve a commit SHA for the fixture clone", file=sys.stderr)
            return 1
        pinned = f"{url}@{head}"
        print(f"[+] pinning unpinned source to cloned HEAD {head[:12]}", file=sys.stderr)

    tests = dest / "tests"
    if not tests.is_dir():
        print(f"no tests/ tree in {url} — cannot run the sanity gate", file=sys.stderr)
        return 1

    # OPENGREP IGNORES `tests/` BY DEFAULT. Measured 2026-08-06: scanning
    # the pack's tests/ tree directly reports 0 files scanned, while the
    # identical files copied to a neutrally-named directory scan every
    # file and report thousands of results. Pointing the sanity gate at
    # a path the scanner declines to read would report "the rules don't fire" about
    # a pack that fires fine — so stage the fixtures somewhere neutral.
    staged = CACHE_ROOT / "fixture-stage" / url.rstrip("/").rsplit("/", 1)[-1]
    if staged.exists():
        shutil.rmtree(staged, ignore_errors=True)
    staged.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    shutil.copytree(tests, staged)
    facts, err = scan(staged, pinned)
    if err:
        print(f"fixture scan FAILED: {err}", file=sys.stderr)
        return 1
    by_rule = collections.Counter(f["rule_id"] for f in facts)
    print(
        f"fixture scan: {len(facts)} findings from {len(by_rule)} distinct rules over {url}/tests"
    )
    if not facts:
        print(
            "  ZERO findings on the pack's own fixtures — the rules are "
            "not loading or not matching. Do not proceed to corpus "
            "calibration until this is understood.",
            file=sys.stderr,
        )
        return 1
    out_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    (out_dir / "fixture-scan.json").write_text(
        json.dumps(
            {
                "rules_source": rules_src,
                "findings": len(facts),
                "distinct_rules": len(by_rule),
                "by_rule": dict(by_rule.most_common()),
            },
            indent=1,
        )
        + "\n",
        encoding="utf-8",
    )
    print(f"  wrote {out_dir / 'fixture-scan.json'}")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    add_config_home_arg(ap)
    ap.add_argument("--rules", required=True, help="rules source, as accepted by run_opengrep.py")
    ap.add_argument(
        "--fixtures", action="store_true", help="sanity gate only: scan the pack's own tests/ tree"
    )
    ap.add_argument(
        "--corpus",
        type=Path,
        default=None,
        help="TP corpus JSONL (default: <progress-tracker>/metrics/rule-mining/tp-corpus.jsonl)",
    )
    ap.add_argument("--cwe-set", default="crypto", choices=[*sorted(CWE_SETS), "all"])
    ap.add_argument("--limit", type=int, default=25, help="max repos to scan (clones are the cost)")
    ap.add_argument("--sample", type=int, default=40, help="novel hits to emit for manual review")
    # Per-user 0700 cache, never a fixed /tmp name: a predictable
    # world-writable path lets any local user pre-create or swap the
    # output dir (rule S6).
    ap.add_argument(
        "--out", type=Path, default=DEFAULT_OUT, help=f"report destination (default {DEFAULT_OUT})"
    )
    ap.add_argument(
        "--langs",
        default=None,
        help="comma-separated languages to target (default: "
        "every language the pack covers). Use to calibrate "
        "one language at a time, e.g. --langs rust",
    )
    ap.add_argument("--keep-clones", action="store_true")
    args = ap.parse_args(argv)

    if args.fixtures:
        return run_fixtures(args.rules, args.out)

    engine = load_engine(args.config_home)
    corpus_path = args.corpus or (
        progress_tracker_dir(engine) / "metrics" / "rule-mining" / "tp-corpus.jsonl"
    )
    corpus = load_corpus(corpus_path)
    if not corpus:
        print(f"no TP corpus at {corpus_path} — run /mine-ledger first", file=sys.stderr)
        return 3
    langs = None
    if args.langs:
        langs = {s.strip().lower() for s in args.langs.split(",") if s.strip()}
        unknown = langs - PACK_LANGS
        if unknown:
            print(
                f"--langs: {', '.join(sorted(unknown))} not in PACK_LANGS "
                f"({', '.join(sorted(PACK_LANGS))})",
                file=sys.stderr,
            )
            return 2
    targets = select_targets(corpus, None if args.cwe_set == "all" else args.cwe_set, langs)
    print(
        f"[+] {len(targets)} repo@commit targets "
        f"({sum(t['count'] for t in targets.values())} confirmed TPs)"
        f"{' · langs=' + ','.join(sorted(langs)) if langs else ''}",
        file=sys.stderr,
    )
    if len(targets) < REDISCOVERY_GATE:
        # Fewer repos than the gate needs means no rule can possibly clear
        # it; the run would produce a table of guaranteed failures.
        print(
            f"[!] only {len(targets)} target(s) — below the "
            f"{REDISCOVERY_GATE}-repo gate, so no rule can clear it. "
            f"Widen --cwe-set or --langs.",
            file=sys.stderr,
        )
    covered = pack_cwes(args.rules)
    if not covered:
        print(
            "[!] pack CWEs unreadable (not cached yet?) — skipping the gate-reachability check",
            file=sys.stderr,
        )
    else:
        span, top_cwe = gate_reachability(targets, covered)
        if span < REDISCOVERY_GATE:
            print(
                f"[!] GATE UNREACHABLE: across these targets the widest "
                f"CWE the pack actually has rules for is "
                f"{top_cwe or 'none'} at {span} repo(s), under the "
                f"{REDISCOVERY_GATE}-repo gate. Every rule will score "
                f"zero regardless of quality — read the result as "
                f"'untestable', NOT as a verdict on the pack.",
                file=sys.stderr,
            )

    state = args.out / "per-repo"
    state.mkdir(parents=True, exist_ok=True, mode=0o700)
    per_repo: list[dict] = []
    for i, ((repo, commit), meta) in enumerate(sorted(targets.items())):
        if i >= args.limit:
            break
        slug = re.sub(r"[^A-Za-z0-9_.-]", "-", f"{repo}@{commit[:12]}")
        cached = state / f"{slug}.json"
        if cached.is_file():  # resumable — never re-clone a done repo
            per_repo.append(json.loads(cached.read_text(encoding="utf-8")))
            continue
        dest = CACHE_ROOT / "repos" / slug
        print(f"[{i + 1}/{min(args.limit, len(targets))}] {repo}@{commit[:8]}", file=sys.stderr)
        rec: dict = {
            "repo": repo,
            "commit": commit,
            "tp_locations": sorted(meta["locations"]),
            "scanned": False,
            "rediscovery": [],
            "novel": [],
        }
        if clone_at(repo, commit, dest):
            facts, err = scan(dest, args.rules)
            if err:
                # never let a failed scan masquerade as a clean one
                rec["error"] = err
                print(f"    scan failed: {err}", file=sys.stderr)
            else:
                rec.update(scanned=True, **classify(facts, meta["locations"]))
            if not args.keep_clones:
                shutil.rmtree(dest, ignore_errors=True)
        else:
            rec["error"] = "clone failed (unreachable, gone, or non-https)"
        cached.write_text(json.dumps(rec) + "\n", encoding="utf-8")
        per_repo.append(rec)

    res = aggregate(per_repo)
    sample = novel_sample(per_repo, args.sample)
    args.out.mkdir(parents=True, exist_ok=True, mode=0o700)
    (args.out / "calibration.json").write_text(
        json.dumps(
            {"rules_source": args.rules, "cwe_set": args.cwe_set, **res, "novel_sample": sample},
            indent=1,
        )
        + "\n",
        encoding="utf-8",
    )
    (args.out / "calibration.md").write_text(render(res, args.rules, sample), encoding="utf-8")
    t = res["totals"]
    print(
        f"[+] scanned {t['scanned']}/{t['repos']} · {t['findings']} "
        f"findings ({t['rediscovery']} rediscovery, {t['novel']} novel) "
        f"→ {args.out}/calibration.md",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    import sys

    from traust.cli.__main__ import main

    raise SystemExit(main(["impact", "calibrate-rule-pack", *sys.argv[1:]]))
