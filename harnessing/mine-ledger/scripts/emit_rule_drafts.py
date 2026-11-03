#!/usr/bin/env python3
"""Emit regression-rule drafts from resolved ledger findings (C6).

Every finding the disposition ledger records as RESOLVED at a named fix
commit yields a natural calibration pair: the pre-fix file (the rule MUST
fire on it) and the post-fix file (the rule MUST NOT fire). This script
harvests those pairs — the same extraction the recall benchmark
bootstraps from — and stages one DRAFT per finding under
harnessing/mine-ledger/rule-drafts/:

    <draft-id>/
      DRAFT.md              evidence: finding, fix commit, rationale
      before/<files>        pre-fix content  (must-fire fixtures)
      after/<files>         post-fix content (must-not-fire fixtures)
      rule.skeleton.yaml    id/metadata prefilled; patterns: TODO

Authoring the pattern is the /mine-ledger skill's (human+LLM) job; this
script is deterministic staging plus the calibration gate:

    --verify <draft-dir> --rule <rules.yaml>

runs opengrep with the candidate rule over before/ (>=1 match required)
and after/ (0 matches required). A draft is promotable into the pack only
when --verify passes. The pack is the single copy bundled in traust-engine
(src/traust_engine/data/secure-code-audit/opengrep-rules/): promotion is a
traust-engine PR, then the traust engine-pin bump. Drafts are NEVER loaded by run_opengrep — the
rule-drafts/ dir sits outside the pack.

CLI:
    python3 scripts/emit_rule_drafts.py \
        --results-root PATH --limit 6 \
        [--cwe CWE-78] [--out-dir harnessing/mine-ledger/rule-drafts]
    python3 scripts/emit_rule_drafts.py --verify <draft-dir> --rule <yaml>
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from traust_engine._util.script_loader import load_script

from traust.context import add_config_home_arg, resolve_results_root
from traust.paths import skill_dir

HARNESS_ROOT = Path(__file__).resolve().parents[3]


def _load(name: str):
    return load_script(name, HARNESS_ROOT)


bb = _load("bootstrap_benchmark_targets")

EXT_LANG = {
    ".go": "go",
    ".py": "python",
    ".sh": "bash",
    ".bash": "bash",
    ".ts": "typescript",
    ".js": "typescript",
    ".tsx": "typescript",
}


def lang_of(paths: list[str]) -> str | None:
    for p in paths:
        lang = EXT_LANG.get(Path(p).suffix.lower())
        if lang:
            return lang
    return None


def git_show(repo: Path, ref: str, path: str) -> str | None:
    proc = subprocess.run(
        ["git", "-C", str(repo), "show", f"{ref}:{path}"],
        capture_output=True,
        text=True,
        timeout=60,
    )
    return proc.stdout if proc.returncode == 0 else None


def draft_slug(cand: dict) -> str:
    exp = cand["expected"][0]
    return re.sub(r"[^a-z0-9-]+", "-", f"{cand['id'][3:]}-{exp['cwes'][0].lower()}")


def emit_draft(cand: dict, out_dir: Path) -> dict | None:
    """Clone, extract before/after pairs, write the draft dir."""
    exp = cand["expected"][0]
    lang = lang_of(exp["paths"])
    if lang is None:
        return None
    slug = draft_slug(cand)
    draft = out_dir / slug
    with tempfile.TemporaryDirectory(prefix="ruledraft-") as tmp:
        r = subprocess.run(
            ["git", "clone", "-q", "--filter=blob:none", cand["repo_url"], tmp],
            capture_output=True,
            text=True,
            timeout=300,
        )
        if r.returncode != 0:
            return None
        repo = Path(tmp)
        fix = cand["fix_commit"]
        pairs = []
        for p in exp["paths"]:
            before = git_show(repo, f"{fix}^", p)
            after = git_show(repo, fix, p)
            if before is None:
                continue  # file added by the fix — no pre-image to fire on
            if after is not None and before == after:
                # the fix commit didn't touch this finding path — a
                # non-differing pair calibrates nothing
                continue
            pairs.append((p, before, after))
        if not pairs:
            return None
        if draft.exists():
            shutil.rmtree(draft)
        for sub, _idx in (("before", 1), ("after", 2)):
            (draft / sub).mkdir(parents=True)
        used_names: set[str] = set()
        for p, before, after in pairs:
            name = Path(p).name
            if name in used_names:
                # two expected paths share a basename — keep both fixtures by
                # flattening the repo-relative path (sep -> "__"), else the
                # second pair silently overwrites the first and narrows the
                # calibration set
                name = "__".join(Path(p).parts)
                i = 2
                while name in used_names:
                    name = f"{name}~{i}"
                    i += 1
            used_names.add(name)
            (draft / "before" / name).write_text(before, encoding="utf-8")
            if after is not None:
                (draft / "after" / name).write_text(after, encoding="utf-8")
        rule_id = f"harness-{lang}-regression-{slug}"
        (draft / "rule.skeleton.yaml").write_text(
            f"""rules:
  - id: {rule_id}
    languages: [{lang}]
    severity: {"ERROR" if exp["severity"] in ("critical", "high") else "WARNING"}
    message: >-
      TODO — one-sentence description of the vulnerable shape and the fix.
      {exp["cwes"][0]}.
    metadata:
      cwe: {json.dumps(exp["cwes"])}
      category: regression
      confidence: HIGH
      regression_of:
        fingerprint: "{exp.get("fingerprint") or ""}"
        source_finding: "{exp.get("source_finding") or ""}"
        repo: "{cand["repo_url"]}"
        fix_commit: "{fix}"
      references:
        - "{cand["evidence"]["ref"]}"
    patterns:
      - pattern: TODO   # author from before/ (must fire) vs after/ (must not)
""",
            encoding="utf-8",
        )
        (draft / "DRAFT.md").write_text(
            f"""# Rule draft: {rule_id}

**Regression guard for:** {exp.get("title") or "(untitled finding)"}
**CWE:** {", ".join(exp["cwes"])} · **severity:** {exp["severity"]}
**Repo:** {cand["repo_url"]} · **fix commit:** `{fix}`
**Fingerprint:** `{exp.get("fingerprint") or "—"}`

**Fix rationale (verification evidence):**

> {cand["evidence"].get("excerpt", "")[:500]}

**Authoring contract:** write `patterns:` in `rule.skeleton.yaml` so that
`emit_rule_drafts.py --verify {slug} --rule rule.skeleton.yaml`
fires on every file in `before/` and on nothing in `after/`. Then move
the rule into the pack category file in traust-engine
(`src/traust_engine/data/secure-code-audit/opengrep-rules/`, a traust-engine
PR) — not `regression.yaml` dumps —
match the pack's category layout) with `ruleid:`-annotated fixture
lines, and delete this draft dir.
""",
            encoding="utf-8",
        )
    return {"draft": slug, "lang": lang, "cwe": exp["cwes"][0], "files": len(pairs)}


def verify(draft: Path, rule: Path) -> int:
    def run(target: Path) -> int:
        proc = subprocess.run(
            ["opengrep", "scan", "--config", str(rule), "--json", "--quiet", str(target)],
            capture_output=True,
            text=True,
            timeout=300,
        )
        try:
            return len(json.loads(proc.stdout).get("results") or [])
        except json.JSONDecodeError:
            print(
                f"ERROR: opengrep produced no JSON for {target}:\n{proc.stderr[:400]}",
                file=sys.stderr,
            )
            return -1

    n_before = run(draft / "before")
    n_after = run(draft / "after")
    ok = n_before > 0 and n_after == 0
    print(
        f"{draft.name}: before={n_before} (need >0), "
        f"after={n_after} (need 0) -> {'PASS' if ok else 'FAIL'}"
    )
    return 0 if ok else 1


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    add_config_home_arg(ap)
    ap.add_argument("--results-root", type=Path, default=None)
    ap.add_argument("--out-dir", type=Path, default=skill_dir("mine-ledger") / "rule-drafts")
    ap.add_argument("--cwe", default=None)
    ap.add_argument("--limit", type=int, default=6)
    ap.add_argument(
        "--skip-existing",
        action="store_true",
        help="never re-stage a draft dir that already exists "
        "(protects authored-but-unpromoted patterns; the "
        "rule-mining lane's mode)",
    )
    ap.add_argument(
        "--verify", type=Path, default=None, help="draft dir to verify instead of emitting"
    )
    ap.add_argument("--rule", type=Path, default=None)
    args = ap.parse_args(argv)

    if args.verify:
        if not args.rule:
            sys.exit("--verify requires --rule")
        return verify(args.verify, args.rule)

    cands = bb.collect_candidates(resolve_results_root(args))
    if args.cwe:
        cands = [c for c in cands if args.cwe.upper() in c["expected"][0]["cwes"]]
    emitted, skipped_existing = [], 0
    for cand in cands:
        if len(emitted) >= args.limit:
            break
        if args.skip_existing and (args.out_dir / draft_slug(cand)).is_dir():
            skipped_existing += 1
            continue
        res = emit_draft(cand, args.out_dir)
        if res:
            emitted.append(res)
            print(
                f"drafted {res['draft']} ({res['lang']}, {res['cwe']}, {res['files']} file pair(s))"
            )
    print(
        f"{len(emitted)} draft(s) under {args.out_dir}"
        + (f" ({skipped_existing} existing draft(s) left untouched)" if skipped_existing else "")
        + " — author patterns, then --verify each before promoting "
        "into the pack"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
