#!/usr/bin/env python3
"""Apply one fleet-fix transform spec to one repo clone (capability C5).

The deterministic core of /fleet-fix: given a schema-validated transform
spec (contracts/schemas/fleet-fix.schema.json) and a CLEAN working clone, it

  1. runs the spec's own golden tests in a scratch dir (pinned test SHA) —
     a failing golden test aborts before any real repo is touched;
  2. scans only the spec's file_glob allowlist;
  3. matcher kind `pinned_ref_line`: finds lines matching match_regex that
     sit within context_window lines AFTER a context_regex line, resolves
     the nearest preceding url_regex capture via `git ls-remote` (or the
     --pin override), and rewrites the line from the template;
     kind `ast_grep`: shells out to `ast-grep --update-all`;
  4. enforces guards (max_files_changed, clean tree) and writes
     <repo>-<spec-id>.diff + <repo>-<spec-id>-result.json to --out-dir.

Interactive apply stays here until traust has an ops CLI to submit/approve/claim
a fleet-fix run order - NEED(ops CLI); under a leased order, use
`traust remediation fleet-apply` (traust-core's apply_fleet_fix door).

It NEVER commits, forks, or opens MRs — those are the skill's later,
human-gated stages. Exit 0 = applied (or no matches — see result JSON);
2 = guard/golden-test refusal; 1 = tool failure.

CLI:
    python3 harnessing/7-remediate/fleet-fix/scripts/apply_fleet_fix.py \
        --spec specs/<id>.yaml --repo <clone> --out-dir <dir> \
        [--pin SHA] [--date YYYY-MM-DD]
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

import jsonschema
import yaml
from traust_contracts.paths import schema_path

# Harness root: the directory holding VERSION, found by walking up rather
# than counting parents, so nesting this skill under a stage directory
# (skill-usability plan 1.2) cannot silently repoint it.
HARNESS = next(p for p in Path(__file__).resolve().parents if (p / "VERSION").is_file())
SCHEMA = json.loads(schema_path("fleet-fix").read_text(encoding="utf-8"))


def load_spec(path: Path) -> dict:
    spec = yaml.safe_load(path.read_text(encoding="utf-8"))
    jsonschema.validate(spec, SCHEMA)
    return spec


def ls_remote_sha(url: str, ref: str, timeout: int = 60) -> str | None:
    # url is harvested from TARGET-REPO file contents (spec url_regex) —
    # hostile by definition. https-only + GIT_ALLOW_PROTOCOL blocks
    # ext::/ssh helper execution; the dash checks block option injection
    # (audit A1, confirmed-RCE class; remediation plan P0.1).
    if not re.match(r"^https://[^\s'\"]+$", url or ""):
        return None
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]*", ref or ""):
        return None
    try:
        out = subprocess.run(
            ["git", "ls-remote", "--", url, f"refs/heads/{ref}", ref],
            capture_output=True,
            text=True,
            timeout=timeout,
            env={**os.environ, "GIT_ALLOW_PROTOCOL": "https", "GIT_TERMINAL_PROMPT": "0"},
        )
        for line in out.stdout.splitlines():
            sha = line.split("\t")[0].strip()
            if re.fullmatch(r"[0-9a-f]{40}", sha):
                return sha
    except (subprocess.SubprocessError, OSError):
        pass
    return None


def glob_files(repo: Path, globs: list[str]) -> list[Path]:
    out = []
    for pattern in globs:
        for p in sorted(repo.glob(pattern)):
            if p.is_file() and not p.is_symlink():
                out.append(p)
    return out


def apply_pinned_ref_line(spec: dict, repo: Path, pin: str | None, date: str) -> dict:
    m = spec["matcher"]
    ctx_rx = re.compile(m["context_regex"])
    match_rx = re.compile(m["match_regex"])
    url_rx = re.compile(m["url_regex"]) if m.get("url_regex") else None
    ctx_win = m.get("context_window", 3)
    url_win = m.get("url_window", 10)
    ref = (spec.get("resolver") or {}).get("ref", "main")

    sha_cache: dict[str, str | None] = {}
    changed: dict[str, int] = {}
    unresolved: list[str] = []

    for f in glob_files(repo, m["file_glob"]):
        lines = f.read_text(encoding="utf-8", errors="replace").splitlines(keepends=True)
        dirty = False
        for i, line in enumerate(lines):
            mt = match_rx.match(line.rstrip("\n"))
            if not mt:
                continue
            ctx_lo = max(0, i - ctx_win)
            if not any(ctx_rx.search(lines[j]) for j in range(ctx_lo, i)):
                continue
            sha = pin
            if sha is None and url_rx is not None:
                url = None
                for j in range(i - 1, max(-1, i - url_win - 1), -1):
                    um = url_rx.search(lines[j])
                    if um:
                        url = um.group(1)
                        break
                if url is None:
                    unresolved.append(f"{f}:{i + 1}: no URL in window")
                    continue
                if url not in sha_cache:
                    sha_cache[url] = ls_remote_sha(url, ref)
                sha = sha_cache[url]
                if sha is None:
                    unresolved.append(f"{f}:{i + 1}: ls-remote failed for {url}")
                    continue
            new = spec["rewrite"]["template"].format(
                indent=mt.group(1), sha=sha, short_sha=sha[:12], ref=ref, date=date, id=spec["id"]
            )
            eol = "\n" if line.endswith("\n") else ""
            lines[i] = new + eol
            dirty = True
        if dirty:
            f.write_text("".join(lines), encoding="utf-8")
            changed[str(f.relative_to(repo))] = changed.get(str(f.relative_to(repo)), 0) + 1
    return {"files_changed": sorted(changed), "unresolved": unresolved}


def apply_ast_grep(spec: dict, repo: Path) -> dict:
    m = spec["matcher"]
    cmd = [
        "ast-grep",
        "run",
        "--pattern",
        m["pattern"],
        "--rewrite",
        spec["rewrite"]["template"],
        "--lang",
        m["lang"],
        "--update-all",
        *[str(repo / g) for g in m["file_glob"]],
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    if proc.returncode not in (0, 1):
        raise RuntimeError(f"ast-grep failed: {proc.stderr[:400]}")
    diff = git(repo, "diff", "--name-only")
    return {"files_changed": [ln for ln in diff.splitlines() if ln], "unresolved": []}


def git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, text=True, timeout=120
    ).stdout


def run_golden_tests(spec: dict, date: str) -> list[str]:
    """Each golden test materializes a throwaway repo, applies the spec
    with a pinned deterministic SHA, and asserts the after-state."""
    failures = []
    for t in spec["tests"]:
        with tempfile.TemporaryDirectory(prefix="fleetfix-golden-") as tmp:
            repo = Path(tmp)
            subprocess.run(["git", "init", "-q", str(repo)], check=True, capture_output=True)
            target = repo / t["file"]
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(t["before"], encoding="utf-8")
            apply_pinned_ref_line(spec, repo, pin="0" * 40, date=date) if spec["matcher"][
                "kind"
            ] == "pinned_ref_line" else apply_ast_grep(spec, repo)
            after = target.read_text(encoding="utf-8")
            for want in t["after_contains"]:
                if (
                    want.format(sha="0" * 40, short_sha="0" * 12, id=spec["id"], date=date)
                    not in after
                ):
                    failures.append(f"{t['name']}: missing {want!r}")
            for bad in t.get("after_not_contains") or []:
                if bad in after:
                    failures.append(f"{t['name']}: still contains {bad!r}")
    return failures


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--spec", type=Path, required=True)
    ap.add_argument("--repo", type=Path, required=True)
    ap.add_argument("--out-dir", type=Path, required=True)
    ap.add_argument(
        "--pin", default=None, help="skip the resolver and pin to this SHA (tests/reproducibility)"
    )
    ap.add_argument("--date", default=datetime.date.today().isoformat())
    args = ap.parse_args(argv)

    spec = load_spec(args.spec)
    repo = args.repo.resolve()

    failures = run_golden_tests(spec, args.date)
    if failures:
        for f in failures:
            print(f"GOLDEN TEST FAILED: {f}", file=sys.stderr)
        return 2

    if (
        spec["guards"].get("require_clean_tree", True)
        and git(repo, "status", "--porcelain").strip()
    ):
        print(f"guard: {repo} working tree is not clean", file=sys.stderr)
        return 2

    if spec["matcher"]["kind"] == "pinned_ref_line":
        res = apply_pinned_ref_line(spec, repo, args.pin, args.date)
    else:
        res = apply_ast_grep(spec, repo)

    max_files = spec["guards"].get("max_files_changed")
    if max_files and len(res["files_changed"]) > max_files:
        git(repo, "checkout", "--", ".")
        print(
            f"guard: {len(res['files_changed'])} files changed exceeds "
            f"max_files_changed={max_files} — reverted",
            file=sys.stderr,
        )
        return 2

    diff = git(repo, "diff")
    args.out_dir.mkdir(parents=True, exist_ok=True)
    stem = f"{repo.name}-{spec['id']}"
    (args.out_dir / f"{stem}.diff").write_text(diff, encoding="utf-8")
    result = {
        "spec": spec["id"],
        "pattern_ref": spec["pattern_ref"],
        "repo": str(repo),
        "applied": bool(res["files_changed"]),
        "files_changed": res["files_changed"],
        "unresolved": res["unresolved"],
        "date": args.date,
        "pinned": bool(args.pin),
    }
    (args.out_dir / f"{stem}-result.json").write_text(
        json.dumps(result, indent=2) + "\n", encoding="utf-8"
    )
    print(
        f"{spec['id']} @ {repo.name}: "
        f"{len(res['files_changed'])} file(s) changed, "
        f"{len(res['unresolved'])} unresolved; diff -> "
        f"{args.out_dir / (stem + '.diff')}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
