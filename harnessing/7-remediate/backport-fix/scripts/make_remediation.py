#!/usr/bin/env python3
"""
make_remediation.py — Synthesize a remediation JSON from a triage finding.

`remediate-finding` emits a *-remediation.json as the byproduct of actually
producing a fix. When the fix ALREADY exists as a commit (upstream, a
sustaining fork, a teammate's PR), there is nothing to remediate — but
backport-fix still needs that artifact as its Seam B input. This builds a
schema-valid one from the finding plus the existing commit.

The patch block is derived from the commit itself (git numstat/name-status),
so files_changed/diffstat describe the real fix rather than hand-typed
guesses. Checks default to `skip` — claiming `pass` for a build nobody ran
here would be a lie; pass --check-outcome pass when the commit is known
green.

Usage:
    python3 make_remediation.py \
        --triage analysis-results/oss-findings/cri-o/cri-o/cri-o-triage.json \
        --finding f001 \
        --fix-commit 79a4de5 \
        --repo /path/to/clone \
        --out cri-o.f001-remediation.json
"""
from __future__ import annotations

import argparse
import importlib
import json
import logging
import re
import subprocess
import sys
from datetime import date
from pathlib import Path

# Sibling module in this same directory; see the NOTE in emit_backport_report.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import _harness_paths as _paths  # noqa: E402

log = logging.getLogger(__name__)

_SEVERITIES = ("critical", "high", "medium", "low", "informational")
_CHANGE_TYPE = {"A": "added", "M": "modified", "D": "deleted", "R": "renamed"}
# schema/remediation.schema.json $defs.fix_strategy
_STRATEGIES = (
    "input-validation", "bound-resource", "rbac-scope-down", "auth-add",
    "tls-enforce", "url-allowlist", "digest-pin", "config-default-harden",
    "api-restrict", "remove-feature", "dependency-bump", "other",
)
_CWE_RE = re.compile(r"^CWE-\d{1,5}$")


def git(repo: Path, *args: str) -> str:
    try:
        r = subprocess.run(
            ["git", "-C", str(repo), *args],
            capture_output=True, text=True, timeout=30,
        )
    except subprocess.TimeoutExpired:
        raise SystemExit(f"git {' '.join(args)} timed out in {repo}")
    if r.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed: {r.stderr.strip()}")
    return r.stdout.strip()


def find_entry(report: dict, finding_id: str) -> dict:
    for f in report.get("findings", []):
        if str(f.get("id", "")) == finding_id:
            return f
    raise SystemExit(f"finding {finding_id!r} not found (ids: "
                     f"{[f.get('id') for f in report.get('findings', [])][:10]})")


def resolve_audit(triage_path: Path, triage_finding: dict, explicit: Path | None) -> tuple[dict | None, str]:
    """Locate the audit report backing a triage finding; returns (audit, audit_finding_id)."""
    source = str(triage_finding.get("source", ""))
    audit_id = source.rsplit("#", 1)[-1] if "#" in source else ""
    path = explicit
    if path is None and source:
        candidate = triage_path.parent / source.split("#", 1)[0]
        if candidate.is_file():
            path = candidate
    if path is None or not path.is_file():
        return None, audit_id
    with open(path) as f:
        return json.load(f), audit_id


def patch_block(repo: Path, sha: str, strategy: str, rationale: str) -> dict:
    """Derive files_changed/diffstat from the commit itself."""
    files: list[dict] = []
    for line in git(repo, "show", "--name-status", "--format=", sha).splitlines():
        parts = line.split("\t")
        if len(parts) < 2:
            continue
        files.append({
            "path": parts[-1],
            "change_type": _CHANGE_TYPE.get(parts[0][:1], "modified"),
        })
    additions = deletions = 0
    for line in git(repo, "show", "--numstat", "--format=", sha).splitlines():
        cols = line.split("\t")
        if len(cols) >= 3 and cols[0].isdigit() and cols[1].isdigit():
            additions += int(cols[0])
            deletions += int(cols[1])
    if not files:
        raise SystemExit(f"commit {sha} changes no files — wrong commit?")
    return {
        "strategy": strategy,
        "rationale": rationale,
        "files_changed": files,
        "diffstat": {"files": len(files), "additions": additions, "deletions": deletions},
    }


def harness_version() -> str:
    return _paths.harness_version(with_rev=True)


def _validator_python() -> str | None:
    """Interpreter that can import traust.cli.reporting, else None.

    Preference: this interpreter, then the harness venv (the repo's
    documented convention is ../traust/.venv/bin/python — the harness is a
    sibling checkout, so its dependencies are not in ours).
    """
    for exe in (sys.executable, *(
        [str(_paths.harness_root() / ".venv" / "bin" / "python")]
        if _paths.harness_root() is not None else []
    )):
        try:
            r = subprocess.run(
                [exe, "-c", "from traust.cli import reporting"],
                capture_output=True, timeout=60,
            )
        except (OSError, subprocess.SubprocessError):
            continue
        if r.returncode == 0:
            return exe
    return None


def resolve_schema(explicit: Path | None) -> Path | None:
    """The remediation contract schema.

    Order: --schema, the installed traust-contracts/ai-security-contracts
    package, then a sibling checkout. Schemas left the harness root in the
    contracts refactor, so a hardcoded <repo>/schema path is always wrong.
    """
    if explicit is not None:
        return explicit if explicit.is_file() else None
    for mod, getter in (
        ("traust_contracts.paths", "schema_path"),
        ("ai_security_contracts.paths", "schema_path"),
    ):
        try:
            mod_obj = importlib.import_module(mod)
            p = getattr(mod_obj, getter)("remediation.schema.json")
        except Exception:
            continue
        if Path(p).is_file():
            return Path(p)
    ws = _paths.workspace_root()
    if ws is None:
        return None
    for candidate in (
        ws / "traust-contracts" / "schemas" / "v1" / "remediation.schema.json",
        ws / "ai-security-contracts" / "schemas" / "remediation.schema.json",
    ):
        if candidate.is_file():
            return candidate
    return None


def normalize_repo_url(url: str) -> str:
    url = url.strip().removesuffix(".git")
    if url.startswith("git@"):
        return "https://" + url.removeprefix("git@").replace(":", "/", 1)
    for pre in ("ssh://git@", "ssh://", "git://"):
        if url.startswith(pre):
            return "https://" + url.removeprefix(pre)
    return url


def build(args) -> dict:
    with open(args.triage) as f:
        triage = json.load(f)
    tf = find_entry(triage, args.finding)
    audit, audit_id = resolve_audit(args.triage, tf, args.audit)
    af = {}
    if audit and audit_id:
        try:
            af = find_entry(audit, audit_id)
        except SystemExit:
            log.warning("audit finding %s not found; falling back to triage fields", audit_id)

    cwes = list(args.cwe) or list(af.get("cwes") or [])
    bad = [c for c in cwes if not _CWE_RE.match(str(c))]
    if bad:
        raise SystemExit(f"invalid CWE id(s) {bad} — expected CWE-NNN")
    if not cwes:
        where = (
            "the resolved audit finding carries none"
            if af else
            "no audit finding was resolved (triage `source` missing or not "
            "'<audit>.json#<id>')"
        )
        raise SystemExit(
            f"no CWEs: {where} — pass --cwe CWE-NNN (repeatable) or "
            "--audit <security-audit.json>"
        )

    locations = af.get("locations") or []
    if not locations:
        path = tf.get("file")
        if not path:
            raise SystemExit("no locations: finding has no file, and no audit report was resolved")
        loc = {"path": path}
        if tf.get("line"):
            loc["lines"] = str(tf["line"])
        locations = [loc]

    severity = str(
        args.severity or tf.get("severity") or tf.get("claimed_severity")
        or af.get("severity") or "medium"
    ).lower()
    if severity not in _SEVERITIES:
        severity = "medium"

    title = args.title or tf.get("title") or af.get("title") or f"Finding {args.finding}"
    try:
        fix_commit = git(args.repo, "rev-parse", f"{args.fix_commit}^{{commit}}")
    except RuntimeError as e:
        raise SystemExit(f"--fix-commit not resolvable in {args.repo}: {e}")
    if args.repo_url:
        repo_url = args.repo_url
    else:
        try:
            repo_url = normalize_repo_url(git(args.repo, "remote", "get-url", "origin"))
        except RuntimeError:
            raise SystemExit(
                f"{args.repo} has no 'origin' remote — pass --repo-url"
            )

    base_ref = args.base_ref
    if not base_ref:
        try:
            base_ref = git(args.repo, "symbolic-ref", "refs/remotes/origin/HEAD", "--short").removeprefix("origin/")
        except Exception:
            base_ref = "main"

    audited = args.audited_commit
    if not audited:
        try:
            audited = git(args.repo, "rev-parse", "--short", f"{fix_commit}^")
        except Exception:
            audited = ""

    checks = []
    if args.build_cmd:
        checks.append({"name": "build", "command": args.build_cmd, "outcome": args.check_outcome})
    if args.test_cmd:
        checks.append({"name": "unit-tests", "command": args.test_cmd, "outcome": args.check_outcome})
    if not checks:
        raise SystemExit("--build-cmd and/or --test-cmd is required (backport-fix reads them)")

    metadata = {
        "date": args.date or date.today().isoformat(),
        "harness_version": harness_version(),
        "logical_product": args.product or repo_url.rstrip("/").rsplit("/", 1)[-1],
        "repository": repo_url,
        "operator": args.operator,
    }
    if audited:
        metadata["audited_commit"] = audited
    if args.language:
        metadata["language"] = args.language

    source_finding = {
        "finding_ref": f"{args.triage.name}#{args.finding}",
        "title": title,
        "severity": severity,
        "cwes": cwes,
        "locations": locations,
    }
    # Thread the audit path through so the backport report's
    # verification_hint can name the original audit.
    audit_path = args.audit
    if audit_path is None and audit is not None:
        source = str(tf.get("source", ""))
        candidate = args.triage.parent / source.split("#", 1)[0]
        if candidate.is_file():
            audit_path = candidate
    if audit_path is not None:
        source_finding["audit_report_path"] = str(audit_path)

    passed = sum(1 for c in checks if c["outcome"] == "pass")
    return {
        "title": f"Remediation: {title}",
        "metadata": metadata,
        "source_findings": [source_finding],
        "fork": {
            "url": args.fork_url or repo_url,
            "visibility": args.visibility,
            "base_ref": base_ref,
            "fix_branch": args.fix_branch or f"ex-wing/{args.finding}",
            "fix_commit": fix_commit,
            "upstream_remote": repo_url,
        },
        "patch": patch_block(
            args.repo, fix_commit, args.strategy,
            args.rationale or f"Existing fix {fix_commit[:10]} closes {args.finding}; "
                              "recorded for propagation to release branches.",
        ),
        "checks": checks,
        "summary": {
            "status": args.status,
            "checks_passed": passed,
            "checks_total": len(checks),
        },
    }


def main() -> None:
    p = argparse.ArgumentParser(
        description="Synthesize a schema-valid remediation JSON from a triage finding "
                    "plus an existing fix commit."
    )
    p.add_argument("--triage", required=True, type=Path, help="*-triage.json")
    p.add_argument("--finding", required=True, help="triage finding id (e.g. f001)")
    p.add_argument("--fix-commit", required=True, help="existing commit containing the fix")
    p.add_argument("--repo", required=True, type=Path, help="local clone holding the fix commit")
    p.add_argument("--audit", type=Path, default=None,
                   help="*-security-audit.json for CWEs/locations "
                        "(default: resolved from the triage finding's source field)")
    p.add_argument("--cwe", action="append", default=[], help="CWE-NNN (repeatable); overrides the audit")
    p.add_argument("--title", default="", help="override the finding title")
    p.add_argument("--severity", default="",
                   choices=("", "critical", "high", "medium", "low", "informational"),
                   help="override the triage/audit severity")
    p.add_argument("--audited-commit", default="",
                   help="commit the finding was found at (default: the fix commit's parent)")
    p.add_argument("--out", "-o", type=Path, required=True)
    p.add_argument("--repo-url", default="", help="override the repository URL (default: origin)")
    p.add_argument("--fork-url", default="", help="private mirror URL (default: the repository URL)")
    p.add_argument("--visibility", default="public", choices=("public", "private", "internal"))
    p.add_argument("--base-ref", default="", help="branch the fix lives on (default: origin/HEAD)")
    p.add_argument("--fix-branch", default="", help="default: ex-wing/<finding>")
    p.add_argument("--strategy", default="other", choices=_STRATEGIES,
                   help="patch strategy (schema fix_strategy enum)")
    p.add_argument("--rationale", default="", help="why the fix closes the root cause")
    p.add_argument("--build-cmd", default="", help="build command backport-fix will run per branch")
    p.add_argument("--test-cmd", default="", help="test command backport-fix will run per branch")
    p.add_argument("--check-outcome", default="skip", choices=("pass", "fail", "skip", "error"),
                   help="outcome recorded for the checks (default: skip — not run here)")
    p.add_argument("--status", default="patched",
                   choices=("candidate", "forked", "patched", "checks_passed", "checks_failed",
                            "revalidated_fixed", "revalidated_still_vulnerable", "pr_opened",
                            "merged", "abandoned"))
    p.add_argument("--product", default="", help="logical_product (default: repo name)")
    p.add_argument("--language", default="")
    p.add_argument("--operator", default="make-remediation")
    p.add_argument("--date", default="", help="YYYY-MM-DD (default: today)")
    p.add_argument("--no-validate", action="store_true",
                   help="skip schema validation")
    p.add_argument("--schema", type=Path, default=None,
                   help="remediation contract schema (default: resolved from "
                        "the installed contracts package or a sibling checkout)")
    p.add_argument("--verbose", "-v", action="store_true")
    args = p.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s", datefmt="%H:%M:%S",
    )
    if not args.triage.is_file():
        raise SystemExit(f"triage JSON not found: {args.triage}")
    if not (args.repo / ".git").exists():
        raise SystemExit(f"not a git clone: {args.repo}")

    report = build(args)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with open(args.out, "w") as f:
        json.dump(report, f, indent=2)
    log.info("Wrote %s", args.out)

    if not args.no_validate:
        if args.schema is not None and not args.schema.is_file():
            raise SystemExit(f"--schema not found: {args.schema}")
        schema = resolve_schema(args.schema)
        python = _validator_python()
        if schema is not None and python is not None:
            cmd = [python, "-m", "traust.cli", "reporting", "validate",
                   "--schema", str(schema), str(args.out)]
        else:
            cmd = None

        if cmd:
            try:
                r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            except subprocess.TimeoutExpired:
                args.out.unlink(missing_ok=True)
                raise SystemExit("validation timed out — output removed")
            print(r.stdout.strip().splitlines()[-1] if r.stdout.strip() else "")
            if r.returncode != 0:
                log.error("Schema validation FAILED:\n%s", r.stdout or r.stderr)
                args.out.unlink(missing_ok=True)
                sys.exit(1)
        else:
            missing = "the remediation schema" if schema is None \
                else "a validator (traust.cli / the harness venv)"
            log.error(
                "%s could not be found — refusing to emit an unvalidated "
                "remediation JSON. Install the contracts package, set "
                "HARNESS_WORKSPACE, or pass --no-validate deliberately.",
                missing,
            )
            args.out.unlink(missing_ok=True)
            sys.exit(1)

    print(f"  finding_ref: {report['source_findings'][0]['finding_ref']}")
    print(f"  fix_commit:  {report['fork']['fix_commit']}")
    print(f"  files:       {report['patch']['diffstat']}")
    print(f"\n  Next: python3 harnessing/7-remediate/backport-fix/scripts/generate_backport_configs.py "
          f"--remediation {args.out} --repo {args.repo} --branch-pattern 'release-*' --scan-only")


if __name__ == "__main__":
    main()
