#!/usr/bin/env python3
"""
emit_backport_report.py — Collect Amalgamator results into a harness-compatible report.

Reads per-branch results (summary.json, candidate.patch) from the backport
output directory and the source remediation JSON, then emits a single
schema-validated *-backport-report.json.

Usage:
    python3 emit_backport_report.py \
        --results-dir /tmp/backport-fix/results \
        --remediation <path-to-remediation.json> \
        --output <repo>-backport-report.json

    # Validation is ON by default, against the traust-contracts schema:
    python3 emit_backport_report.py \
        --results-dir /tmp/backport-fix/results \
        --remediation <path-to-remediation.json> \
        --output <repo>-backport-report.json
"""
from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from datetime import date
from pathlib import Path

import yaml

# Sibling module in this same directory. Direct execution puts it on sys.path;
# importlib-based loaders (tests) do not, hence the explicit insert.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from _harness_paths import analysis_results_root, contracts_schema_path, harness_version  # noqa: E402

log = logging.getLogger(__name__)


def get_harness_version() -> str:
    """Harness VERSION from the traust/ sibling (traust-internal has none)."""
    return harness_version()


def read_remediation_metadata(path: Path) -> dict:
    """Extract metadata from a remediation JSON."""
    with open(path) as f:
        data = json.load(f)

    metadata = data.get("metadata", {})
    fork = data.get("fork", {})
    findings = data.get("source_findings", [])

    cwes = []
    finding_refs = []
    audit_report_path = ""
    for f in findings:
        cwes.extend(f.get("cwes", []))
        ref = f.get("finding_ref", "")
        if ref:
            finding_refs.append(ref)
        if not audit_report_path:
            audit_report_path = f.get("audit_report_path", "")

    return {
        "seam": "remediation",
        "audit_report_path": audit_report_path,
        "repository": metadata.get("repository", ""),
        "logical_product": metadata.get("logical_product", ""),
        "language": metadata.get("language", ""),
        "fix_commit": fork.get("fix_commit", ""),
        "fix_branch_name": fork.get("fix_branch", ""),
        "base_ref": fork.get("base_ref", ""),
        "fork_url": fork.get("url", ""),
        "cwes": cwes,
        "finding_refs": finding_refs,
        "remediation_path": str(path),
    }


def _branch_head(repo_path: Path, branch: str) -> str:
    """Head SHA of a local branch, or "" — read-only, no fetch."""
    try:
        r = subprocess.run(
            ["git", "-C", str(repo_path), "rev-parse", "--verify", "--quiet",
             f"refs/heads/{branch}"],
            capture_output=True, text=True, timeout=15,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    sha = r.stdout.strip()
    return sha if re.fullmatch(r"[0-9a-f]{7,40}", sha) else ""


def _source_repo(branch_dir: Path) -> Path | None:
    """The source clone recorded in the branch's config copy, if usable."""
    cfg = branch_dir / "config.yaml"
    if not cfg.is_file():
        return None
    try:
        with open(cfg) as f:
            data = yaml.safe_load(f) or {}
        source = (data.get("repository") or {}).get("source_path") or ""
    except (OSError, yaml.YAMLError, AttributeError):
        return None
    path = Path(str(source)).expanduser()
    return path if (path / ".git").exists() else None


def _config_target(branch_dir: Path) -> str:
    """Target branch named in the run's config copy — the real name, not the
    sanitized directory slug (release-4.16 must not become release-4-16)."""
    cfg = branch_dir / "config.yaml"
    if not cfg.is_file():
        return ""
    try:
        with open(cfg) as f:
            data = yaml.safe_load(f) or {}
        target = (data.get("branches") or {}).get("target") or ""
    except (OSError, yaml.YAMLError, AttributeError):
        return ""
    return str(target).removeprefix("origin/").strip()


def read_branch_result(branch_dir: Path, repo_path: Path | None = None) -> dict:
    """Read Amalgamator outputs for a single branch.

    repo_path is the source clone from the run's config copy; it is only used
    to read the preserved amalgamator/<issue_id> branch head when the tracker
    does not carry a commit.
    """
    result = {
        "branch": branch_dir.name,
        "status": "unknown",
        "phase_reached": "",
        # None = unknown: a pipeline success does not prove a build or a test
        # ran (empty commands are allowed), so these are only filled from an
        # explicit verdict and omitted otherwise.
        "build_passed": None,
        "test_passed": None,
        "cost_usd": 0.0,
        "duration_seconds": 0,
        "tokens_used": 0,
        "has_patch": False,
        "patch_path": "",
        "patch_sha256": "",
        "patch_files_changed": 0,
        "backport_commit": "",
        "backport_branch": "",
        "error": "",
    }

    summary_path = branch_dir / "summary.json"
    if summary_path.exists():
        try:
            with open(summary_path) as f:
                summary = json.load(f)

            # Handle both Amalgamator summary formats:
            # Format A (multi-target): {total_targets, succeeded, targets: [{outcome, cost_usd, ...}]}
            # Format B (flat): {status, cost_usd, duration_seconds, ...}
            if "targets" in summary and isinstance(summary["targets"], list):
                target = summary["targets"][0] if summary["targets"] else {}
                outcome = target.get("outcome", "unknown")
                result["status"] = "success" if outcome == "success" else outcome
                result["cost_usd"] = target.get("cost_usd", summary.get("total_cost_usd", 0.0))
                result["duration_seconds"] = target.get("duration_s", summary.get("total_duration_s", 0))
                result["error"] = target.get("error", "")
                # A successful pipeline does not imply the build and the tests
                # ran (the loader allows empty commands), and the summary
                # carries no per-check verdict. Report only what is known;
                # absent booleans are omitted rather than asserted true.
                for key, src in (("build_passed", target), ("test_passed", target)):
                    if isinstance(src.get(key), bool):
                        result[key] = src[key]
                issue_id = target.get("issue_id", "")
                if issue_id:
                    result["backport_branch"] = f"amalgamator/{issue_id}"
                target_branch = str(target.get("target_branch") or "")
                if target_branch:
                    result["branch"] = target_branch.removeprefix("origin/")
            else:
                result["status"] = summary.get("status", "unknown")
                result["phase_reached"] = summary.get("phase_reached", "")
                for key in ("build_passed", "test_passed"):
                    if isinstance(summary.get(key), bool):
                        result[key] = summary[key]
                result["cost_usd"] = summary.get("cost_usd", 0.0)
                result["duration_seconds"] = summary.get("duration_seconds", 0)
                result["tokens_used"] = summary.get("tokens_used", 0)
                result["error"] = summary.get("error", "")
        except (json.JSONDecodeError, KeyError) as e:
            result["error"] = f"Failed to parse summary.json: {e}"
            result["status"] = "error"

    # The directory name is a sanitized slug (release-4.16 -> release-4-16);
    # the real target name lives in the run's config copy. Prefer it so
    # verification hints and worklists name a branch that exists.
    if result["branch"] == branch_dir.name:
        cfg_target = _config_target(branch_dir)
        if cfg_target:
            result["branch"] = cfg_target

    # Provenance recorded at collection time by run_backport.sh. This is the
    # authoritative commit: amalgamator/<issue_id> is mutable and may have
    # been moved by a later run.
    result_path = branch_dir / "result.json"
    has_record = result_path.is_file()
    recorded_head = ""
    if has_record:
        try:
            with open(result_path) as f:
                rd = json.load(f)
            if isinstance(rd, dict):
                sha = str(rd.get("head_sha") or "")
                if re.fullmatch(r"[0-9a-f]{7,40}", sha):
                    recorded_head = sha
                if rd.get("target_branch"):
                    result["branch"] = str(rd["target_branch"]).removeprefix("origin/")
        except (OSError, json.JSONDecodeError):
            pass

    successful = result["status"] in ("success", "passed", "partial_success")
    if successful and recorded_head:
        # Immutable evidence recorded at collection time wins outright: the
        # tracker can be rewritten by a later run, and the branch is mutable.
        result["backport_commit"] = recorded_head
    elif successful and not has_record:
        # Legacy result dirs (written before result.json existed) only.
        tracker = branch_dir / "tracker.json"
        if tracker.is_file():
            try:
                with open(tracker) as f:
                    td = json.load(f)
                if isinstance(td, dict):
                    result["backport_commit"] = (
                        td.get("backport_commit", "") or td.get("final_commit", "")
                    )
            except (OSError, json.JSONDecodeError):
                pass
        if (not result["backport_commit"] and repo_path is not None
                and result.get("backport_branch")):
            result["backport_commit"] = _branch_head(repo_path, result["backport_branch"])
    # If result.json exists but carries no SHA, report no commit: substituting
    # the current (mutable) branch would fabricate provenance.

    patch_path = branch_dir / "candidate.patch"
    if patch_path.exists() and patch_path.stat().st_size > 0:
        result["has_patch"] = True
        result["patch_path"] = str(patch_path)

        content = patch_path.read_bytes()
        result["patch_sha256"] = hashlib.sha256(content).hexdigest()

        files_changed = set()
        for line in patch_path.read_text(errors="replace").splitlines():
            if line.startswith("diff --git"):
                parts = line.split()
                if len(parts) >= 4:
                    files_changed.add(parts[3].removeprefix("b/"))
        result["patch_files_changed"] = len(files_changed)

    # Schema-optional fields must be absent rather than empty.
    if not result["patch_sha256"]:
        del result["patch_sha256"]
        del result["patch_path"]
    if not result.get("backport_commit"):
        result.pop("backport_commit", None)
    if not result.get("backport_branch"):
        result.pop("backport_branch", None)
    for key in ("build_passed", "test_passed"):
        if result.get(key) is None:
            del result[key]

    return result


def read_impact_metadata(path: Path, impact_repo: str | None) -> dict:
    """
    Same metadata shape as read_remediation_metadata, from an
    *-impact-analysis.json (Seam A). The advisory carries no fix commit or
    source branch — both are resolved from the run's configs.
    """
    with open(path) as f:
        data = json.load(f)
    meta = data.get("metadata", {})
    cve = meta.get("cve", "")
    if not cve:
        log.error("Impact analysis has no metadata.cve")
        sys.exit(1)

    entries = data.get("repos", [])
    entry = None
    if impact_repo:
        want = _norm_repo_id(impact_repo)
        entry = next((e for e in entries if _norm_repo_id(e.get("repo", "")) == want), None)
        if entry is None:
            log.error("No repos[] entry matches %r in %s", impact_repo, path)
            sys.exit(1)
    elif len(entries) == 1:
        entry = entries[0]
    else:
        log.error(
            "%d repos[] entries in %s — pass --impact-repo <id> to pick this run's repo",
            len(entries), path,
        )
        sys.exit(1)

    # URL from the entry's ORIGINAL casing (normalization is for matching
    # only — a lowercased URL breaks joins and case-sensitive hosts).
    raw = entry.get("repo", "").strip().removeprefix("repo:")
    for pre in ("https://", "http://", "ssh://", "git://"):
        raw = raw.removeprefix(pre)
    if raw.startswith("git@"):
        raw = raw.removeprefix("git@").replace(":", "/", 1)
    raw = raw.rstrip("/").removesuffix(".git")
    products = entry.get("products") or []
    return {
        "seam": "impact",
        "audit_report_path": "",
        "repository": f"https://{raw}" if raw else "",
        "logical_product": products[0] if products else "",
        "language": "",
        "fix_commit": "",
        "fix_branch_name": "",
        "base_ref": "",
        "fork_url": "",
        "cwes": [],
        "finding_refs": [cve],
        # provenance pointer: the artifact this report was built from
        "remediation_path": str(path),
    }


def _to_https(url: str) -> str:
    """Normalise a git remote URL to https form (provenance readability)."""
    u = url.strip()
    if u.startswith("git@"):
        host, _, path = u[len("git@"):].partition(":")
        return f"https://{host}/{path}"
    if u.startswith(("http://", "ssh://", "git://")):
        return "https://" + u.split("://", 1)[1]
    return u


def read_run_metadata(
    results_dir: Path, repository: str = "", logical_product: str = ""
) -> dict:
    """Seam C: no input artifact at all — read the run's own records.

    A patch-file run (and any manual run) has no *-remediation.json or
    *-impact-analysis.json, but the config copies name the fix commit and the
    source branch, and the source clone's origin names the repository. Without
    this, the documented patch workflow could generate and run configs but
    never emit a report.
    """
    cfg_meta = resolve_from_configs(results_dir)  # also rejects mixed runs
    repo = repository
    if not repo:
        for entry in sorted(results_dir.iterdir()):
            src = _source_repo(entry)
            if src is None:
                continue
            r = subprocess.run(
                ["git", "-C", str(src), "remote", "get-url", "origin"],
                capture_output=True, text=True, timeout=15,
            )
            if r.returncode == 0 and r.stdout.strip():
                repo = _to_https(r.stdout.strip())
                break
    return {
        "seam": "run",
        "audit_report_path": "",
        "repository": repo,
        "logical_product": logical_product,
        "language": "",
        "fix_commit": cfg_meta["fix_commit"],
        "fix_branch_name": "",
        "base_ref": cfg_meta["source_branch"],
        "fork_url": "",
        "cwes": [],
        "finding_refs": [],
        "remediation_path": "",
    }


def _norm_repo_id(value: str) -> str:
    v = value.strip().lower().removeprefix("repo:")
    for pre in ("https://", "http://", "ssh://", "git://"):
        v = v.removeprefix(pre)
    if v.startswith("git@"):
        v = v.removeprefix("git@").replace(":", "/", 1)
    return v.rstrip("/").removesuffix(".git")


def resolve_from_configs(results_dir: Path) -> dict:
    """
    Fix commit and source branch from the per-branch config copies that
    run_backport.sh leaves beside each result. ALL configs must agree —
    disagreement means the results dir mixes runs (stale branch dirs from
    a previous backport), which would silently poison the report's
    provenance.
    """
    commits: set[str] = set()
    sources: set[str] = set()
    for entry in sorted(results_dir.iterdir()):
        cfg_candidate = entry / "config.yaml"
        if not cfg_candidate.is_file():
            # A branch dir with results but no config copy is a stale or
            # foreign leftover — it would enter the report while bypassing
            # this agreement check.
            if entry.is_dir() and (entry / "summary.json").is_file():
                log.error(
                    "Branch dir %s has results but no config.yaml — stale "
                    "leftover from an older run? Use a fresh --output-dir.",
                    entry.name,
                )
                sys.exit(1)
            continue
        try:
            with open(cfg_candidate) as f:
                cfg = yaml.safe_load(f) or {}
        except (OSError, yaml.YAMLError):
            log.error("Unreadable config copy %s — refusing to emit.", cfg_candidate)
            sys.exit(1)
        sha = cfg.get("fix", {}).get("commit", "")
        if sha:
            commits.add(sha)
        source = cfg.get("branches", {}).get("source", "")
        if source:
            sources.add(source.removeprefix("origin/"))
    if len(commits) > 1:
        log.error(
            "Results dir mixes runs: per-branch configs disagree on "
            "fix.commit (%s). Use a fresh --output-dir per backport run.",
            ", ".join(sorted(c[:12] for c in commits)),
        )
        sys.exit(1)
    if len(sources) > 1:
        log.error(
            "Results dir mixes runs: per-branch configs disagree on "
            "branches.source (%s). Use a fresh --output-dir per run.",
            ", ".join(sorted(sources)),
        )
        sys.exit(1)
    return {
        "fix_commit": next(iter(commits), ""),
        "source_branch": next(iter(sources), ""),
    }


def build_report(
    results_dir: Path,
    rem_meta: dict,
) -> dict:
    """Build the full backport report from collected results."""
    branch_results = []
    for entry in sorted(results_dir.iterdir()):
        if entry.is_dir() and entry.name != "__pycache__":
            branch_results.append(read_branch_result(entry, _source_repo(entry)))

    # A successful row must carry a commit. If result.json, the tracker and
    # the preserved branch all failed to yield one, the only "provenance"
    # left would be a mutable branch name — refuse rather than fabricate it.
    for r in branch_results:
        if r["status"] in ("success", "passed") and not r.get("backport_commit"):
            log.error(
                "Branch %s is reported successful but has no recorded commit "
                "(result.json, tracker, or preserved branch) — refusing to "
                "emit fabricated provenance", r["branch"],
            )
            sys.exit(1)

    # pipeline_stop = pipeline declined to act: a skip, not a failure.
    passed = sum(1 for r in branch_results if r["status"] in ("success", "passed"))
    skipped = sum(1 for r in branch_results if r["status"] in ("skipped", "pipeline_stop"))
    failed = sum(
        1 for r in branch_results
        if r["status"] not in ("success", "passed", "skipped", "pipeline_stop")
    )
    total_cost = sum(r["cost_usd"] for r in branch_results)
    total_duration = sum(r["duration_seconds"] for r in branch_results)

    # Always consult the run's config copies. They are the only record of what
    # actually executed, and resolve_from_configs() is where a results dir
    # that mixes runs is rejected. Calling it only when the artifact lacks a
    # commit let conflicting configs be attributed to one source fix — and
    # misattributed `--patch-file --remediation` runs, where the patch created
    # a commit the remediation JSON never saw.
    cfg_meta = resolve_from_configs(results_dir)

    fix_commit = rem_meta["fix_commit"]
    if fix_commit and cfg_meta["fix_commit"] and fix_commit != cfg_meta["fix_commit"]:
        log.warning(
            "Input artifact names fix commit %s but the run used %s — using the "
            "run's commit (the artifact can be stale; a patch input creates a "
            "new commit)",
            fix_commit[:12], cfg_meta["fix_commit"][:12],
        )
        fix_commit = cfg_meta["fix_commit"]
    fix_commit = fix_commit or cfg_meta["fix_commit"]
    if not fix_commit:
        if rem_meta.get("seam") == "impact":
            log.error(
                "No fix commit resolvable from the results dir's config copies "
                "(re-run run_backport.sh, which writes them) — refusing to emit "
                "a report with fabricated provenance."
            )
            sys.exit(1)
        log.warning("Could not resolve fix_commit — report may fail schema validation.")
        fix_commit = "0000000"

    source_branch = (
        cfg_meta["source_branch"]
        or rem_meta["base_ref"] or rem_meta["fix_branch_name"]
        or "unknown"
    )
    artifact_branch = rem_meta["base_ref"] or rem_meta["fix_branch_name"]
    if artifact_branch and cfg_meta["source_branch"] and artifact_branch != cfg_meta["source_branch"]:
        log.warning(
            "Input artifact says source branch %r but the run used %r — using the "
            "run's value",
            artifact_branch, cfg_meta["source_branch"],
        )

    report = {
        "title": f"Backport Report: {rem_meta['repository'].split('/')[-1]}",
        "metadata": {
            "date": date.today().isoformat(),
            "harness_version": get_harness_version(),
            "repository": rem_meta["repository"],
            "logical_product": rem_meta["logical_product"],
            "language": rem_meta["language"],
            "operator": "amalgamator",
        },
        "source_fix": {
            "commit": fix_commit,
            "branch": source_branch,
            "fork_url": rem_meta["fork_url"],
            "remediation_path": rem_meta["remediation_path"],
            "finding_refs": rem_meta["finding_refs"],
            "cwes": rem_meta["cwes"],
        },
        "target_branches": branch_results,
        "summary": {
            "total": len(branch_results),
            "passed": passed,
            "failed": failed,
            "skipped": skipped,
            "total_cost_usd": round(total_cost, 2),
            "total_duration_seconds": total_duration,
        },
    }

    # verification_hint for verify-remediation: one entry per successful
    # branch (source of truth for what the fix proved is the run's config).
    successful = [r for r in branch_results if r["status"] in ("success", "passed") and r.get("has_patch")]
    # Prefer the immutable commit: the branch is mutable and a later run can
    # move it, pointing verification at code this run never produced.
    hint_ref = ""
    if successful:
        hint_ref = (
            successful[0].get("backport_commit")
            or successful[0].get("backport_branch")
            or successful[0]["branch"]
        )
    if successful:
        repo_name = rem_meta["repository"].split("/")[-1].removesuffix(".git")
        report["verification_hint"] = {
            **({"original_audit_report": rem_meta["audit_report_path"]}
               if rem_meta.get("audit_report_path") else {}),
            "repository": rem_meta["repository"],
            "branches": [
                {
                    "target_branch": r["branch"],
                    **({"backport_commit": r["backport_commit"]} if r.get("backport_commit") else {}),
                    **({"backport_branch": r["backport_branch"]} if r.get("backport_branch") else {}),
                }
                for r in successful
            ],
            "command": (
                f"/verify-remediation <{repo_name}-security-audit.json> "
                f"<repo>@{hint_ref}"
            ),
        }

    return report


def validate_against_schema(report: dict, schema_path: Path) -> bool:
    """Validate the report against a JSON schema. Returns True if valid."""
    try:
        import jsonschema
    except ImportError:
        # Fail closed: a missing validator is not evidence of a valid report,
        # and publishing one would contradict the skill's promise.
        log.error(
            "jsonschema is not installed — refusing to treat the report as "
            "valid. Install it (pip install jsonschema) or pass --no-schema "
            "deliberately."
        )
        return False

    with open(schema_path) as f:
        schema = json.load(f)

    try:
        jsonschema.validate(report, schema)
        log.info("Report validates against schema.")
        return True
    except jsonschema.ValidationError as e:
        log.error("Schema validation failed: %s", e.message)
        return False


_PATH_TOKEN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


def _copy_untrusted_file(src: Path, dst: Path) -> bool:
    """
    Race-free copy from the untrusted results dir: O_NOFOLLOW open +
    fstat-enforced regular single-link file. False on refusal.
    """
    try:
        fd = os.open(src, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError as e:
        log.error("Refusing publish copy of %s: %s", src, e)
        return False
    fsrc = None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
            log.error(
                "Refusing publish: %s is not a regular single-link file "
                "(nlink=%d)", src, st.st_nlink,
            )
            return False
        fsrc = os.fdopen(fd, "rb")
        with open(dst, "wb") as fdst:
            shutil.copyfileobj(fsrc, fdst)
        return True
    finally:
        if fsrc is not None:
            fsrc.close()
        else:
            os.close(fd)


def default_publish_root() -> Path | None:
    """The analysis-results root: AUDIT_RESULTS_ROOT, else the sibling of the
    workspace (never a fixed parent count — see _harness_paths)."""
    return analysis_results_root()


def publish_results(
    publish_root: Path,
    results_dir: Path,
    report: dict,
    rem_meta: dict,
) -> Path | None:
    """
    Publish report/patches/delivery record under
    <publish_root>/remediations/<logical_product>/<repo>/ — the lane
    remediate-finding writes to. Needs no token or fork access.
    Returns the destination directory, or None on refusal.
    """
    repo_short = (
        rem_meta["repository"].rstrip("/").rsplit("/", 1)[-1].removesuffix(".git")
        if rem_meta["repository"] else ""
    )
    logical = rem_meta["logical_product"] or repo_short
    # JSON-derived path components: campaign charset only, no dot-runs.
    for v in (logical, repo_short):
        if not v or not _PATH_TOKEN_RE.match(v) or ".." in v:
            log.error("Unsafe or empty path component for publish: %r", v)
            return None

    dest = publish_root / "remediations" / logical / repo_short

    # The results dir is pipeline-writable: a planted symlink/hardlink named
    # candidate.patch or delivery.json would copy arbitrary host files into
    # a committed tree. Refuse before touching dest, so a refusal leaves
    # any previous publish intact.
    def tampered(p: Path) -> bool:
        if p.is_symlink():
            return True
        if not p.exists():
            return False
        return not p.is_file() or p.lstat().st_nlink != 1

    to_copy: list[tuple[Path, Path]] = []
    patch_map: dict[str, str] = {}
    for entry in sorted(results_dir.iterdir()):
        if entry.is_symlink():
            log.error("Refusing publish: symlinked entry in results dir: %s", entry)
            return None
        if not entry.is_dir():
            continue
        if not _PATH_TOKEN_RE.match(entry.name) or ".." in entry.name:
            log.warning("Skipping branch dir with unsafe name: %r", entry.name)
            continue
        patch = entry / "candidate.patch"
        if tampered(patch):
            log.error("Refusing publish: symlink or non-regular file: %s", patch)
            return None
        if patch.is_file() and patch.stat().st_size > 0:
            dst_patch = dest / f"{repo_short}-backport-{entry.name}.patch"
            to_copy.append((patch, dst_patch))
            patch_map[str(patch)] = str(dst_patch)

    delivery = results_dir / "delivery.json"
    if tampered(delivery):
        log.error("Refusing publish: symlink or non-regular file: %s", delivery)
        return None
    if delivery.is_file():
        to_copy.append((delivery, dest / f"{repo_short}-backport-delivery.json"))

    # Build the complete artifact set in a staging directory, then swap it in.
    # Copying straight into dest after deleting the old files meant a failure
    # on the second patch destroyed the previous, complete publication.
    dest.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=".publish-", dir=dest.parent))
    try:
        # Rewrite patch_path to the PUBLISHED file. The report travels with
        # the patches; leaving scratch paths made every published reference
        # dangle as soon as the results dir was cleaned up.
        published_report = json.loads(json.dumps(report))
        for row in published_report.get("target_branches", []):
            p = row.get("patch_path")
            if p and p in patch_map:
                row["patch_path"] = patch_map[p]

        with open(staging / f"{repo_short}-backport-report.json", "w") as f:
            json.dump(published_report, f, indent=2)
        published = 1
        for src, dst in to_copy:
            if not _copy_untrusted_file(src, staging / dst.name):
                return None
            published += 1

        # Swap only now that every artifact is in place.
        backup = None
        if dest.exists():
            backup = dest.with_name(f"{dest.name}.old-{os.getpid()}")
            dest.rename(backup)
        try:
            staging.rename(dest)
        except OSError as e:
            if backup is not None:
                backup.rename(dest)
            log.error("Publish swap failed (%s); previous publication restored", e)
            return None
        if backup is not None:
            shutil.rmtree(backup, ignore_errors=True)
    finally:
        if staging.exists():
            shutil.rmtree(staging, ignore_errors=True)

    log.info("Published %d artifact(s) to %s", published, dest)
    return dest


def main():
    parser = argparse.ArgumentParser(
        description="Emit a backport report from Amalgamator results."
    )
    parser.add_argument(
        "--results-dir", "-d", required=True, type=Path,
        help="Directory containing per-branch result subdirectories"
    )
    parser.add_argument(
        "--remediation", "-r", type=Path, default=None,
        help="Seam B input: path to *-remediation.json"
    )
    parser.add_argument(
        "--impact", type=Path, default=None,
        help="Seam A input: path to *-impact-analysis.json (no remediation "
             "JSON needed; fix commit and source branch come from the run's "
             "config copies)"
    )
    parser.add_argument(
        "--impact-repo", type=str, default=None,
        help="repos[] id to select when the impact analysis covers several repos"
    )
    parser.add_argument(
        "--repository", type=str, default="",
        help="Repository URL for a run-only report (default: the source "
             "clone's origin); ignored with --remediation/--impact"
    )
    parser.add_argument(
        "--logical-product", type=str, default="",
        help="logical_product for a run-only report (default: the repo name)"
    )
    parser.add_argument(
        "--output", "-o", required=True, type=Path,
        help="Output path for the backport report JSON"
    )
    parser.add_argument(
        "--schema", "-s", type=Path, default=None,
        help="Schema for validation (default: the bundled "
             "the traust-contracts backport-report schema; validation is ON)"
    )
    parser.add_argument(
        "--no-schema", action="store_true",
        help="Skip schema validation (not recommended)"
    )
    parser.add_argument(
        "--publish-root", type=Path, default=None,
        help="analysis-results checkout root (default: AUDIT_RESULTS_ROOT "
             "or the ../analysis-results sibling). Publishing is ON by "
             "default: the report, per-branch candidate patches, and the "
             "delivery record land under remediations/<logical_product>/"
             "<repo>/ (no token needed)"
    )
    parser.add_argument(
        "--no-publish", action="store_true",
        help="Skip publishing into analysis-results (report is still "
             "written to --output)"
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )

    if not args.results_dir.exists():
        log.error("Results directory not found: %s", args.results_dir)
        sys.exit(1)
    if args.remediation and args.impact:
        log.error("Provide at most one of --remediation (Seam B) or --impact "
                  "(Seam A); with neither, the report is built from the run's "
                  "own config copies.")
        sys.exit(1)
    if args.remediation and args.impact_repo:
        log.error("--impact-repo only applies to --impact mode.")
        sys.exit(1)
    if (args.remediation or args.impact) and (args.repository or args.logical_product):
        log.error("--repository/--logical-product only apply to a run-only report.")
        sys.exit(1)
    if args.remediation and not args.remediation.exists():
        log.error("Remediation JSON not found: %s", args.remediation)
        sys.exit(1)
    if args.impact and not args.impact.exists():
        log.error("Impact analysis JSON not found: %s", args.impact)
        sys.exit(1)
    if args.schema is not None and not args.schema.is_file():
        log.error("Schema not found: %s", args.schema)
        sys.exit(1)

    if args.remediation:
        rem_meta = read_remediation_metadata(args.remediation)
    elif args.impact:
        rem_meta = read_impact_metadata(args.impact, args.impact_repo)
    else:
        log.info("No --remediation/--impact given — building from the run's "
                 "config copies (patch/manual input)")
        rem_meta = read_run_metadata(
            args.results_dir, args.repository, args.logical_product
        )
    report = build_report(args.results_dir, rem_meta)

    # Validation is ON by default: the skill promises validated reports, and
    # an opt-in flag meant the documented commands emitted unchecked JSON.
    # A missing bundled schema is a packaging error, not a reason to emit
    # unchecked output — fail closed unless --no-schema is explicit.
    if args.no_schema:
        schema_path = None
    else:
        schema_path = args.schema
        if schema_path is None:
            schema_path = contracts_schema_path("backport-report.schema.json")
            if schema_path is None:
                log.error(
                    "backport-report schema not found — install traust-contracts "
                    "(or check out it as a sibling), or pass --no-schema to skip "
                    "validation deliberately"
                )
                sys.exit(1)

    schema_ok = True
    if schema_path is not None:
        schema_ok = validate_against_schema(report, schema_path)
        if not schema_ok:
            log.error(
                "Report failed schema validation — writing --output for "
                "debugging, but NOT publishing an invalid report."
            )

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)
    if not schema_ok:
        sys.exit(1)

    # Publishing is on by default; explicit missing root errors, a missing
    # default sibling only warns (standalone clones).
    published_dir = None
    if not args.no_publish:
        publish_root = args.publish_root or default_publish_root()
        if publish_root is None:
            log.warning(
                "no analysis-results root found (set HARNESS_WORKSPACE, "
                "AUDIT_RESULTS_ROOT, or pass --publish-root) — skipping publish"
            )
        elif not publish_root.is_dir():
            if args.publish_root:
                log.error(
                    "Publish root not found or not a directory: %s", publish_root
                )
                sys.exit(1)
            log.warning(
                "analysis-results not found at %s — skipping publish "
                "(set AUDIT_RESULTS_ROOT or pass --publish-root)",
                publish_root,
            )
        else:
            published_dir = publish_results(
                publish_root, args.results_dir, report, rem_meta
            )
            if published_dir is None:
                sys.exit(1)

    print()
    print("=" * 60)
    print("  BACKPORT REPORT")
    print("=" * 60)
    print(f"  Repository: {rem_meta['repository']}")
    print(f"  Fix commit: {rem_meta['fix_commit']}")
    print(f"  Branches:   {report['summary']['total']}")
    print(f"  Passed:     {report['summary']['passed']}")
    print(f"  Failed:     {report['summary']['failed']}")
    print(f"  Total cost: ${report['summary']['total_cost_usd']:.2f}")
    print(f"  Report:     {args.output}")
    if published_dir is not None:
        print(f"  Published:  {published_dir}")
    print("=" * 60)


if __name__ == "__main__":
    main()
