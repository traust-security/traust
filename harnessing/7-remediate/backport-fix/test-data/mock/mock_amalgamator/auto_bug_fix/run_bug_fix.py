"""Mock of the Amalgamator auto_bug_fix pipeline for end-to-end dry runs.

Mimics the real pipeline's observable contract without any LLM calls:
- config path is POSITIONAL (sys.argv[1], no --config flag)
- writes runs/<yaml_basename>_<UTC ts>/ relative to the process CWD
  (the real pipeline ignores output.directory for artifacts)
- per-target subdir named by the sanitized branch; candidate.patch lands
  there (like git format-patch output); parent summary.json in the real
  multi-target shape (targets[].outcome etc.)
- creates the amalgamator/<issue_id> preservation branch in the SOURCE
  repo for success/partial outcomes
- creates the config's workdir with a worktree clone so run_backport.sh's
  fallback patch collection path stays exercised
- exit 0 only when every target's outcome is success

Per-branch outcomes are controlled by MOCK_OUTCOMES (comma-separated
branch=outcome pairs, e.g. "release-2=pipeline_stop"); unlisted branches
succeed.

Extra safety assertion for the harness contract: refuses to run if
GITHUB_TOKEN leaked into the pipeline environment (run_backport.sh must
strip it).
"""
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone

import yaml


def outcomes_from_env() -> dict:
    out = {}
    for pair in os.environ.get("MOCK_OUTCOMES", "").split(","):
        if "=" in pair:
            branch, outcome = pair.split("=", 1)
            out[branch.strip()] = outcome.strip()
    return out


def fail(msg: str) -> None:
    print(f"MOCK-AMALGAMATOR INPUT ERROR: {msg}", file=sys.stderr)
    sys.exit(2)


def main() -> None:
    for leaked in ("GITHUB_TOKEN", "GITHUB_AGENT_TOKEN_GLASSWING"):
        if leaked in os.environ:
            fail(f"{leaked} is present in the pipeline environment — "
                 "run_backport.sh failed to strip it")

    if len(sys.argv) < 2:
        fail("config path must be positional argv[1] (the real pipeline has no --config flag)")
    cfg_path = sys.argv[1]
    with open(cfg_path) as f:
        cfg = yaml.safe_load(f)

    # --- input placement checks (mirrors config_loader requirements) ---
    for key in ("issue_id", "bug_description", "repository", "branches", "fix", "build"):
        if key not in cfg:
            fail(f"missing required top-level key: {key}")
    src = cfg["repository"].get("source_path") or fail("repository.source_path missing")
    source = cfg["branches"].get("source") or fail("branches.source missing")
    target = cfg["branches"].get("target") or fail("branches.target missing")
    fix_commit = cfg["fix"].get("commit") or fail("fix.commit missing")

    for ref, what in ((fix_commit + "^{commit}", "fix.commit"),
                      (source, "branches.source"), (target, "branches.target")):
        r = subprocess.run(["git", "rev-parse", "--verify", "--quiet", ref],
                           cwd=src, capture_output=True)
        if r.returncode != 0:
            fail(f"{what} ({ref}) not resolvable in source repo {src}")

    sanitized = target.removeprefix("origin/").replace("/", "_")
    outcome = outcomes_from_env().get(sanitized, "success")
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    base = os.path.basename(cfg_path)
    base = base[:-5] if base.endswith(".yaml") else base

    # CWD-relative runs/ — deliberately identical to the real pipeline
    run_dir = os.path.join("runs", f"{base}_{ts}")
    tdir = os.path.join(run_dir, sanitized)
    os.makedirs(tdir, exist_ok=True)

    with open(os.path.join(tdir, "dossier.md"), "w") as f:
        f.write(f"# Mock dossier — {cfg['issue_id']}\noutcome: {outcome}\n")
    with open(os.path.join(tdir, "run_log.txt"), "w") as f:
        f.write("mock pipeline run\n")
    with open(os.path.join(tdir, f"{cfg['issue_id']}_{ts}.json"), "w") as f:
        json.dump({"run_id": "mock", "issue_id": cfg["issue_id"],
                   "outcome": outcome, "total_cost_usd": 0.42,
                   "backport_commit": fix_commit}, f)

    if outcome in ("success", "partial_success"):
        # candidate.patch lands in the per-target run dir, like the real
        # pipeline (git format-patch bytes)
        with open(os.path.join(tdir, "candidate.patch"), "w") as f:
            f.write("From mock Mon Sep 17 00:00:00 2001\n"
                    "Subject: [PATCH] mock backport\n\n"
                    "diff --git a/mock b/mock\n--- a/mock\n+++ b/mock\n"
                    "@@ -1 +1 @@\n-old\n+new\n")
        # preservation branch in the source clone, like the real pipeline
        subprocess.run(
            ["git", "branch", "-f", f"amalgamator/{cfg['issue_id']}", fix_commit],
            cwd=src, check=True, capture_output=True,
        )
        # workdir worktree so run_backport.sh's fallback path is exercised
        wd = cfg["repository"].get("workdir", "")
        if wd:
            shutil.rmtree(wd, ignore_errors=True)
            os.makedirs(wd, exist_ok=True)
            wt = os.path.join(wd, "worktree")
            subprocess.run(["git", "clone", "-q", src, wt], check=True)
            subprocess.run(
                ["git", "-c", "user.email=m@m", "-c", "user.name=mock",
                 "checkout", "-q", "-b", "mock-backport", fix_commit],
                cwd=wt, check=True,
            )

    summary = {
        "total_targets": 1,
        "succeeded": 1 if outcome == "success" else 0,
        "failed": 0 if outcome == "success" else 1,
        "total_duration_s": 1.2,
        "total_cost_usd": 0.42,
        "targets": [{
            "target_branch": target,
            "issue_id": cfg["issue_id"],
            "outcome": outcome,
            "duration_s": 1.2,
            "cost_usd": 0.42,
            "dossier_path": f"{sanitized}/dossier.md",
            "tracker_path": f"{sanitized}/{cfg['issue_id']}_{ts}.json",
            "error": "" if outcome == "success" else f"mock {outcome}",
        }],
    }
    with open(os.path.join(run_dir, "summary.json"), "w") as f:
        json.dump(summary, f, indent=1)

    print(f"Run directory: {run_dir}")
    print(f"MOCK pipeline finished: outcome={outcome}")
    sys.exit(0 if outcome == "success" else 1)


main()
