#!/usr/bin/env python3
"""Build the continuous-operations rescan worklist — the daily router.

Deterministic router (continuous-operations-wiring-plan §2, rescan-cadence
policy v1.3 §2.2/§2.3): walks every HEAD code-audit in findings.db and
decides which scan lane, if any, each audited repository needs next —
so the expensive agent lanes run only where the assurance actually
decayed. This script only routes — it never authors a finding, verdict,
or audit; every row is an instruction for a lane that does.

Population: repos rows with report_kind='code-audit' AND
is_branch_audit=0 (HEAD audits), deduplicated by normalized repo_url
(freshest audit_date wins; sibling repo_keys recorded on the row).

Risk tiers, from live crit/high counts in findings.db:
  P0  >=5 live crit/high    P1  >=1    P2  0, active
  P3  0 live crit/high AND (archived per stage 1, or dormant:
      pushed_at older than 365d) — live risk always outranks dormancy.
"Live" predicate (value domains inspected 2026-07-27; '' treated as
NULL): severity IN ('critical','high') AND validity (when set) NOT IN
('false_positive','withdrawn','refuted','hardening') AND resolution
(when set) NOT IN ('resolved','risk_accepted'). hardening validity is
excluded because hardening recommendations are not open vulnerability
risk; risk_accepted is a deliberate closed disposition. partially_
resolved / regression_introduced / open stay live.

Two-stage change detection (per-host; unknown hosts get status
'unsupported-host' and still hit the age-ceiling rule — never silently
dropped):
  github.com — stage 1 `gh api repos/{org}/{repo}` (pushed_at,
    archived, default_branch); stage 2
    `gh api repos/{org}/{repo}/compare/{sha}...HEAD` (files[] capped at
    300 — a 300-file diff exceeds every threshold, so `truncated` is a
    flag, not a gap). org/name are validated against a strict charset
    before path interpolation (same guard as check_repo_liveness.py).
  github.com / gitlab.com (plus any host in $GIT_HOSTS) — stage 1
    GET /api/v4/projects/:urlencoded_path (last_activity_at as
    pushed_at, archived, default_branch); stage 2
    GET /api/v4/projects/:path/repository/compare?from=<sha>&to=<branch>
    — per-file line counts come from counting +/- hunk lines in each
    diffs[].diff text (headers skipped). GitLab caps the diffs[] array
    and may set compare_timeout on big compares — `truncated` is set on
    either. Transport is the `glab` CLI (the existing harness GitLab
    pattern: doctor.py auth probe, fleet-fix MR flow) — the token lives
    in glab's own auth store or the GITLAB_TOKEN env var, NEVER in
    argv. glab absent -> per-repo status 'no-credentials'; a private forge
    is VPN-gated, so connection failures -> per-repo 'unreachable'
    (counted and stated in the MD summary so a VPN-down run reads as
    incomplete, never falsely green).
Candidate test is day-granular and fail-safe: pushed_at date >= audit
date (audit_date is date-only; stage-2 zero-diff resolves same-day
false positives).

Decision table (v1.3, first match wins; encoded as data in
DECISION_TABLE so each rule is unit-testable):
  1   unconsumed rescan-events.jsonl rows queue AHEAD of the table
      (external-report -> full-audit+validate; methodology -> full-audit
      for P0-tier repos; cve -> impact-lane; release -> branch/container/
      rpm lane passthrough note). The router marks nothing consumed —
      it is read-only over events and lists what it honored.
  2   R >= 10% (R = C / lines_reviewed, only when recoverable from
      report metadata.additional) OR C >= 8,000 -> full-audit
  3   sensitive files changed AND >=200 lines there -> full-audit
      (P0/P1) / diff-scan (P2+)
  3b  only dependency manifests changed -> deps-lane (osv/impact)
  4   audit age > ceiling (P0 180d / P1 270d / P2 365d) -> full-audit
  5   any first-party change below thresholds -> diff-scan-quarterly
  6   pushed_at moved but 0 commits ahead -> none (tag/branch noise)
  7   otherwise -> none
Session-4 levers (wiring plan §6c, policy v1.4 §2.1b):
  rule-1 bootstrap (lever 1d)  the inventory population (portfolio-
      graph repo nodes, built from the inputs inventory) is diffed
      against the audited baselines; never-audited repos get
      full-audit+bootstrap rows (rule-1-bootstrap) so new intake
      becomes a routed audit obligation on the next daily run. Zero
      API calls: exposure from the curated designation only, private
      default. --no-bootstrap disables; --graph-db overrides the spine
      (default: portfolio-graph.db beside --db).
  exposure classes  public-external | private-external |
      public-internal | private-internal (visibility x externality,
      externality dominant — operator ground truth 2026-07-27),
      computed from stage-1 visibility/fork/parent + corpus ownership
      at zero marginal API cost. Public visibility DEFAULTS to
      public-external (public ~= productized in this portfolio) unless
      an explicit non-productized marker demotes it; a public upstream
      makes a private repo public on the visibility axis (rank 3
      unless also externally tagged). Exposure is the primary sort
      key inside every lane; the external band tightens the rule-4
      ceiling one notch (P1 270->180d, P2 365->270d).
  tripwire (lever 1, v1)  gitleaks over the change's patch text for
      every below-threshold routed row (GitLab patches captured free in
      stage 2; GitHub costs one extra quota-aware call) — any hit
      escalates the row to an immediate diff-scan. Routes only; the
      diff scan adjudicates. --no-tripwire disables.
  trickle-drain (lever 2)  diff-scan-quarterly rows carry drain_order
      (risk sort: exposure -> tier -> S_lines -> C); the weekly
      dispatch takes drain_order < --drain-rate (default ceil(pool/13));
      external-band rows changed >14d ago are flagged overdue.
  refusal pre-route (2026-07-27, pilot follow-up)  diff-lane rows the
      resolver would refuse at dispatch (truncated compare -> churn
      undercounted; >30% of first-party files changed, checked via one
      GitHub tree call per candidate row, quota-aware) are re-routed to
      full-audit at build time — a clone-then-refuse dispatch still
      costs a run (32% of the pilot). GitLab rows skip the ratio check
      honestly. --no-preroute disables. Routes only; the resolver
      remains the dispatch-time authority.
  lever-6 companion backfill (router-lane-coverage-plan §4)  a repo
      whose latest code-audit report stamps metadata.additional
      .companion_lanes: ["cloud-config-audit"] (the audit's tree survey
      saw Terraform/CFN/ARM+Bicep it does not assess) and has no
      cloud-config baseline gets an ADDITIVE iac-baseline row (rule
      lever-6-companion) even without an IaC diff this run — the stamp
      doubles as backfill discovery for repos the Phase-0 census missed.
C sums line changes over FIRST-PARTY files (vendor/, node_modules/,
third_party/, dist/, *_generated*, *.pb.go, *.md excluded); S/S_lines
use the narrow sensitive-identifier matcher over first-party paths.

Budget guard (advisory, no silent truncation): with --monthly-budget
(or a monthly USD ceiling in $TRAUST_CONFIG_HOME/budget-policy.yaml, when one
exists), projected full-audit cost = count x --unit-cost-full; if it
exceeds the budget, lowest-tier table-routed fulls are dropped to fit
and LISTED in dropped_for_budget. Event-injected rows are never
dropped.

Output: rescan-worklist.json + rescan-worklist.md beside it (default
analysis-results/findings/_manifest/). /drift-watch flags the JSON when
older than 3 days.

Usage:
    python3 -m traust.cli.build_rescan_worklist
        [--db FILE] [--events FILE] [--out FILE]
        [--no-network] [--jobs N] [--limit N]
        [--unit-cost-full USD] [--monthly-budget USD]
        [--no-tripwire] [--no-preroute] [--drain-rate N]
"""

from __future__ import annotations

import argparse
import concurrent.futures
import datetime as _dt
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import urllib.parse
from pathlib import Path

from traust_engine.corpus.resolver import normalize_repo_url

from traust.context import add_config_home_arg, analysis_results_dir, load_engine
from traust.paths import HARNESS_ROOT, optional_config_path

# Copied from harnessing/8-verify/verify-remediation/scripts/build_verify_sweep.py
# (parse_pinned_sha + SHA_RX) — small shared copy by convention rather
# than a cross-skill import.
SHA_RX = re.compile(r"\b([0-9a-f]{7,40})\b")

# Same injection guard as harnessing/census/scripts/check_repo_liveness.py: identifier
# segments become an API path — constrain so a crafted repo_url can't
# traverse into another endpoint.
_GH_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


# Forge-host classification. Both kinds are configurable, because both are
# hardcoded otherwise — github.com was a literal in split_repo_url() while
# only GitLab hosts were a named tuple, so the name said GitLab and the
# behaviour covered both.
#
# One variable, kind-tagged, because the two forges parse differently:
# GitHub takes owner/repo, GitLab keeps the full (possibly subgrouped)
# path. A flat host list could not say which rule applies.
#
#   GIT_HOSTS="gitlab:gitlab.example.com,github:ghe.example.com"
#
# Classification only: this widens which URLs are RECOGNISED, never what
# the tool is permitted to reach.
def _git_hosts() -> dict[str, str]:
    hosts = {"github.com": "github", "gitlab.com": "gitlab"}
    for entry in os.environ.get("GIT_HOSTS", "").split(","):
        entry = entry.strip()
        if not entry or ":" not in entry:
            continue
        kind, host = (p.strip().lower() for p in entry.split(":", 1))
        if kind in ("github", "gitlab") and host:
            hosts[host] = kind
    return hosts


GIT_HOSTS = _git_hosts()

# NARROW sensitive matcher (rescan-cadence plan §2.2 — measured to
# discriminate at 43% of changed repos vs 90% for a broad matcher).
SENSITIVE_RX = re.compile(
    r"auth|login|token|secret|cred|crypt|tls|ssl|cert|session|passw|"
    r"rbac|scc|privile|sanitiz|escap|deserial|unmarshal|jwt|oauth|"
    r"saml|acl",
    re.I,
)

DEPS_MANIFESTS = {
    "go.mod",
    "go.sum",
    "package.json",
    "package-lock.json",
    "yarn.lock",
    "poetry.lock",
    "pom.xml",
    "Cargo.toml",
    "Cargo.lock",
    "Gemfile",
    "Gemfile.lock",
}
_EXCLUDE_DIR_PARTS = {"vendor", "node_modules", "third_party", "dist"}

GH_COMPARE_FILE_CAP = 300  # GitHub compare API hard cap on files[]
GITLAB_DIFF_CAP = 1000  # GitLab compare caps diffs[] server-side

CHURN_FULL_LINES = 8000  # rule-2 C threshold (plan §2.3)
CHURN_FULL_RATIO = 0.10  # rule-2 R threshold
SENSITIVE_MIN_LINES = 200  # rule-3
# Diff-resolver refusal threshold — small shared copy of
# harnessing/3-audit/vuln-scan/scripts/resolve_baseline.py MAX_CHANGED_FILE_RATIO
# (same convention as parse_pinned_sha above).
MAX_CHANGED_FILE_RATIO = 0.30
PREROUTE_MIN_FILES = 3  # ratio pre-check only when >= this many
# first-party files changed (tranche-1
# observed a 5/10-file refusal, so the
# floor sits low; the imminent-row scope
# keeps the call count affordable)
PREROUTE_QUOTA_RESERVE = 100  # keep headroom after tree fetches
PREROUTE_HORIZON_WEEKS = 2  # ratio-check quarterly rows only within
# this many weekly drain tranches — rows
# deeper in the pool get checked as they
# approach dispatch (tranche-1 lesson:
# 466 tree calls exhausted the quota
# mid-sweep and failures were silent)
TIER_CEILING_DAYS = {"P0": 180, "P1": 270, "P2": 365}  # rule-4
DORMANT_DAYS = 365
P0_MIN_LIVE = 5

TIER_ORDER = ("P0", "P1", "P2", "P3")
LANES = (
    "full-audit+validate",
    "full-audit",
    "impact-lane",
    "iac-lane",
    "iac-baseline",
    "release-passthrough",
    "threat-model-review",
    "deps-lane",
    "diff-scan",
    "diff-scan-quarterly",
    "threat-model-quarterly",
    "none",
)

# --- threat-model re-model cadence (plan: progress-tracker/plans/
# threat-model-cadence-plan.md; owner decisions 2026-08-05) -----------
# Phase 1 rides the diff lanes as a report-only STAMP rather than its
# own lane: the diff dispatch has already cloned the repo and resolved
# the anchor, so `/threat-model pr` runs on that same clone at that
# same base. A separate lane would re-clone the same repo at the same
# SHA to answer a different question about the same diff.
_DIFF_LANES_TM = ("diff-scan", "diff-scan-quarterly")
# New-entry-point / trust-boundary proxy for the Phase-1 stamp.
# Deliberately DIRECTORY-ANCHORED: the cadence doc records that a broad
# infra matcher hit 90% of changed repos and was useless, so this one
# keys on interface-bearing directories and a short list of contract
# files instead of loose substrings. Re-derived quarterly with the rest
# of the router thresholds.
TM_SURFACE_RX = re.compile(
    r"(^|/)(cmd|api|apis|handler|handlers|route|routes|controller|"
    r"controllers|webhook|webhooks|middleware|admission|server|"
    r"endpoints?)(/|$)"
    r"|(^|/)main\.(go|py|rs|java|ts|js)$"
    r"|(^|/)(openapi|swagger)[^/]*\.(ya?ml|json)$"
    r"|\.proto$",
    re.I,
)
# Phase 2: only these release-bump kinds re-model. The feeder classifies
# (harnessing/2-threat-model/threat-model/scripts/build_release_events.py
#  REMODEL_CHANGES) — kept as a literal
# here so the router never depends on the feeder being importable.
RELEASE_REMODEL_CHANGES = ("major", "minor")
# Phase 3: calendar backstop for repos whose code is quiet but whose
# threat landscape isn't. Held in LOCKSTEP with check_drift.py's
# THREAT_MODEL_STALE_DAYS — the drift row is the dead-timer that fires
# only if this lane stops draining, so the two must not diverge.
THREAT_MODEL_QUARTERLY_DAYS = 92
THREAT_MODEL_DRAIN_WEEKS = 13  # spread the pool over one quarter
_TM_TAIL_BYTES = 8192  # provenance is section 7, near EOF
_TM_DATE_RX = re.compile(r"^-?\s*date:\s*(\d{4}-\d{2}-\d{2})", re.M)

# Exposure classes (cadence policy v1.4 §2.1b, wiring plan §6b —
# ground truth set by the operator 2026-07-27): a 2x2 of visibility x
# externality, EXTERNALITY DOMINANT. Tiers decide what TRIGGERS a scan,
# exposure decides how long a triggered scan may WAIT ("scan the most"
# -> "scan the least"):
#   public-external   product code made available to customers
#   private-external  tooling/services repos powering customer-facing
#                     services (private visibility, external impact)
#   public-internal   tools we use but do not productize
#   private-internal  internal tools that never reach customers
# A private repo forked from a public upstream counts as public on the
# visibility axis: the upstream code is attacker-readable and its vulns
# propagate on rebases/bumps.
EXPOSURE_ORDER = ("public-external", "private-external", "public-internal", "private-internal")
# "external" is a REPOSITORY EXPOSURE DESIGNATION — whether the
# repo's code reaches customers / externally-facing services. It is
# NOT the corpus ownership tag (external-bu = organizational, wrong
# signal). Designations are operator-curated in
# findings/_manifest/exposure-designations.json (--designations):
#   {"designations": [{"match": "<normalized url or prefix ending
#    with '/'>", "exposure": "external" | "internal-tooling",
#    "note": "..."}]}
# The router consumes read-only. Public visibility is a near-proxy
# for productization in this portfolio (products ship as open
# source), so PUBLIC DEFAULTS TO public-external; the explicit
# "internal-tooling" designation demotes to public-internal.
TIGHTENED_CEILING_DAYS = {"P0": 180, "P1": 180, "P2": 270}
DRAIN_TARGET_DAYS = 14  # public/external max days in the pool

DEFAULT_UNIT_COST_FULL = 29.04  # measured dual-pass unit (cost report v2)

# Tripwire (wiring plan §6c lever 1, v1: secrets-on-patch): gitleaks
# runs over the compare patch text of every below-threshold changed
# row — a hit escalates the row to an immediate diff-scan without any
# clone. KHS/opengrep tripwires need raw-file fetches or checkouts and
# land with the session-4 screener; manifest-only changes already reach
# osv via the deps lane (rule 3b), so a tripwire osv pass is redundant.
TRIPWIRE_PATCH_CAP = 2_000_000  # bytes of patch fed to the scanners
TRIPWIRE_QUOTA_RESERVE = 100  # keep headroom after patch fetches
# Secondary-ban circuit breaker: GitHub's anti-scraping bans are
# INVISIBLE to the rate_limit endpoint (measured 2026-07-28: quota
# read healthy while most stage-1 calls errored). A streak of
# consecutive GitHub errors this long means the run is banned, not
# unlucky — abort the sweep instead of churning failures (which
# prolongs the ban); remaining repos get status 'ban-suspected' and
# the next daily run retries.
BAN_STREAK_THRESHOLD = 50


def load_designations(path: Path) -> list[tuple[str, str]]:
    """Operator-curated exposure designations -> [(match, exposure)].
    Missing/invalid file -> empty (every repo then classifies from
    visibility/upstream alone). Read-only, like rescan-events."""
    try:
        raw = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError, ValueError):
        return []
    out = []
    for d in raw.get("designations") or []:
        m, e = d.get("match"), d.get("exposure")
        if m and e in ("external", "internal-tooling"):
            out.append((m, e))
    return out


def lookup_designation(url: str | None, designations: list[tuple[str, str]]) -> str | None:
    """Exact normalized-URL match, or prefix match for entries ending
    with '/' (org- or group-level designations). First match wins."""
    if not url:
        return None
    for match, exposure in designations:
        if url == match or (match.endswith("/") and url.startswith(match)):
            return exposure
    return None


def exposure_class(entry: dict) -> str:
    """Exposure class = visibility x externality, externality dominant
    (operator ground truth 2026-07-27). Externality axis = the curated
    repository exposure designation (does the code reach customers /
    externally-facing services) — NOT corpus ownership. Visibility
    axis = stage-1 visibility, with a public upstream elevating a
    private repo to effectively-public (the upstream is
    attacker-readable; vulns propagate on rebases/bumps). Public
    visibility defaults to public-external (public ~= productized in
    this portfolio) unless designated internal-tooling. Network-
    unreached repos classify from the designation alone and default
    private on the visibility axis."""
    designation = entry.get("designation")
    public_vis = (entry.get("visibility") or "").lower() == "public"
    upstream = bool(entry.get("fork") and entry.get("parent"))
    if public_vis:
        return "public-internal" if designation == "internal-tooling" else "public-external"
    if designation == "external":
        # upstream elevation moves the visibility axis
        return "public-external" if upstream else "private-external"
    if upstream:
        # private, undesignated, public upstream -> rank 3 (the
        # upstream default must NOT ride the public~=productized rule)
        return "public-internal"
    return "private-internal"


def parse_pinned_sha(commit_field: str | None) -> str | None:
    """metadata.commit is sometimes prose ('edb306fe… (main HEAD, …)');
    take the first hex run that looks like a SHA. (Copied from
    build_verify_sweep.py.)"""
    if not commit_field:
        return None
    m = SHA_RX.search(commit_field)
    return m.group(1) if m else None


# ---------------------------------------------------------------------------
# URL parsing / API-path safety
# ---------------------------------------------------------------------------


def split_repo_url(url: str | None) -> tuple[str | None, str | None, str | None]:
    """-> (kind, host, project_path). kind is 'github' | 'gitlab' | None
    (unsupported host). project_path is 'org/name' for GitHub, the full
    (possibly subgrouped) namespace path for GitLab."""
    m = re.match(r"^https://([^/]+)/(.+)$", url or "")
    if not m:
        return None, None, None
    host, path = m.group(1).lower(), m.group(2).strip("/")
    path = path.removesuffix(".git")
    kind = GIT_HOSTS.get(host)
    if kind == "github":
        parts = path.split("/")
        if len(parts) >= 2:
            return "github", host, "/".join(parts[:2])
        return None, host, None
    if kind == "gitlab":
        return "gitlab", host, path
    return None, host, None


def safe_project_path(path: str) -> bool:
    """Every path segment must match the strict identifier charset
    before it is interpolated / encoded into an API path."""
    segs = path.split("/")
    return bool(segs) and all(_GH_NAME_RE.fullmatch(s) for s in segs)


def gitlab_project_enc(path: str) -> str:
    """GitLab wants the full namespace path URL-encoded as ONE id:
    group/subgroup/repo -> group%2Fsubgroup%2Frepo."""
    return urllib.parse.quote(path, safe="")


# ---------------------------------------------------------------------------
# fetchers (all monkeypatchable in tests; API errors are per-repo data,
# never fatal)
# ---------------------------------------------------------------------------


def _classify_stderr(stderr: str) -> str:
    """Map a CLI failure to a per-repo status kind."""
    s = (stderr or "").lower()
    if "401" in s or "unauthorized" in s or "authentication" in s:
        return "no-credentials"
    if (
        "dial tcp" in s
        or "no such host" in s
        or "connection refused" in s
        or "i/o timeout" in s
        or "could not resolve" in s
        or "network is unreachable" in s
        or "tls handshake timeout" in s
    ):
        return "unreachable"
    return "error"


def gh_rate_remaining() -> int | None:
    """Remaining GitHub core-API quota, or None when undeterminable
    (gh missing/unauthenticated — stage 1 will surface that per-repo)."""
    try:
        proc = subprocess.run(
            ["gh", "api", "rate_limit", "--jq", ".resources.core.remaining"],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (subprocess.SubprocessError, OSError):
        return None
    if proc.returncode != 0:
        return None
    try:
        return int(proc.stdout.strip())
    except ValueError:
        return None


def gh_repo_info(project: str) -> dict:
    """Stage 1, GitHub: one `gh api` call -> pushed_at/archived/branch."""
    org, _, name = project.partition("/")
    if not (_GH_NAME_RE.fullmatch(org) and _GH_NAME_RE.fullmatch(name)):
        return {"ok": False, "kind": "error", "error": f"unsafe org/name: {project}"}
    try:
        proc = subprocess.run(
            [
                "gh",
                "api",
                f"repos/{org}/{name}",
                "--jq",
                "{pushed_at, archived, default_branch, visibility, "
                "fork, parent: .parent.full_name}",
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )
    except (subprocess.SubprocessError, OSError) as e:
        return {"ok": False, "kind": "unreachable", "error": str(e)[:120]}
    if proc.returncode != 0:
        return {
            "ok": False,
            "kind": _classify_stderr(proc.stderr),
            "error": proc.stderr.strip()[:120] or "api-error",
        }
    try:
        return {"ok": True, **json.loads(proc.stdout)}
    except json.JSONDecodeError:
        return {"ok": False, "kind": "error", "error": "unparseable"}


def gh_compare(project: str, sha: str) -> dict:
    """Stage 2, GitHub: pinned-SHA...HEAD compare, no clone needed."""
    org, _, name = project.partition("/")
    if not (
        _GH_NAME_RE.fullmatch(org)
        and _GH_NAME_RE.fullmatch(name)
        and re.fullmatch(r"[0-9a-f]{7,40}", sha)
    ):
        return {"ok": False, "kind": "error", "error": f"unsafe org/name/sha: {project}"}
    try:
        proc = subprocess.run(
            [
                "gh",
                "api",
                f"repos/{org}/{name}/compare/{sha}...HEAD",
                "--jq",
                "{ahead_by, status, files: [.files[] | {filename, changes}]}",
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )
    except (subprocess.SubprocessError, OSError) as e:
        return {"ok": False, "kind": "unreachable", "error": str(e)[:120]}
    if proc.returncode != 0:
        return {
            "ok": False,
            "kind": _classify_stderr(proc.stderr),
            "error": proc.stderr.strip()[:120] or "api-error",
        }
    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return {"ok": False, "kind": "error", "error": "unparseable"}
    files = payload.get("files") or []
    return {
        "ok": True,
        "ahead_by": int(payload.get("ahead_by") or 0),
        "files": files,
        "truncated": len(files) >= GH_COMPARE_FILE_CAP,
    }


_GH_REF_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]*$")


def gh_tree_fp_count(project: str, ref: str) -> dict:
    """Pre-route ratio input: count first-party files in the repo tree
    (one API call — the resolver counts the same population via
    `git ls-files` in its clone). `truncated: true` means the tree
    exceeded the API's 100k-entry cap; a repo that large cannot hit the
    30% ratio with a <=300-file compare, so callers skip the check."""
    org, _, name = project.partition("/")
    if not (_GH_NAME_RE.fullmatch(org) and _GH_NAME_RE.fullmatch(name)):
        return {"ok": False, "error": f"unsafe org/name: {project}"}
    if not _GH_REF_RE.fullmatch(ref or "") or ".." in ref:
        ref = "HEAD"
    try:
        proc = subprocess.run(
            [
                "gh",
                "api",
                f"repos/{org}/{name}/git/trees/{ref}?recursive=1",
                "--jq",
                '{truncated, paths: [.tree[] | select(.type=="blob") | .path]}',
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )
    except (subprocess.SubprocessError, OSError) as e:
        return {"ok": False, "error": str(e)[:120]}
    if proc.returncode != 0:
        return {"ok": False, "error": proc.stderr.strip()[:120] or "api-error"}
    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return {"ok": False, "error": "unparseable"}
    fp = sum(1 for p in payload.get("paths") or [] if is_first_party(p))
    return {"ok": True, "fp_files": fp, "truncated": bool(payload.get("truncated"))}


def _glab_api(host: str, request_path: str) -> dict:
    """One `glab api` call. Token stays in glab's auth store /
    GITLAB_TOKEN env — never in argv (rule S5 class)."""
    if shutil.which("glab") is None:
        return {
            "ok": False,
            "kind": "no-credentials",
            "error": "glab CLI not installed (and no GitLab transport without it)",
        }
    try:
        proc = subprocess.run(
            ["glab", "api", "--hostname", host, request_path],
            capture_output=True,
            text=True,
            timeout=120,
        )
    except (subprocess.SubprocessError, OSError) as e:
        return {"ok": False, "kind": "unreachable", "error": str(e)[:120]}
    if proc.returncode != 0:
        return {
            "ok": False,
            "kind": _classify_stderr(proc.stderr),
            "error": proc.stderr.strip()[:120] or "api-error",
        }
    try:
        return {"ok": True, "payload": json.loads(proc.stdout)}
    except json.JSONDecodeError:
        return {"ok": False, "kind": "error", "error": "unparseable"}


def gitlab_repo_info(host: str, project: str) -> dict:
    """Stage 1, GitLab: GET /projects/:enc — last_activity_at plays the
    pushed_at role."""
    if not safe_project_path(project):
        return {"ok": False, "kind": "error", "error": f"unsafe project path: {project}"}
    res = _glab_api(host, f"projects/{gitlab_project_enc(project)}")
    if not res.get("ok"):
        return res
    p = res["payload"]
    fork_parent = (p.get("forked_from_project") or {}).get("path_with_namespace")
    return {
        "ok": True,
        "pushed_at": p.get("last_activity_at"),
        "archived": bool(p.get("archived")),
        "default_branch": p.get("default_branch"),
        "visibility": p.get("visibility"),
        "fork": bool(fork_parent),
        "parent": fork_parent,
    }


def count_diff_lines(diff_text: str) -> int:
    """Changed-line count from one GitLab diff hunk text: lines starting
    with a single +/- (the '+++'/'---' file headers and '@@' hunk
    headers are skipped)."""
    n = 0
    for line in (diff_text or "").splitlines():
        if line.startswith(("+++", "---")):
            continue
        if line.startswith(("+", "-")):
            n += 1
    return n


def gitlab_compare(host: str, project: str, sha: str, default_branch: str) -> dict:
    """Stage 2, GitLab: /repository/compare?from=<sha>&to=<branch>.
    Normalized to the GitHub shape: {ahead_by, files:[{filename,
    changes}], truncated}."""
    if not (safe_project_path(project) and re.fullmatch(r"[0-9a-f]{7,40}", sha)):
        return {"ok": False, "kind": "error", "error": f"unsafe project path/sha: {project}"}
    to_ref = urllib.parse.quote(default_branch or "HEAD", safe="")
    res = _glab_api(
        host, f"projects/{gitlab_project_enc(project)}/repository/compare?from={sha}&to={to_ref}"
    )
    if not res.get("ok"):
        return res
    p = res["payload"]
    diffs = p.get("diffs") or []
    files = [
        {
            "filename": d.get("new_path") or d.get("old_path") or "",
            "changes": count_diff_lines(d.get("diff") or ""),
        }
        for d in diffs
    ]
    patch = "\n".join(d.get("diff") or "" for d in diffs)
    return {
        "ok": True,
        "ahead_by": len(p.get("commits") or []),
        "files": files,
        "patch": patch[:TRIPWIRE_PATCH_CAP],
        "truncated": (bool(p.get("compare_timeout")) or len(diffs) >= GITLAB_DIFF_CAP),
    }


# ---------------------------------------------------------------------------
# rule-1 bootstrap (lever 1d): never-audited inventory repos
# ---------------------------------------------------------------------------


def never_audited_rows(
    graph_db: Path, baselined: set[str], designations: list[tuple[str, str]]
) -> list[dict]:
    """Cadence rule 1, implemented (lever 1d, operator directive
    2026-07-28): the inventory population — portfolio-graph repo nodes,
    built from the inputs inventory (the topology authority;
    /drift-watch polices spine freshness) — diffed against the audited
    baselines. Repos with no baseline get a full-audit+bootstrap row so
    a newly ingested repo becomes a routed audit obligation on the next
    daily run instead of waiting for a human to notice. Zero API calls
    (GitHub fleet-sweep ban avoidance): visibility is unknown here, so
    the exposure axis uses the curated designation only and defaults
    private — fail-toward-standard; the bootstrap audit establishes
    everything else (baseline, graph edges, change detection)."""
    if not graph_db.is_file():
        return []
    con = sqlite3.connect(f"file:{graph_db}?mode=ro", uri=True)
    try:
        node_ids = [r[0] for r in con.execute("SELECT id FROM nodes WHERE id LIKE 'repo:%'")]
    finally:
        con.close()
    rows = []
    for rid in node_ids:
        url = normalize_repo_url(f"https://{rid[5:]}")
        if not url or url in baselined:
            continue
        designation = lookup_designation(url, designations)
        exposure = "private-external" if designation == "external" else "private-internal"
        rows.append(
            {
                "repo_key": url,
                "repo_url": url,
                "tier": "P2",
                "lane": "full-audit",
                "rule": "rule-1-bootstrap",
                "reason": (
                    "rule-1: never audited — inventory repo without "
                    "a baseline; full audit + threat-model bootstrap "
                    "(self-heals into change detection, the graph, "
                    "and dependency watch)"
                ),
                "status": "never-audited",
                "C": None,
                "S_lines": None,
                "deps_only": None,
                "ahead_by": None,
                "truncated": None,
                "audit_age_days": None,
                "exposure": exposure,
                "changed_days": None,
                "error": None,
            }
        )
    rows.sort(key=lambda d: (EXPOSURE_ORDER.index(d["exposure"]), d["repo_url"]))
    return rows


# ---------------------------------------------------------------------------
# tripwire (lever 1 v1: gitleaks over patch text — no clone, no verdict)
# ---------------------------------------------------------------------------


def gh_compare_patch(project: str, sha: str) -> str | None:
    """Raw unified diff of pinned-SHA...HEAD (one core-quota call). None
    on any failure — the tripwire is opportunistic, never fatal."""
    org, _, name = project.partition("/")
    if not (
        _GH_NAME_RE.fullmatch(org)
        and _GH_NAME_RE.fullmatch(name)
        and re.fullmatch(r"[0-9a-f]{7,40}", sha)
    ):
        return None
    try:
        # bytes, not text: real-world diffs carry arbitrary encodings
        # (observed live: a 28MB patch with invalid UTF-8 crashed the
        # text-mode pipe); decode tolerantly after capping
        proc = subprocess.run(
            [
                "gh",
                "api",
                "-H",
                "Accept: application/vnd.github.v3.diff",
                f"repos/{org}/{name}/compare/{sha}...HEAD",
            ],
            capture_output=True,
            timeout=120,
        )
    except (subprocess.SubprocessError, OSError):
        return None
    if proc.returncode != 0 or not proc.stdout:
        return None
    return proc.stdout[:TRIPWIRE_PATCH_CAP].decode("utf-8", "replace")


def gitleaks_hits(patch: str) -> int | None:
    """Leak count from `gitleaks stdin` over patch text. None = scanner
    unavailable or errored (recorded, never escalates)."""
    if not patch or shutil.which("gitleaks") is None:
        return None
    with tempfile.TemporaryDirectory(prefix="rescan-tripwire-") as td:
        report = Path(td) / "report.json"
        try:
            subprocess.run(
                [
                    "gitleaks",
                    "stdin",
                    "--no-banner",
                    "--exit-code",
                    "0",
                    "--report-format",
                    "json",
                    "--report-path",
                    str(report),
                ],
                input=patch.encode("utf-8", "replace"),
                capture_output=True,
                timeout=300,
            )
            if not report.is_file():
                return None
            leaks = json.loads(report.read_text() or "[]")
            return len(leaks) if isinstance(leaks, list) else None
        except (subprocess.SubprocessError, OSError, json.JSONDecodeError, ValueError):
            return None


def run_tripwire(
    rows: list[dict], by_key: dict, jobs: int, gh_patch=None, leak_scan=None, rate_remaining=None
) -> dict:
    """Lever-1 escalation pass over below-threshold routed rows: any
    gitleaks hit in the change's patch upgrades the row to an immediate
    diff-scan (rule 'tripwire'). Routes only — the diff scan
    adjudicates. Quota-aware for the GitHub patch fetches; GitLab
    patches were captured in stage 2 for free. Returns counters for the
    population block."""
    gh_patch = gh_patch or gh_compare_patch
    leak_scan = leak_scan or gitleaks_hits
    rate_remaining = rate_remaining or gh_rate_remaining
    eligible = [
        r
        for r in rows
        if r["lane"] in ("deps-lane", "diff-scan-quarterly") and (r.get("C") or 0) > 0
    ]
    stats = {
        "eligible": len(eligible),
        "escalated": 0,
        "quota_skipped": 0,
        "scanner_unavailable": 0,
    }
    if not eligible:
        return stats
    if shutil.which("gitleaks") is None:
        stats["scanner_unavailable"] = len(eligible)
        return stats

    gh_rows = [r for r in eligible if by_key[r["repo_key"]].get("host_kind") == "github"]
    rem = rate_remaining()
    gh_budget = max(0, rem - TRIPWIRE_QUOTA_RESERVE) if rem is not None else len(gh_rows)
    if gh_budget < len(gh_rows):
        stats["quota_skipped"] = len(gh_rows) - gh_budget
    gh_allowed = set(id(r) for r in gh_rows[:gh_budget])

    def work(row: dict) -> None:
        e = by_key[row["repo_key"]]
        if e.get("host_kind") == "github":
            if id(row) not in gh_allowed:
                return
            patch = gh_patch(e["project"], e["pinned_sha"])
        else:
            patch = e.get("_patch")
        hits = leak_scan(patch) if patch else None
        if hits:
            row["lane"] = "diff-scan"
            row["rule"] = "tripwire"
            row["reason"] = (
                f"tripwire: {hits} gitleaks hit(s) in the "
                f"change patch — escalated to immediate "
                f"diff-scan (was {row['reason']})"
            )
            row["tripwire"] = {"gitleaks": hits}

    with concurrent.futures.ThreadPoolExecutor(max_workers=jobs) as ex:
        list(ex.map(work, eligible))
    stats["escalated"] = sum(1 for r in eligible if r.get("tripwire"))
    return stats


_DIFF_LANES = ("diff-scan", "diff-scan-quarterly")


def _preroute_row(row: dict, why: str) -> None:
    row["lane"] = "full-audit"
    row["rule"] = f"{row['rule']}+preroute"
    row["reason"] = f"preroute: {why} (was {row['reason']})"


def run_preroute(
    rows: list[dict], by_key: dict, jobs: int, tree_count=None, rate_remaining=None
) -> dict:
    """Refusal pre-route (diff-lane cost fix, 2026-07-27): apply the
    diff resolver's refusal predicates at routing time, so rows that
    would clone-then-refuse at dispatch (32% of the pilot — each
    refusal still costs a run) go straight to full-audit instead.

      leg 1  compare `truncated` -> C/file counts are undercounts; the
             resolver's clone-side numbers would exceed a refusal
             threshold. No API cost.
      leg 2  changed-file ratio: the resolver refuses when >30% of
             first-party files changed. One GitHub tree call per
             candidate row (quota-aware); GitLab rows are skipped
             honestly — no cheap tree count over glab.

    Routes only — the resolver stays the authority at dispatch."""
    tree_count = tree_count or gh_tree_fp_count
    rate_remaining = rate_remaining or gh_rate_remaining
    stats = {
        "eligible": 0,
        "rerouted_truncated": 0,
        "rerouted_ratio": 0,
        "checked_ratio": 0,
        "quota_skipped": 0,
        "gitlab_unchecked": 0,
        "tree_failed": 0,
        "scoped_out": 0,
    }
    for r in rows:
        if r["lane"] in _DIFF_LANES and r.get("truncated"):
            _preroute_row(
                r, "compare truncated — churn is an undercount; the diff resolver would refuse"
            )
            stats["rerouted_truncated"] += 1

    cands = [
        r
        for r in rows
        if r["lane"] in _DIFF_LANES
        and (by_key[r["repo_key"]].get("fp_files") or 0) >= PREROUTE_MIN_FILES
    ]
    # scope the quota-costing ratio check to dispatch-imminent rows:
    # every immediate diff-scan, plus the quarterly rows inside the
    # next PREROUTE_HORIZON_WEEKS of weekly drain (same risk sort the
    # drain uses) — deeper pool rows are checked as they surface
    quarterly = [r for r in cands if r["lane"] == "diff-scan-quarterly"]
    pool_size = sum(1 for r in rows if r["lane"] == "diff-scan-quarterly")
    horizon = PREROUTE_HORIZON_WEEKS * max(1, -(-pool_size // 13))
    quarterly.sort(
        key=lambda d: (
            EXPOSURE_ORDER.index(d.get("exposure") or "private-internal"),
            TIER_ORDER.index(d.get("tier") or "P3"),
            -(d.get("S_lines") or 0),
            -(d.get("C") or 0),
        )
    )
    imminent = set(id(r) for r in quarterly[:horizon])
    stats["scoped_out"] = len(quarterly) - min(len(quarterly), horizon)
    cands = [r for r in cands if r["lane"] == "diff-scan" or id(r) in imminent]
    stats["eligible"] = len(cands)
    gh_rows = [r for r in cands if by_key[r["repo_key"]].get("host_kind") == "github"]
    stats["gitlab_unchecked"] = len(cands) - len(gh_rows)
    if not gh_rows:
        return stats
    rem = rate_remaining()
    budget = max(0, rem - PREROUTE_QUOTA_RESERVE) if rem is not None else len(gh_rows)
    if budget < len(gh_rows):
        stats["quota_skipped"] = len(gh_rows) - budget
    allowed = gh_rows[:budget]

    def work(row: dict) -> None:
        e = by_key[row["repo_key"]]
        res = tree_count(e["project"], e.get("default_branch") or "HEAD")
        if not res.get("ok"):
            # leave the row (resolver decides at dispatch) but COUNT it
            # — tranche-1's silent failures hid a mid-sweep quota
            # exhaustion behind checked_ratio=466 / 0 hits
            row["preroute_tree_error"] = (res.get("error") or "?")[:120]
            return
        if res.get("truncated"):
            return  # tree >100k entries can't hit 30% on a capped diff
        total = res["fp_files"]
        changed = e.get("fp_files") or 0
        if total and changed / total > MAX_CHANGED_FILE_RATIO:
            _preroute_row(
                row,
                f"{changed}/{total} ({changed / total:.0%}) of "
                f"first-party files changed — the diff resolver "
                f"refuses above {MAX_CHANGED_FILE_RATIO:.0%}",
            )
            row["preroute"] = {
                "changed_first_party_files": changed,
                "total_first_party_files": total,
            }

    with concurrent.futures.ThreadPoolExecutor(max_workers=jobs) as ex:
        list(ex.map(work, allowed))
    stats["tree_failed"] = sum(1 for r in allowed if r.get("preroute_tree_error"))
    stats["checked_ratio"] = len(allowed) - stats["tree_failed"]
    stats["rerouted_ratio"] = sum(1 for r in allowed if r.get("preroute"))
    return stats


# ---------------------------------------------------------------------------
# change metrics (pure — the unit-testable core of stage 2)
# ---------------------------------------------------------------------------


def is_first_party(path: str) -> bool:
    parts = path.split("/")
    if any(p in _EXCLUDE_DIR_PARTS for p in parts):
        return False
    if any("_generated" in p for p in parts):
        return False
    name = parts[-1]
    return not (name.endswith(".pb.go") or name.lower().endswith(".md"))


def is_deps_manifest(path: str) -> bool:
    name = path.rsplit("/", 1)[-1]
    if name in DEPS_MANIFESTS:
        return True
    return name.startswith("requirements") and name.endswith(".txt")


# iac-lane detection (router-lane-coverage-plan §3, lever 6): the
# /cloud-config-audit lane owns what secure-code-audit's KHS arm does
# NOT cover — Terraform / CloudFormation(dir-based; *.template.yaml is
# an OpenShift Template in this portfolio) / ARM+Bicep. Patterns mirror
# traust.ops.build_iac_inventory (the Phase-0 census).
IAC_RX = re.compile(
    r"\.tf$|\.tfvars$|\.tf\.json$"
    r"|(^|/)(cloudformation|cfn)/[^ ]*\.(ya?ml|json)$"
    r"|\.bicep$|(^|/)azuredeploy[^/]*\.json$"
)


def change_metrics(files: list[dict]) -> dict:
    """files: [{filename, changes}] -> {C, S, S_lines, deps_only,
    fp_files, iac_files, tm_files}. C, S, fp_files, iac_files and
    tm_files are computed over first-party files only; deps_only over
    ALL changed files (strict: every single file is a manifest)."""
    C, S_lines, sensitive, fp_files, iac_files = 0, 0, False, 0, 0
    tm_files = 0
    deps_only = bool(files)
    for f in files:
        path = f.get("filename") or ""
        changes = int(f.get("changes") or 0)
        if not is_deps_manifest(path):
            deps_only = False
        if not is_first_party(path):
            continue
        C += changes
        fp_files += 1
        if SENSITIVE_RX.search(path):
            sensitive = True
            S_lines += changes
        if IAC_RX.search(path):
            iac_files += 1
        if TM_SURFACE_RX.search(path):
            tm_files += 1
    return {
        "C": C,
        "S": sensitive,
        "S_lines": S_lines,
        "deps_only": deps_only,
        "fp_files": fp_files,
        "iac_files": iac_files,
        "tm_files": tm_files,
    }


# ---------------------------------------------------------------------------
# threat-model cadence (plan Phases 1-3) — provenance reading + lanes
# ---------------------------------------------------------------------------


def threat_model_path(report_path: str | None) -> Path | None:
    """The HEAD threat model companion to a baseline audit report, or
    None. Models sit beside the report they scope
    (`<repo>-security-audit.json` -> `<repo>-threat-model.md`, the
    /threat-model placement contract). Branch-suffixed portfolio copies
    (`<repo>__release-4.22-threat-model.md`) are deliberately excluded:
    this lane is about the HEAD model the audits actually consume."""
    if not report_path:
        return None
    p = Path(report_path)
    base = p.name
    for suffix in ("-security-audit.json", "-security-audit.md", ".json"):
        if base.endswith(suffix):
            base = base[: -len(suffix)]
            break
    cand = p.parent / f"{base}-threat-model.md"
    if cand.is_file():
        return cand
    try:
        loose = sorted(m for m in p.parent.glob("*-threat-model.md") if "__" not in m.name)
    except OSError:
        return None
    return loose[0] if len(loose) == 1 else None


def read_model_date(path: Path) -> _dt.date | None:
    """Provenance `date:` from section 7. Tail-read first (the section
    sits near EOF and the corpus is ~7.7k files — a full read of every
    model costs ~46s per router run); falls back to a full read when the
    heading is not in the tail, so an unusual layout still parses."""
    try:
        size = path.stat().st_size
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            if size > _TM_TAIL_BYTES:
                fh.seek(size - _TM_TAIL_BYTES)
            text = fh.read()
        if "## 7. Provenance" not in text:
            text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    prov = text.split("## 7. Provenance", 1)
    m = _TM_DATE_RX.search(prov[1] if len(prov) > 1 else text)
    if not m:
        return None
    try:
        return _dt.date.fromisoformat(m.group(1))
    except ValueError:
        return None


def load_threat_model_ages(entries: list[dict], today: _dt.date) -> dict:
    """Stamps e['tm_path'], e['tm_date'], e['tm_age_days'] in place.
    -> {read, undated, missing} counts for the summary. Deterministic
    and local — no API calls, no clones."""
    stats = {"read": 0, "undated": 0, "missing": 0}
    for e in entries:
        path = threat_model_path(e.get("report_path"))
        e["tm_path"] = str(path) if path else None
        e["tm_date"] = e["tm_age_days"] = None
        if path is None:
            stats["missing"] += 1
            continue
        d = read_model_date(path)
        if d is None:
            stats["undated"] += 1
            continue
        stats["read"] += 1
        e["tm_date"] = d.isoformat()
        e["tm_age_days"] = (today - d).days
    return stats


def stamp_threat_model_pr(rows: list[dict], by_key: dict) -> dict:
    """Phase 1 (report-only, owner decision 2026-08-05). A diff-lane row
    whose change touched a trust boundary (the router's own sensitive
    matcher) or an interface-bearing path (TM_SURFACE_RX) carries a
    `threat_model_pr` stamp: the dispatcher runs `/threat-model pr` on
    the clone it already has, at the anchor it already resolved. Report
    only — `pr` writes no model and re-stamps no SHA; promoting to an
    auto-applied `update` is a separate decision after a calibration
    window."""
    stats = {"eligible": 0, "stamped": 0, "no_model": 0}
    for row in rows:
        if row.get("lane") not in _DIFF_LANES_TM:
            continue
        stats["eligible"] += 1
        e = by_key.get(row["repo_key"])
        if not e:
            continue
        sensitive = bool(e.get("S"))
        tm_files = int(e.get("tm_files") or 0)
        if not sensitive and not tm_files:
            continue
        if not e.get("tm_path"):
            # No model to assess the diff against — the gap is real but
            # bootstrapping one is a full-audit-sized job, not a diff
            # companion. Counted, never silently stamped.
            stats["no_model"] += 1
            continue
        why = []
        if sensitive:
            why.append("sensitive-identifier path")
        if tm_files:
            why.append(f"{tm_files} interface-bearing file(s)")
        row["threat_model_pr"] = {
            "mode": "report-only",
            "model": e["tm_path"],
            "reason": (
                "diff touches " + " + ".join(why) + " — assess the diff for new entry points / "
                "trust boundaries against the existing model"
            ),
        }
        stats["stamped"] += 1
    return stats


def threat_model_quarterly_rows(entries: list[dict], already: set, stale_days: int) -> list[dict]:
    """Phase 3 (calendar backstop). Phases 1-2 only fire on change, so a
    repo whose code is quiet but whose threat landscape moved would
    never be re-modelled. One additive row per repo whose HEAD model is
    older than `stale_days`, excluding repos already getting a
    threat-model action this run."""
    out = []
    for e in entries:
        age = e.get("tm_age_days")
        if age is None or age < stale_days or not e.get("tm_path"):
            continue
        if e.get("repo_url") in already:
            continue
        out.append(
            {
                "repo_key": e["repo_key"],
                "repo_url": e["repo_url"],
                "tier": None,
                "lane": "threat-model-quarterly",
                "rule": "threat-model-3",
                "reason": (
                    f"threat-model calendar backstop: model is "
                    f"{age}d old (>{stale_days}d) and no change-"
                    f"triggered re-model fired — /threat-model "
                    f"review --auto"
                ),
                "status": e.get("status"),
                "C": e.get("C"),
                "S_lines": e.get("S_lines"),
                "deps_only": e.get("deps_only"),
                "ahead_by": e.get("ahead_by"),
                "truncated": e.get("truncated"),
                "audit_age_days": e.get("audit_age_days"),
                "exposure": e.get("exposure"),
                "threat_model": e.get("tm_path"),
                "threat_model_age_days": age,
            }
        )
    return out


def cloud_config_baseline_urls(db_path) -> set:
    """Normalized repo URLs that already carry a /cloud-config-audit
    baseline (findings.db projection, report_kind='cloud-config') —
    decides iac-lane (diff the baseline) vs iac-baseline (create one)."""
    import sqlite3

    try:
        con = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        rows = con.execute("SELECT repo_url FROM repos WHERE report_kind='cloud-config'").fetchall()
        con.close()
    except Exception:
        return set()
    urls = set()
    for (raw,) in rows:
        norm = normalize_repo_url(raw)
        if norm:
            urls.add(norm)
    return urls


def iac_rows(entries: list[dict], cc_urls: set) -> list[dict]:
    """lever 6 (router-lane-coverage-plan §3): ADDITIVE rows — an IaC
    change rides alongside whatever lane the decision table picked (a
    full-audit does not run Checkov's TF/CFN/Bicep policies, so routing
    one lane would silently drop the other). One extra row per repo
    whose stage-2 diff touched IaC files."""
    out = []
    for e in entries:
        if e.get("status") != "ok" or not e.get("iac_files"):
            continue
        has_baseline = e.get("repo_url") in cc_urls
        out.append(
            {
                "repo_key": e["repo_key"],
                "repo_url": e["repo_url"],
                "tier": None,
                "lane": ("iac-lane" if has_baseline else "iac-baseline"),
                "rule": "lever-6",
                "reason": (
                    f"iac: {e['iac_files']} IaC file(s) changed — "
                    + (
                        "re-run /cloud-config-audit against the existing baseline"
                        if has_baseline
                        else "no cloud-config baseline yet — full /cloud-config-audit creates one"
                    )
                ),
                "status": e["status"],
                "C": e.get("C"),
                "S_lines": e.get("S_lines"),
                "deps_only": e.get("deps_only"),
                "ahead_by": e.get("ahead_by"),
                "truncated": e.get("truncated"),
                "audit_age_days": e.get("audit_age_days"),
                "exposure": e.get("exposure"),
                "iac_files": e.get("iac_files"),
            }
        )
    return out


def companion_rows(entries: list[dict], cc_urls: set, already_routed: set) -> list[dict]:
    """lever-6 companion backfill (router-lane-coverage-plan §4): the
    audit-side declaration half of lever 6. secure-code-audit's tree
    survey stamps metadata.additional.companion_lanes:
    ["cloud-config-audit"] when the checkout carries IaC the code audit
    does not assess (Terraform/CFN/ARM+Bicep). A repo whose latest
    code-audit report carries that stamp, has NO cloud-config baseline,
    and is not already getting an iac row this run gets an ADDITIVE
    iac-baseline row — the stamp doubles as backfill discovery for
    repos the Phase-0 IaC census missed (no stage-2 diff needed: the
    IaC is already sitting unassessed in the tree)."""
    out = []
    for e in entries:
        if "cloud-config-audit" not in (e.get("companion_lanes") or []):
            continue
        if e.get("repo_url") is None or e["repo_url"] in cc_urls or e["repo_url"] in already_routed:
            continue
        out.append(
            {
                "repo_key": e["repo_key"],
                "repo_url": e["repo_url"],
                "tier": None,
                "lane": "iac-baseline",
                "rule": "lever-6-companion",
                "reason": (
                    "companion: latest code-audit report stamps "
                    "metadata.additional.companion_lanes="
                    "['cloud-config-audit'] and no cloud-config "
                    "baseline exists — full /cloud-config-audit "
                    "creates one"
                ),
                "status": e.get("status"),
                "C": e.get("C"),
                "S_lines": e.get("S_lines"),
                "deps_only": e.get("deps_only"),
                "ahead_by": e.get("ahead_by"),
                "truncated": e.get("truncated"),
                "audit_age_days": e.get("audit_age_days"),
                "exposure": e.get("exposure"),
                "iac_files": e.get("iac_files"),
            }
        )
    return out


# ---------------------------------------------------------------------------
# decision table (rescan-cadence plan v1.3 §2.3) — data, first match wins
# ---------------------------------------------------------------------------


def _rule3_lane(ctx: dict) -> str:
    return "full-audit" if ctx["tier"] in ("P0", "P1") else "diff-scan"


def _over_ceiling(ctx: dict) -> bool:
    # the external band (customer-facing impact) tightens the ceiling
    # one notch (P1 270->180d, P2 365->270d; P0 already tightest) —
    # policy v1.4, externality-dominant 2x2
    table = (
        TIGHTENED_CEILING_DAYS
        if ctx.get("exposure") in ("public-external", "private-external")
        else TIER_CEILING_DAYS
    )
    ceiling = table.get(ctx["tier"])
    age = ctx.get("audit_age_days")
    return ceiling is not None and age is not None and age > ceiling


# (rule id, predicate, lane-resolver, reason). Rule 1 (event injection)
# runs ahead of this table in main(), by design.
DECISION_TABLE: tuple = (
    (
        "rule-2",
        lambda c: (
            (c.get("R") is not None and c["R"] >= CHURN_FULL_RATIO) or c["C"] >= CHURN_FULL_LINES
        ),
        lambda c: "full-audit",
        "coverage-map churn (R>=10% or C>=8000 first-party lines)",
    ),
    (
        "rule-3",
        lambda c: c["S"] and c["S_lines"] >= SENSITIVE_MIN_LINES,
        _rule3_lane,
        "sensitive-identifier files changed, >=200 lines",
    ),
    (
        "rule-3b",
        lambda c: c["deps_only"],
        lambda c: "deps-lane",
        "dependency manifests only (deterministic osv/impact lane)",
    ),
    (
        "rule-4",
        _over_ceiling,
        lambda c: "full-audit",
        "audit age over tier ceiling (P0 180d / P1 270d / P2 365d)",
    ),
    (
        "rule-5",
        lambda c: c["C"] > 0,
        lambda c: "diff-scan-quarterly",
        "below-threshold change (accumulates for the quarterly batch)",
    ),
    (
        "rule-6",
        lambda c: c.get("changed") and c.get("ahead_by") == 0,
        lambda c: "none",
        "pushed_at moved but 0 commits ahead (tag/branch noise)",
    ),
    (
        "rule-7",
        lambda c: True,
        lambda c: "none",
        "no qualifying change (dormant repos re-enter on push)",
    ),
)


def decide(ctx: dict) -> tuple[str, str, str]:
    """-> (rule_id, lane, reason). ctx needs tier, C, S, S_lines,
    deps_only, audit_age_days; optional R, changed, ahead_by."""
    for rule_id, pred, lane_fn, reason in DECISION_TABLE:
        if pred(ctx):
            return rule_id, lane_fn(ctx), f"{rule_id}: {reason}"
    raise AssertionError("rule-7 is a catch-all")  # pragma: no cover


def risk_tier(live_crit_high: int, archived: bool, dormant: bool) -> str:
    """Live risk outranks dormancy: an archived repo with live
    crit/highs still needs assurance."""
    if live_crit_high >= P0_MIN_LIVE:
        return "P0"
    if live_crit_high >= 1:
        return "P1"
    if archived or dormant:
        return "P3"
    return "P2"


# ---------------------------------------------------------------------------
# event injection (rule 1) — read-only over rescan-events.jsonl
# ---------------------------------------------------------------------------

EVENT_SOURCES = ("external-report", "methodology", "cve", "release")


def load_events(path: Path) -> list[dict]:
    """Unconsumed events from the JSONL file; absent file -> []."""
    if not path.is_file():
        return []
    events = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not ev.get("consumed") and ev.get("source") in EVENT_SOURCES:
            events.append(ev)
    return events


def event_lane(source: str, tier: str | None) -> str | None:
    """Lane for an event row; None = honored but not queued (recorded
    in events_honored either way)."""
    if source == "external-report":
        return "full-audit+validate"
    if source == "methodology":
        # P0 re-audits within a week; P1+ catch up via the rule-4 ceiling
        return "full-audit" if tier == "P0" else None
    if source == "cve":
        return "impact-lane"
    if source == "release":
        return "release-passthrough"
    return None


# ---------------------------------------------------------------------------
# findings.db loading
# ---------------------------------------------------------------------------

_LIVE_SQL = """
SELECT repo_key, COUNT(*) FROM findings
WHERE severity IN ('critical','high')
  AND (validity IS NULL OR validity = '' OR validity NOT IN
       ('false_positive','withdrawn','refuted','hardening'))
  AND (resolution IS NULL OR resolution = '' OR resolution NOT IN
       ('resolved','risk_accepted'))
GROUP BY repo_key
"""

_REPOS_SQL = """
SELECT repo_key, repo_url, report_path, audit_date, product, tree,
       ownership
FROM repos WHERE report_kind = 'code-audit' AND is_branch_audit = 0
"""


def _report_meta(report_path: str | None) -> tuple[str | None, int | None, list[str]]:
    """-> (pinned_sha, lines_reviewed, companion_lanes). lines_reviewed
    is optional and only inconsistently present in metadata.additional
    (plan §4). companion_lanes is the audit-side declaration stamped by
    secure-code-audit's tree survey (router-lane-coverage-plan §4) —
    lane names for content the code audit saw but does not assess."""
    if not report_path:
        return None, None, []
    try:
        meta = json.loads(Path(report_path).read_text(encoding="utf-8")).get("metadata") or {}
    except (OSError, json.JSONDecodeError):
        return None, None, []
    add = meta.get("additional") or {}
    loc = None
    for key in ("lines_reviewed", "loc_reviewed", "lines_of_code"):
        v = add.get(key)
        if isinstance(v, (int, float)) and v > 0:
            loc = int(v)
            break
    lanes = add.get("companion_lanes")
    companions = [s for s in lanes if isinstance(s, str)] if isinstance(lanes, list) else []
    return parse_pinned_sha(meta.get("commit")), loc, companions


def load_population(db_path: Path) -> list[dict]:
    """HEAD code-audit rows, deduped by normalized URL (freshest audit
    wins; live risk = max over sibling filings so multi-product
    duplicates never double-count the same finding)."""
    con = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        live = dict(con.execute(_LIVE_SQL).fetchall())
        rows = con.execute(_REPOS_SQL).fetchall()
    finally:
        con.close()
    by_url: dict[str, dict] = {}
    no_url: list[dict] = []
    for repo_key, repo_url, report_path, audit_date, product, tree, ownership in rows:
        url = normalize_repo_url(repo_url)
        rec = {
            "repo_key": repo_key,
            "repo_url": url,
            "report_path": report_path,
            "audit_date": audit_date,
            "product": product,
            "tree": tree,
            "ownership": ownership,
            # filled from _report_meta(report_path) in main —
            # the audit-side companion-lane declaration rides the
            # deduped record so the lever-6 companion backfill can
            # read it without re-opening the report
            "companion_lanes": [],
            "live_crit_high": int(live.get(repo_key, 0)),
        }
        if url is None:
            rec["sibling_repo_keys"] = []
            no_url.append(rec)
            continue
        prev = by_url.get(url)
        if prev is None:
            rec["sibling_repo_keys"] = []
            by_url[url] = rec
        else:
            # freshest audit anchors the row; risk is the max across
            # sibling filings of the same repo
            prev["live_crit_high"] = max(prev["live_crit_high"], rec["live_crit_high"])
            if (rec["audit_date"] or "") > (prev["audit_date"] or ""):
                rec["live_crit_high"] = prev["live_crit_high"]
                rec["sibling_repo_keys"] = prev["sibling_repo_keys"] + [prev["repo_key"]]
                by_url[url] = rec
            else:
                prev["sibling_repo_keys"].append(repo_key)
    return sorted(by_url.values(), key=lambda r: r["repo_url"]) + no_url


# ---------------------------------------------------------------------------
# budget guard (advisory — Layer-1 posture of $TRAUST_CONFIG_HOME/budget-policy.yaml)
# ---------------------------------------------------------------------------

_FULL_LANES = ("full-audit", "full-audit+validate")


# budget-policy.yaml `enforcement` values under which a policy ceiling
# actually binds a router run. `none` is the shipped posture (the policy
# is a documented artifact, not a control — see the plan's design
# principle: "a config that documents its own non-enforcement is honest;
# one that implies enforcement it lacks is a vulnerability").
_POLICY_GATING_MODES = ("advisory", "enforced")
# `observe` (Phase 1, 2026-08-05) computes a verdict and records it but
# NEVER withholds work, so it is deliberately absent from the gating
# set above: read_policy_budget() reports it as a non-binding ceiling
# and the drop path physically cannot see it. The shadow accounting
# reads it through read_policy_shadow_ceiling() instead.
_POLICY_OBSERVE_MODE = "observe"
# Pre-2026-08 flat key names. The live policy has never used them — this
# reader looked ONLY here and so silently found nothing for months (see
# the docstring). Kept as a fallback so an external deployment carrying
# the flat shape is not newly broken.
_LEGACY_BUDGET_KEYS = ("monthly_usd", "monthly_budget_usd", "per_month_usd")


def read_policy_budget(path: Path | None) -> tuple[float | None, str]:
    """Monthly USD ceiling from budget-policy.yaml -> (ceiling, why).

    `why` is always populated and is surfaced in the worklist as
    `summary.budget_source`, because the failure this function shipped
    with was INVISIBLE: it looked for a flat `monthly_usd` key, the
    policy nests the figure at `budget_policy.monthly_budget.usd_central`,
    so it returned None on every run and the worklist reported
    `budget_usd: null` as if no budget had ever been configured. Silence
    is not an acceptable outcome for a spend control — every path here
    explains itself.

    Two rules, in order:

    1. **`enforcement` decides whether a ceiling binds at all.** The
       shipped posture is `none`: the policy is documentation, and only
       `--monthly-budget` gates a run. Fixing the key lookup must NOT
       quietly switch on a guillotine nobody enabled — measured
       2026-08-05, the live worklist projected just under the configured
       ceiling, so activation would have begun
       dropping full audits within one ordinary run. L1 advisory
       enforcement is Phase 3 of
       progress-tracker/plans/budget-policy-implementation-plan.md.
    2. **Then read the nested figure**, falling back to the legacy flat
       keys. A policy that asks to gate but carries no readable ceiling
       is a loud warning, never a silent no-op.

    `enforced` is legal only on the central platform (L4), never in a
    user checkout. Encountering it here warns and still applies the
    ceiling — honoring a stricter-than-asked intent is safer than
    ignoring it, but the caller is told the enforcement is only
    advisory-strength because the client cannot self-enforce.
    """
    if path is None or not path.is_file():
        return None, "no budget-policy.yaml in $TRAUST_CONFIG_HOME"
    try:
        import yaml
    except ImportError:
        return None, "PyYAML unavailable — budget policy not read"
    try:
        pol = (yaml.safe_load(path.read_text(encoding="utf-8")) or {}).get("budget_policy") or {}
    except Exception:
        print(f"[!] unparseable {path} — no policy ceiling applied", file=sys.stderr)
        return None, "unparseable budget policy"
    if not pol:
        return None, "budget policy has no budget_policy block"

    mode = str(pol.get("enforcement") or "none").strip().lower()
    if mode == _POLICY_OBSERVE_MODE:
        return None, (
            "policy enforcement=observe — shadow accounting "
            "only; the verdict is recorded and NOTHING is "
            "withheld (budget-guard plan Phase 1)"
        )
    if mode not in _POLICY_GATING_MODES:
        why = (
            f"policy enforcement={mode} — ceiling not applied "
            f"(L1 advisory enforcement is Phase 3 of the "
            f"budget-policy plan); only --monthly-budget binds"
        )
        if mode != "none":
            print(
                f"[!] unrecognized budget-policy enforcement '{mode}' — treating as 'none'",
                file=sys.stderr,
            )
            why = (
                f"policy enforcement='{mode}' is not a recognized "
                f"mode — treated as none, ceiling not applied"
            )
        return None, why

    ceiling, found_at = None, ""
    mb = pol.get("monthly_budget")
    if isinstance(mb, dict):
        v = mb.get("usd_central")
        if isinstance(v, (int, float)) and not isinstance(v, bool) and v > 0:
            ceiling, found_at = float(v), "monthly_budget.usd_central"
    if ceiling is None:
        for key in _LEGACY_BUDGET_KEYS:
            v = pol.get(key)
            if isinstance(v, (int, float)) and not isinstance(v, bool) and v > 0:
                ceiling, found_at = float(v), f"legacy flat key `{key}`"
                break
    if ceiling is None:
        # The exact shape of the original bug — asked to gate, found no
        # number. Never degrade to "no budget configured" in silence.
        print(
            f"[!] budget policy sets enforcement={mode} but carries no "
            f"readable monthly ceiling (expected "
            f"budget_policy.monthly_budget.usd_central) — NO ceiling "
            f"applied; fix the policy or pass --monthly-budget",
            file=sys.stderr,
        )
        return None, (
            f"policy enforcement={mode} but no readable "
            f"monthly_budget.usd_central — ceiling MISSING"
        )
    if mode == "enforced":
        print(
            f"[!] budget policy sets enforcement=enforced, which is "
            f"valid only on the central platform (L4) — a user "
            f"checkout cannot self-enforce. Applying ${ceiling:,.0f} "
            f"as an advisory ceiling.",
            file=sys.stderr,
        )
        return ceiling, (
            f"policy {found_at} (enforcement=enforced is "
            f"platform-only; applied advisory-strength here)"
        )
    return ceiling, f"policy {found_at} (enforcement={mode})"


def read_policy_shadow_ceiling(path: Path) -> tuple[float | None, str]:
    """The ceiling for OBSERVE-mode shadow accounting only.

    Separate entry point on purpose. read_policy_budget() is the drop
    path's reader and reports `observe` as no ceiling, so no future
    edit there can accidentally start withholding work under a mode
    whose entire contract is that it withholds nothing. This reader is
    the only way to see an observe ceiling, and its caller
    (traust.cli.budget_shadow) cannot filter a work list.
    """
    if not path.is_file():
        return None, f"no budget policy at {path}"
    try:
        import yaml
    except ImportError:
        return None, "PyYAML unavailable — budget policy not read"
    try:
        pol = (yaml.safe_load(path.read_text(encoding="utf-8")) or {}).get("budget_policy") or {}
    except Exception:
        return None, "unparseable budget policy"
    mode = str(pol.get("enforcement") or "none").strip().lower()
    if mode != _POLICY_OBSERVE_MODE:
        return None, f"policy enforcement={mode} — not observe mode"
    mb = pol.get("monthly_budget")
    v = mb.get("usd_central") if isinstance(mb, dict) else None
    if isinstance(v, (int, float)) and not isinstance(v, bool) and v > 0:
        return float(v), "policy monthly_budget.usd_central (observe)"
    return None, (
        "policy enforcement=observe but no readable monthly_budget.usd_central — ceiling MISSING"
    )


def apply_budget(
    decisions: list[dict], unit_cost: float, budget: float | None
) -> tuple[list[dict], list[dict]]:
    """Drop lowest-tier table-routed fulls until the projection fits;
    event-injected rows are never dropped. -> (kept, dropped)."""
    if budget is None:
        return decisions, []
    fulls = [d for d in decisions if d["lane"] in _FULL_LANES]
    projected = len(fulls) * unit_cost
    if projected <= budget:
        return decisions, []
    droppable = sorted(
        (d for d in fulls if not d.get("event_source")),
        key=lambda d: (-TIER_ORDER.index(d.get("tier") or "P3"), d.get("C") or 0),
    )
    dropped = []
    while projected > budget and droppable:
        d = droppable.pop(0)
        dropped.append(d)
        projected -= unit_cost
    dropped_ids = {id(d) for d in dropped}
    kept = [d for d in decisions if id(d) not in dropped_ids]
    for d in dropped:
        d["dropped_reason"] = (
            f"budget: projected full-audit cost exceeded {budget:.2f} USD at {unit_cost:.2f}/run"
        )
    return kept, dropped


# ---------------------------------------------------------------------------
# rendering
# ---------------------------------------------------------------------------


def render_md(doc: dict) -> str:
    pop = doc["population"]
    lines = [
        "# Rescan worklist — continuous-operations router",
        "",
        f"Generated {doc['generated_at']} · harness "
        f"{doc['harness_version']} · network "
        f"{'ON' if doc['network'] else 'OFF'} · routes only, never "
        f"authors a verdict (docs/continuous-operations.md)",
        "",
        f"Population: {pop['total']} HEAD code-audit rows -> "
        f"{pop['evaluated']} unique repos evaluated · "
        f"{pop['stage1_candidates']} stage-1 candidates · "
        f"{pop['errors']} API errors · "
        f"{pop['unsupported_host']} unsupported-host · "
        f"{pop['no_credentials']} no-credentials · "
        f"{pop['unreachable']} unreachable",
        "",
    ]
    if pop.get("statuses", {}).get("ban-suspected"):
        lines += [
            f"**RUN ABORTED MID-SWEEP: "
            f"{pop['statuses']['ban-suspected']} repo(s) skipped after a "
            f"{BAN_STREAK_THRESHOLD}-consecutive-error streak — GitHub "
            f"secondary ban suspected** (invisible to the rate_limit "
            f"endpoint). This worklist is INCOMPLETE for change "
            f"detection; do not dispatch change lanes from it. Cool "
            f"down and let the next daily run retry.",
            "",
        ]
    if pop.get("never_audited"):
        lines += [
            f"**{pop['never_audited']} never-audited inventory repo(s)** "
            f"routed to full-audit+bootstrap (rule 1 / lever 1d) — new "
            f"intake becomes an audit obligation automatically; the "
            f"first audit self-heals each repo into change detection, "
            f"the graph, and dependency watch.",
            "",
        ]
    if pop.get("statuses", {}).get("quota-deferred"):
        lines += [
            f"**{pop['statuses']['quota-deferred']} changed repo(s) "
            f"quota-deferred** — their stage-2 compares did not fit this "
            f"hour's GitHub API quota; the next daily run classifies "
            f"them.",
            "",
        ]
    if pop["evaluated"] and pop["errors"] / pop["evaluated"] > 0.05:
        lines += [
            f"**WARNING: {pop['errors']}/{pop['evaluated']} repos "
            f"errored (>5%)** — likely GitHub API rate limiting; treat "
            f"this worklist as INCOMPLETE and re-run after the hourly "
            f"quota reset (per-row `error` fields carry the API "
            f"messages).",
            "",
        ]
    if pop.get("gitlab_unreachable"):
        lines += [
            f"**WARNING: {pop['gitlab_unreachable']} GitLab repo(s) were "
            f"unreachable or errored** (counted under the unreachable/API-"
            f"error totals above) — a private forge may be VPN-gated, so this run "
            f"is INCOMPLETE for the GitLab slice, not clean.",
            "",
        ]
    lines += ["| Lane | Rows |", "|---|---:|"]
    for lane in LANES:
        lines.append(f"| {lane} | {doc['summary']['lanes'].get(lane, 0)} |")
    if doc["events_honored"]:
        lines += [
            "",
            f"Events honored: {len(doc['events_honored'])} "
            f"(the router consumes nothing — mark records "
            f"consumed after dispatch)",
        ]
    if doc["dropped_for_budget"]:
        lines += [
            "",
            f"**{len(doc['dropped_for_budget'])} full-audit "
            f"row(s) dropped for budget** — listed in "
            f"`dropped_for_budget` in the JSON, no silent "
            f"truncation.",
        ]
    bsrc = doc["summary"].get("budget_source")
    if bsrc:
        bud = doc["summary"].get("budget_usd")
        proj = doc["summary"].get("projected_full_audit_cost_usd")
        if bud is None:
            line = (
                f"Budget: **no ceiling applied** — {bsrc}. Projected full-audit cost ${proj:,.2f}."
            )
            if "MISSING" in bsrc:
                line = (
                    "**BUDGET CEILING MISSING** — the policy asks to "
                    f"gate but carries no readable figure ({bsrc}). "
                    f"Projected full-audit cost ${proj:,.2f} is "
                    f"UNGATED."
                )
        else:
            line = (
                f"Budget: ${bud:,.2f} ceiling from {bsrc}; projected "
                f"full-audit cost ${proj:,.2f} "
                f"({proj / bud * 100:.0f}% of ceiling)."
            )
        lines += ["", line]
    smry = doc["summary"]
    exp = smry.get("exposure") or {}
    if exp:
        lines += [
            "",
            "Exposure: " + " · ".join(f"{cls} {exp.get(cls, 0)}" for cls in EXPOSURE_ORDER),
        ]
    tw = smry.get("tripwire") or {}
    if tw.get("disabled"):
        lines += ["", "Tripwire: disabled this run."]
    elif tw.get("scanner_unavailable"):
        lines += [
            "",
            f"**Tripwire skipped: gitleaks not installed** "
            f"({tw['scanner_unavailable']} eligible rows "
            f"unswept).",
        ]
    elif tw.get("eligible"):
        lines += [
            "",
            f"Tripwire (gitleaks-on-patch): "
            f"{tw.get('escalated', 0)} of "
            f"{tw['eligible']} below-threshold rows escalated "
            f"to immediate diff-scan"
            + (
                f"; {tw['quota_skipped']} skipped for quota (next run retries)"
                if tw.get("quota_skipped")
                else ""
            )
            + ".",
        ]
    tm = smry.get("threat_model") or {}
    if tm.get("disabled"):
        lines += ["", "Threat-model lanes: disabled this run."]
    elif tm:
        lines += [
            "",
            f"Threat model: {tm.get('models_read', 0)} model(s) "
            f"read · {tm.get('pr_stamped', 0)} of "
            f"{tm.get('pr_eligible_rows', 0)} diff row(s) "
            f"stamped for `/threat-model pr` (report-only) · "
            f"{tm.get('review_rows', 0)} release review row(s) "
            f"· quarterly pool {tm.get('quarterly_pool', 0)} at "
            f"{tm.get('quarterly_weekly_rate', 0)}/week "
            f"(>{tm.get('stale_days')}d).",
        ]
        gaps = []
        if tm.get("repos_without_model"):
            gaps.append(
                f"{tm['repos_without_model']} audited repo(s) "
                f"have NO threat model (not routed — a bootstrap "
                f"is full-audit-sized work, tracked in the "
                f"cadence plan)"
            )
        if tm.get("pr_skipped_no_model"):
            gaps.append(
                f"{tm['pr_skipped_no_model']} diff row(s) "
                f"qualified for a pr assessment but have no "
                f"model to assess against"
            )
        if tm.get("undated"):
            gaps.append(
                f"{tm['undated']} model(s) carry no parseable "
                f"provenance date (invisible to the backstop)"
            )
        rc = tm.get("release_changes") or {}
        skipped = {k: v for k, v in rc.items() if k not in RELEASE_REMODEL_CHANGES}
        if skipped:
            gaps.append(
                "release events not re-modelled (major/minor "
                "only): " + ", ".join(f"{k} {v}" for k, v in sorted(skipped.items()))
            )
        if gaps:
            lines += ["", "**Threat-model coverage gaps:** " + "; ".join(gaps) + "."]
    pr = smry.get("preroute") or {}
    if pr.get("disabled"):
        lines += ["", "Refusal pre-route: disabled this run."]
    elif pr.get("rerouted_truncated") or pr.get("rerouted_ratio") or pr.get("eligible"):
        lines += [
            "",
            f"Refusal pre-route: "
            f"{pr.get('rerouted_truncated', 0)} truncated-"
            f"compare + {pr.get('rerouted_ratio', 0)} "
            f"file-ratio row(s) re-routed to full-audit "
            f"({pr.get('checked_ratio', 0)} of "
            f"{pr.get('eligible', 0)} eligible rows "
            f"tree-checked"
            + (f"; {pr['quota_skipped']} skipped for quota" if pr.get("quota_skipped") else "")
            + (
                f"; **{pr['tree_failed']} tree fetch(es) "
                f"FAILED** — those rows are unverified, the "
                f"resolver adjudicates at dispatch"
                if pr.get("tree_failed")
                else ""
            )
            + (
                f"; {pr['scoped_out']} deep-pool rows beyond "
                f"the {PREROUTE_HORIZON_WEEKS}-week horizon "
                f"(checked as they approach dispatch)"
                if pr.get("scoped_out")
                else ""
            )
            + (
                f"; {pr['gitlab_unchecked']} GitLab rows unchecked — the resolver adjudicates those"
                if pr.get("gitlab_unchecked")
                else ""
            )
            + ").",
        ]
    dr = smry.get("drain") or {}
    if dr.get("pool"):
        lines += [
            "",
            "## Quarterly-pool trickle (lever 2)",
            "",
            f"Pool {dr['pool']} rows; this week's drain = "
            f"`drain_order < {dr['weekly_rate']}` "
            f"(risk-ordered: exposure → tier → S_lines → C).",
        ]
        if dr.get("overdue_public_external"):
            lines += [
                "",
                f"**{dr['overdue_public_external']} "
                f"public/external row(s) changed more than "
                f"{DRAIN_TARGET_DAYS} days ago and are still "
                f"undrained** — dispatch them this week.",
            ]
    fulls = [d for d in doc["decisions"] if d["lane"] in _FULL_LANES]
    lines += [
        "",
        "## Top full-audit rows (first 20)",
        "",
        "| Tier | Repo | Lane | Reason | C | S_lines | Age (d) |",
        "|---|---|---|---|---:|---:|---:|",
    ]
    fulls.sort(key=lambda d: (TIER_ORDER.index(d.get("tier") or "P3"), -(d.get("C") or 0)))
    for d in fulls[:20]:
        lines.append(
            f"| {d.get('tier') or '?'} | {d['repo_url'] or d['repo_key']} "
            f"| {d['lane']} | {d['reason']} | {d.get('C') or 0} "
            f"| {d.get('S_lines') or 0} | {d.get('audit_age_days') or '?'} |"
        )
    lines.append("")
    return "\n".join(lines)


def harness_version() -> str | None:
    try:
        v = (HARNESS_ROOT / "VERSION").read_text().strip()
        sha = subprocess.run(
            ["git", "-C", str(HARNESS_ROOT), "rev-parse", "--short", "HEAD"],
            capture_output=True,
            text=True,
            timeout=15,
            check=True,
        ).stdout.strip()
        return f"{v}-{sha}"
    except (OSError, subprocess.SubprocessError):
        return None


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------


def _parse_date(s: str | None) -> _dt.date | None:
    if not s:
        return None
    try:
        return _dt.date.fromisoformat(s.strip()[:10])
    except ValueError:
        return None


class _BanBreaker:
    """Consecutive-GitHub-error circuit breaker shared across workers.
    Thread-tolerant by design: exact counts don't matter, only that a
    long streak trips it and any success resets it."""

    def __init__(self, threshold: int | None = None):
        # late-bound: read the module global at instantiation so tests
        # (and future config) can adjust it
        self.threshold = threshold if threshold is not None else BAN_STREAK_THRESHOLD
        self.streak = 0
        self.tripped = False

    def record(self, ok: bool) -> None:
        if ok:
            self.streak = 0
        else:
            self.streak += 1
            if self.streak >= self.threshold:
                self.tripped = True


def stage1(entries: list[dict], jobs: int, gh_info=None, gl_info=None) -> None:
    """Fleet refresh: annotate each entry with pushed_at/archived/
    default_branch or a status kind. Mutates entries in place.
    Fetchers resolve at call time (module globals) so tests can
    monkeypatch gh_repo_info / gitlab_repo_info directly."""
    gh_info = gh_info or gh_repo_info
    gl_info = gl_info or gitlab_repo_info

    breaker = _BanBreaker()

    def work(e: dict) -> None:
        kind, host, project = split_repo_url(e["repo_url"])
        e["host_kind"], e["host"], e["project"] = kind, host, project
        if e["repo_url"] is None:
            e["status"] = "no-repo-url"
            return
        if kind is None:
            e["status"] = "unsupported-host"
            return
        if kind == "github" and breaker.tripped:
            e["status"] = "ban-suspected"
            e["error"] = (
                "skipped: consecutive-error streak suggests a "
                "GitHub secondary ban (rate_limit is blind to "
                "these); next daily run retries"
            )
            return
        info = gh_info(project) if kind == "github" else gl_info(host, project)
        if kind == "github":
            breaker.record(info.get("ok", False))
        if not info.get("ok"):
            e["status"] = info.get("kind", "error")
            e["error"] = info.get("error")
            return
        e["status"] = "ok"
        e["pushed_at"] = info.get("pushed_at")
        e["archived"] = bool(info.get("archived"))
        e["default_branch"] = info.get("default_branch")
        e["visibility"] = info.get("visibility")
        e["fork"] = bool(info.get("fork"))
        e["parent"] = info.get("parent")

    with concurrent.futures.ThreadPoolExecutor(max_workers=jobs) as ex:
        list(ex.map(work, entries))


def stage2(candidates: list[dict], jobs: int, gh_cmp=None, gl_cmp=None) -> None:
    """Per-candidate compare -> change metrics. Mutates in place.

    Quota-aware: GitHub candidates beyond the remaining core quota are
    marked `quota-deferred` instead of burned as errors — they stay
    stage-1 candidates and the next daily run classifies them (GitLab
    candidates use glab's separate quota and are never deferred)."""
    gh_cmp = gh_cmp or gh_compare
    gl_cmp = gl_cmp or gitlab_compare

    rem = gh_rate_remaining()
    deferred: set[int] = set()
    if rem is not None:
        gh_cands = [
            i
            for i, e in enumerate(candidates)
            if e["host_kind"] == "github" and e.get("pinned_sha")
        ]
        if rem < len(gh_cands):
            for i in gh_cands[max(0, rem) :]:
                deferred.add(i)
            print(
                f"[!] stage 2: quota fits {rem}/{len(gh_cands)} GitHub "
                f"compares — {len(deferred)} deferred to the next run",
                file=sys.stderr,
            )

    def work(item: tuple[int, dict]) -> None:
        idx, e = item
        if not e.get("pinned_sha"):
            e["status"] = "no-pinned-sha"
            return
        if idx in deferred:
            e["status"] = "quota-deferred"
            return
        if e["host_kind"] == "github":
            res = gh_cmp(e["project"], e["pinned_sha"])
        else:
            res = gl_cmp(
                e["host"], e["project"], e["pinned_sha"], e.get("default_branch") or "HEAD"
            )
        if not res.get("ok"):
            e["status"] = res.get("kind", "error")
            e["error"] = res.get("error")
            return
        e["ahead_by"] = res["ahead_by"]
        e["truncated"] = res["truncated"]
        if res.get("patch"):
            e["_patch"] = res["patch"]  # tripwire input (GitLab)
        e.update(change_metrics(res["files"]))

    with concurrent.futures.ThreadPoolExecutor(max_workers=jobs) as ex:
        list(ex.map(work, enumerate(candidates)))


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    add_config_home_arg(ap)
    ap.add_argument(
        "--db", type=Path, default=None, help="findings.db projection (build_findings_db.py)"
    )
    ap.add_argument(
        "--events", type=Path, default=None, help="event-injection JSONL (optional; read-only)"
    )
    ap.add_argument("--out", type=Path, default=None, help="output JSON (.md written beside it)")
    ap.add_argument(
        "--no-network",
        action="store_true",
        help="skip both gh/glab stages — decisions fall to the age-ceiling rule only",
    )
    ap.add_argument(
        "--designations",
        type=Path,
        default=None,
        help="operator-curated repository exposure "
        "designations (external / internal-tooling); "
        "read-only, optional",
    )
    ap.add_argument(
        "--graph-db",
        type=Path,
        default=None,
        help="portfolio graph spine for rule-1 never-audited "
        "bootstrap (built from the inputs inventory; "
        "freshness policed by /drift-watch). Default: "
        "portfolio-graph.db beside --db",
    )
    ap.add_argument(
        "--no-bootstrap", action="store_true", help="skip rule-1 never-audited inventory rows"
    )
    ap.add_argument(
        "--no-tripwire",
        action="store_true",
        help="skip the lever-1 gitleaks-on-patch tripwire pass over below-threshold changed rows",
    )
    ap.add_argument(
        "--no-preroute",
        action="store_true",
        help="skip the refusal pre-route pass (truncated "
        "compares + >30%% changed-file ratio -> "
        "full-audit instead of a doomed diff dispatch)",
    )
    ap.add_argument(
        "--drain-rate",
        type=int,
        default=None,
        help="weekly trickle size for the quarterly pool "
        "(default: ceil(pool/13) — one quarter at "
        "weekly cadence)",
    )
    ap.add_argument(
        "--no-threat-model",
        action="store_true",
        help="skip the threat-model re-model lanes "
        "(Phase 1 pr stamp, Phase 2 release review, "
        "Phase 3 quarterly backstop)",
    )
    ap.add_argument(
        "--threat-model-stale-days",
        type=int,
        default=THREAT_MODEL_QUARTERLY_DAYS,
        help="calendar backstop threshold for the "
        "threat-model-quarterly lane (default 92; keep "
        "in lockstep with check_drift.py's "
        "THREAT_MODEL_STALE_DAYS)",
    )
    ap.add_argument(
        "--threat-model-drain-rate",
        type=int,
        default=None,
        help="weekly trickle size for the threat-model "
        "quarterly pool (default: ceil(pool/13) — one "
        "quarter at weekly cadence)",
    )
    ap.add_argument(
        "--ignore-rate-limit",
        action="store_true",
        help="proceed even when the GitHub API quota is too "
        "low for a complete run (worklist will be "
        "visibly incomplete)",
    )
    ap.add_argument("--jobs", type=int, default=12, help="worker threads for the API stages")
    ap.add_argument(
        "--limit", type=int, default=None, help="evaluate only the first N repos (testing)"
    )
    ap.add_argument(
        "--unit-cost-full",
        type=float,
        default=DEFAULT_UNIT_COST_FULL,
        help="measured USD per dual-pass full audit",
    )
    ap.add_argument(
        "--monthly-budget",
        type=float,
        default=None,
        help="advisory USD ceiling; excess lowest-tier fulls are dropped AND listed",
    )
    args = ap.parse_args(argv)

    engine = load_engine(args.config_home)
    results_root = analysis_results_dir(engine)
    manifest = results_root / "findings" / "_manifest"
    args.db = args.db or results_root / "graph" / "findings.db"
    args.events = args.events or manifest / "rescan-events.jsonl"
    args.out = args.out or manifest / "rescan-worklist.json"
    args.designations = args.designations or manifest / "exposure-designations.json"

    if not args.db.is_file():
        print(
            f"findings.db not found: {args.db} — run `traust corpus findings-db` first",
            file=sys.stderr,
        )
        return 2

    entries = load_population(args.db)
    total_rows = sum(1 + len(e["sibling_repo_keys"]) for e in entries)
    if args.limit:
        entries = entries[: args.limit]
    print(f"[+] {len(entries)} unique repos ({total_rows} HEAD code-audit rows)", file=sys.stderr)

    today = _dt.date.today()
    for e in entries:
        (e["pinned_sha"], e["lines_reviewed"], e["companion_lanes"]) = _report_meta(
            e["report_path"]
        )
        d = _parse_date(e["audit_date"])
        e["audit_age_days"] = (today - d).days if d else None

    network = not args.no_network
    if network:
        # Guard stage 1 only: a full fleet needs ~1 call/repo for stage 1
        # plus ~0.45/repo for stage 2 — together that brushes the 5K/hr
        # quota, so stage 2 is quota-aware (defers what does not fit to
        # the next daily run) rather than preflighted. A quota-starved
        # stage 1 silently classifies thousands of repos as errors while
        # the worklist looks legitimate (observed live: well over half
        # of one sweep's calls errored) — refuse that outright.
        gh_needed = int(
            1.05 * sum(1 for e in entries if split_repo_url(e["repo_url"])[0] == "github")
        )
        quota = gh_rate_remaining()
        if quota is not None and quota < gh_needed and not args.ignore_rate_limit:
            print(
                f"[!] GitHub API quota too low for stage 1: {quota} "
                f"remaining, ~{gh_needed} needed. Re-run after the "
                f"hourly reset or pass --ignore-rate-limit to proceed "
                f"anyway (the worklist will be visibly incomplete).",
                file=sys.stderr,
            )
            return 4
        print(
            f"[+] stage 1: fleet refresh over {len(entries)} repos ({args.jobs} workers) …",
            file=sys.stderr,
        )
        stage1(entries, args.jobs)
    else:
        for e in entries:
            kind, host, project = split_repo_url(e["repo_url"])
            e["host_kind"], e["host"], e["project"] = kind, host, project
            if e["repo_url"] is None:
                e["status"] = "no-repo-url"
            elif kind is None:
                e["status"] = "unsupported-host"
            else:
                e["status"] = "network-skipped"

    candidates = []
    for e in entries:
        pushed = _parse_date(e.get("pushed_at"))
        audited = _parse_date(e.get("audit_date"))
        # >= is the fail-safe day-granularity reading of "pushed_at >
        # audit_date": stage-2 zero-diff resolves same-day noise
        e["changed"] = bool(pushed and audited and pushed >= audited)
        e["dormant"] = bool(pushed and (today - pushed).days > DORMANT_DAYS)
        if e["status"] == "ok" and e["changed"]:
            candidates.append(e)
    if network and candidates:
        print(f"[+] stage 2: compare over {len(candidates)} candidates …", file=sys.stderr)
        stage2(candidates, args.jobs)

    # --- decisions -------------------------------------------------------
    events = load_events(args.events)
    designations = load_designations(args.designations)
    # Exposure is resolved for EVERY entry up front (not just the
    # table-routed ones) so event rows and the additive threat-model
    # rows carry it too — it is the primary intra-lane sort key.
    for e in entries:
        e["designation"] = lookup_designation(e["repo_url"], designations)
        e["exposure"] = exposure_class(e)
    if args.no_threat_model:
        tm_stats = {"read": 0, "undated": 0, "missing": 0, "disabled": True}
    else:
        tm_stats = load_threat_model_ages(entries, today)
    by_url = {e["repo_url"]: e for e in entries if e["repo_url"]}
    by_key = {}
    for e in entries:
        by_key[e["repo_key"]] = e
        for k in e["sibling_repo_keys"]:
            by_key[k] = e
    event_rows, events_honored, event_urls = [], [], set()
    # Phase 2 (owner decision 2026-08-05): a release re-models only on a
    # MAJOR/MINOR bump. The feeder stamps `release_change` from the
    # inventory path's version; patch/backfill/initial/unknown (which
    # includes the whole dist-git leg — a commit sha is not a release)
    # are honored as passthrough rows and counted, never re-modelled.
    tm_review_rows, tm_review_urls = [], set()
    tm_release_seen: dict[str, int] = {}
    for ev in events:
        ref = ev.get("repo") or ""
        target = by_url.get(normalize_repo_url(ref)) or by_key.get(ref)
        tier = None
        if target:
            tier = risk_tier(
                target["live_crit_high"],
                target.get("archived", False),
                target.get("dormant", False),
            )
        lane = event_lane(ev.get("source", ""), tier)
        honored = {
            "source": ev.get("source"),
            "repo": ref,
            "date": ev.get("date"),
            "note": ev.get("note"),
            "queued": bool(lane and target),
        }
        if ev.get("source") == "release":
            change = ev.get("release_change") or "unknown"
            honored["release_change"] = change
            honored["release_version"] = ev.get("release_version")
            tm_release_seen[change] = tm_release_seen.get(change, 0) + 1
            if (
                change in RELEASE_REMODEL_CHANGES
                and target
                and not args.no_threat_model
                and target["repo_url"] not in tm_review_urls
            ):
                tm_review_urls.add(target["repo_url"])
                tm_path = target.get("tm_path")
                tm_review_rows.append(
                    {
                        "repo_key": target["repo_key"],
                        "repo_url": target["repo_url"],
                        "tier": tier,
                        "lane": "threat-model-review",
                        "rule": "threat-model-2",
                        "reason": (
                            f"release {ev.get('release_version') or '?'} is a "
                            f"{change} bump over "
                            f"{ev.get('release_previous') or '?'} — "
                            + (
                                "/threat-model review --auto against the existing model"
                                if tm_path
                                else "no HEAD model exists yet: /threat-model bootstrap"
                            )
                        ),
                        "status": target.get("status"),
                        "C": target.get("C"),
                        "S_lines": target.get("S_lines"),
                        "deps_only": target.get("deps_only"),
                        "ahead_by": target.get("ahead_by"),
                        "truncated": target.get("truncated"),
                        "audit_age_days": target.get("audit_age_days"),
                        "exposure": target.get("exposure"),
                        "event_source": "release",
                        "event_note": ev.get("note"),
                        "release_version": ev.get("release_version"),
                        "release_change": change,
                        "threat_model": tm_path,
                        "threat_model_age_days": target.get("tm_age_days"),
                    }
                )
        if not target:
            honored["disposition"] = (
                "repo not in the HEAD code-audit population — dispatch manually"
            )
        elif lane is None:
            honored["disposition"] = (
                "honored, not queued (methodology "
                "events queue P0 only; P1+ catch "
                "up via the rule-4 ceiling)"
            )
        else:
            reason = f"event:{ev['source']}"
            if ev.get("source") == "release":
                reason += (
                    " — passthrough: route to the branch/container/rpm audit lane, not this table"
                )
            event_rows.append(
                {
                    "repo_key": target["repo_key"],
                    "repo_url": target["repo_url"],
                    "tier": tier,
                    "lane": lane,
                    "rule": "rule-1",
                    "reason": reason,
                    "status": target["status"],
                    "C": target.get("C"),
                    "S_lines": target.get("S_lines"),
                    "deps_only": target.get("deps_only"),
                    "ahead_by": target.get("ahead_by"),
                    "truncated": target.get("truncated"),
                    "audit_age_days": target.get("audit_age_days"),
                    "event_source": ev.get("source"),
                    "event_note": ev.get("note"),
                }
            )
            event_urls.add(target["repo_url"])
        events_honored.append(honored)

    table_rows = []
    for e in entries:
        if e["repo_url"] in event_urls:
            continue  # the event row supersedes the table for this repo
        tier = risk_tier(e["live_crit_high"], e.get("archived", False), e.get("dormant", False))
        pushed = _parse_date(e.get("pushed_at"))
        changed_days = (today - pushed).days if pushed else None
        loc = e.get("lines_reviewed")
        ctx = {
            "tier": tier,
            "exposure": e["exposure"],
            "C": e.get("C", 0),
            "S": e.get("S", False),
            "S_lines": e.get("S_lines", 0),
            "deps_only": e.get("deps_only", False),
            "audit_age_days": e.get("audit_age_days"),
            "changed": e.get("changed", False),
            "ahead_by": e.get("ahead_by"),
            "R": (e.get("C", 0) / loc) if loc else None,
        }
        if e["status"] == "quota-deferred":
            # Changed, but the compare did not fit this hour's API
            # quota — an honest "not classified yet", never a lane. The
            # repo stays a stage-1 candidate; the next daily run
            # classifies it.
            rule, lane = "quota-deferred", "none"
            reason = "quota-deferred: changed, stage-2 compare deferred to the next run (API quota)"
        elif e["status"] == "no-pinned-sha":
            # Converter-era reports carry no recoverable anchor SHA, so
            # stage 2 can never run and rules 2/3/5/6 can never fire —
            # without this branch such repos are invisible to change
            # detection forever. Fail-safe: any stage-1 push signal ->
            # full audit (the new report stamps metadata.commit, so the
            # repo self-heals out of this class); otherwise wait.
            if ctx["changed"]:
                rule, lane = "no-pinned-sha", "full-audit"
                reason = (
                    "no-pinned-sha: changed since audit but churn "
                    "unmeasurable — full audit re-establishes the "
                    "anchor (self-healing)"
                )
            else:
                rule, lane = "no-pinned-sha", "none"
                reason = "no-pinned-sha: no push signal; anchor is re-established at the next audit"
        else:
            rule, lane, reason = decide(ctx)
        table_rows.append(
            {
                "repo_key": e["repo_key"],
                "repo_url": e["repo_url"],
                "tier": tier,
                "lane": lane,
                "rule": rule,
                "reason": reason,
                "status": e["status"],
                "C": e.get("C"),
                "S_lines": e.get("S_lines"),
                "deps_only": e.get("deps_only"),
                "ahead_by": e.get("ahead_by"),
                "truncated": e.get("truncated"),
                "audit_age_days": e.get("audit_age_days"),
                "exposure": e["exposure"],
                "changed_days": changed_days if e.get("changed") else None,
                "error": e.get("error"),
            }
        )

    # lever 6: additive iac-lane rows (IaC files changed -> the
    # cloud-config lane runs REGARDLESS of what the table picked)
    cc_urls = cloud_config_baseline_urls(args.db)
    non_event = [e for e in entries if e["repo_url"] not in event_urls]
    lever6_rows = iac_rows(non_event, cc_urls)
    table_rows.extend(lever6_rows)
    # lever-6 companion backfill: companion_lanes stamp with no
    # cloud-config baseline and no iac row this run -> iac-baseline
    table_rows.extend(companion_rows(non_event, cc_urls, {r["repo_url"] for r in lever6_rows}))

    # lever 1d: rule-1 never-audited inventory bootstrap
    graph_db = args.graph_db or args.db.parent / "portfolio-graph.db"
    if not args.no_bootstrap:
        baselined_urls = {e["repo_url"] for e in entries if e["repo_url"]}
        bootstrap_rows = never_audited_rows(graph_db, baselined_urls, designations)
        table_rows.extend(bootstrap_rows)
    else:
        bootstrap_rows = []

    # threat-model Phase 3: additive calendar-backstop rows for models
    # older than the quarterly threshold, excluding repos already
    # getting a Phase-2 review this run.
    if args.no_threat_model:
        tm_quarterly = []
    else:
        tm_quarterly = threat_model_quarterly_rows(
            entries, tm_review_urls, args.threat_model_stale_days
        )
        table_rows.extend(tm_quarterly)

    # lever 1: tripwire escalation over below-threshold routed rows
    if network and not args.no_tripwire:
        tripwire_stats = run_tripwire(table_rows, by_key, args.jobs)
    else:
        tripwire_stats = {
            "eligible": 0,
            "escalated": 0,
            "quota_skipped": 0,
            "scanner_unavailable": 0,
            "disabled": True,
        }

    # refusal pre-route over diff-lane rows (after tripwire, so
    # tripwire-escalated diff-scans are vetted too; before sorting,
    # so re-routed rows land in the full-audit lane and the drain
    # pool shrinks accordingly)
    if network and not args.no_preroute:
        preroute_stats = run_preroute(table_rows, by_key, args.jobs)
    else:
        preroute_stats = {
            "eligible": 0,
            "rerouted_truncated": 0,
            "rerouted_ratio": 0,
            "checked_ratio": 0,
            "quota_skipped": 0,
            "gitlab_unchecked": 0,
            "disabled": True,
        }

    # threat-model Phase 1: stamp the surviving diff-lane rows AFTER the
    # pre-route, so a row re-routed to full-audit never carries a diff
    # companion it will not run.
    if args.no_threat_model:
        tm_pr_stats = {"eligible": 0, "stamped": 0, "no_model": 0, "disabled": True}
    else:
        tm_pr_stats = stamp_threat_model_pr(table_rows, by_key)

    decisions = (
        event_rows
        + tm_review_rows
        + sorted(
            table_rows,
            key=lambda d: (
                LANES.index(d["lane"]),
                EXPOSURE_ORDER.index(d.get("exposure") or "private-internal"),
                # lever-6 / companion rows carry tier None —
                # sort them with P3 rather than crashing
                TIER_ORDER.index(d.get("tier") or "P3"),
                -(d.get("S_lines") or 0),
                -(d.get("C") or 0),
            ),
        )
    )

    # lever 2: risk-ordered trickle-drain of the quarterly pool — the
    # weekly dispatch takes rows with drain_order < --drain-rate; a
    # public/external row older than DRAIN_TARGET_DAYS is flagged
    pool = [d for d in decisions if d["lane"] == "diff-scan-quarterly"]
    for i, d in enumerate(pool):
        d["drain_order"] = i
    drain_rate = args.drain_rate or -(-len(pool) // 13)  # ceil(pool/13)
    drain_overdue = [
        d
        for d in pool
        if d.get("exposure") in ("public-external", "private-external")
        and (d.get("changed_days") or 0) > DRAIN_TARGET_DAYS
    ]

    # threat-model quarterly pool gets its own drain ordering: the
    # backstop's whole point is that every model is revisited once per
    # quarter, so the pool spreads over THREAT_MODEL_DRAIN_WEEKS rather
    # than dispatching in one lump. This is the CADENCE, not a budget
    # cap — no row is ever dropped, only scheduled (uncapped by owner
    # decision 2026-08-05; a hard weekly ceiling can ride
    # --threat-model-drain-rate later if the spend warrants it).
    tm_pool = [d for d in decisions if d["lane"] == "threat-model-quarterly"]
    tm_pool.sort(
        key=lambda d: (
            EXPOSURE_ORDER.index(d.get("exposure") or "private-internal"),
            -(d.get("threat_model_age_days") or 0),
        )
    )
    for i, d in enumerate(tm_pool):
        d["drain_order"] = i
    tm_drain_rate = args.threat_model_drain_rate or -(-len(tm_pool) // THREAT_MODEL_DRAIN_WEEKS)

    if args.monthly_budget is not None:
        budget = args.monthly_budget
        budget_source = "--monthly-budget (explicit operator override)"
    else:
        budget, budget_source = read_policy_budget(optional_config_path("budget-policy.yaml"))
    decisions, dropped = apply_budget(decisions, args.unit_cost_full, budget)

    statuses = {}
    for e in entries:
        statuses[e["status"]] = statuses.get(e["status"], 0) + 1
    gitlab_unreachable = sum(
        1
        for e in entries
        if e.get("host_kind") == "gitlab" and e["status"] in ("unreachable", "error")
    )
    lane_counts = {}
    for d in decisions:
        lane_counts[d["lane"]] = lane_counts.get(d["lane"], 0) + 1
    fulls = sum(lane_counts.get(lane, 0) for lane in _FULL_LANES)

    doc = {
        "artifact": "rescan-worklist",
        "role": (
            "deterministic continuous-operations router — routes "
            "repos to scan lanes only, never authors a verdict"
        ),
        "generated_at": _dt.datetime.now(_dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "harness_version": harness_version(),
        "network": network,
        "population": {
            "total": total_rows,
            "evaluated": len(entries),
            "stage1_candidates": len(candidates),
            "errors": statuses.get("error", 0),
            "unsupported_host": statuses.get("unsupported-host", 0)
            + statuses.get("no-repo-url", 0),
            "no_credentials": statuses.get("no-credentials", 0),
            "unreachable": statuses.get("unreachable", 0),
            "gitlab_unreachable": gitlab_unreachable,
            "never_audited": len(bootstrap_rows),
            "statuses": dict(sorted(statuses.items())),
        },
        "decisions": decisions,
        "dropped_for_budget": dropped,
        "events_honored": events_honored,
        "summary": {
            "lanes": {lane: lane_counts.get(lane, 0) for lane in LANES},
            "full_audits": fulls,
            "projected_full_audit_cost_usd": round(fulls * args.unit_cost_full, 2),
            "budget_usd": budget,
            # Why that value (or why none) — a null ceiling used to be
            # indistinguishable from "no budget configured".
            "budget_source": budget_source,
            "exposure": {
                cls: sum(1 for d in decisions if d.get("exposure") == cls) for cls in EXPOSURE_ORDER
            },
            "tripwire": tripwire_stats,
            "preroute": preroute_stats,
            "drain": {
                "pool": len(pool),
                "weekly_rate": drain_rate,
                "overdue_public_external": len(drain_overdue),
            },
            "threat_model": {
                "stale_days": args.threat_model_stale_days,
                "models_read": tm_stats.get("read", 0),
                "undated": tm_stats.get("undated", 0),
                "repos_without_model": tm_stats.get("missing", 0),
                "pr_eligible_rows": tm_pr_stats.get("eligible", 0),
                "pr_stamped": tm_pr_stats.get("stamped", 0),
                "pr_skipped_no_model": tm_pr_stats.get("no_model", 0),
                "review_rows": len(tm_review_rows),
                "release_changes": dict(sorted(tm_release_seen.items())),
                "quarterly_pool": len(tm_pool),
                "quarterly_weekly_rate": tm_drain_rate,
                "disabled": bool(args.no_threat_model),
            },
        },
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    args.out.with_suffix(".md").write_text(render_md(doc), encoding="utf-8")
    print(f"[+] wrote {args.out} (+ .md)", file=sys.stderr)
    print(
        "[+] lanes: "
        + ", ".join(f"{k}={v}" for k, v in lane_counts.items())
        + (f" | dropped for budget: {len(dropped)}" if dropped else ""),
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    import sys

    from traust.cli.__main__ import main

    raise SystemExit(main(["build", "rescan-worklist", *sys.argv[1:]]))
