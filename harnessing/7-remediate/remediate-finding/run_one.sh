#!/usr/bin/env bash
# Scaffold ONE remediation working tree for a traust-core work item.
#
# Pure shell/python — sets up the fork and the working tree at the audited
# commit, then stops.  The actual code change is produced by the AI-driven
# `remediate-finding` skill (see SKILL.md), which calls this script for
# Phase 1 and ``run_checks.sh`` + ``traust remediation assemble`` for
# Phases 4–5.  Mirrors the structure of validate-operator-live/run_one.sh.
#
# Usage:
#   run_one.sh <work-item-id>
#   run_one.sh --next --repo-url <url>
#   run_one.sh                      (under a run order: $TRAUST_RUN_ID names the work item)
#
# Output (stdout): JSON describing the prepared workspace.

set -euo pipefail
export GIT_ALLOW_PROTOCOL=https  # local mirrors + https fetches only (plan P0.1)

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Harness root: the directory holding VERSION, walked rather than counted,
# so nesting this skill under a stage directory (skill-usability plan 1.2)
# cannot silently repoint it.
HARNESS="${HERE}"
while [ ! -f "${HARNESS}/VERSION" ] && [ "${HARNESS}" != / ]; do
  HARNESS="$(dirname "${HARNESS}")"
done
[ -f "${HARNESS}/VERSION" ] || { echo "harness root not found above ${HERE}" >&2; exit 1; }
# shellcheck source=../../_lib/traust_paths.sh
source "${HARNESS}/harnessing/_lib/traust_paths.sh"
traust_load_paths
traust() { python3 -m traust.cli "$@"; }

WI=""
REPO_URL=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --next)     WI="__next__"; shift;;
    --repo-url) REPO_URL="$2"; shift 2;;
    *)          WI="$1"; shift;;
  esac
done

if [[ -z "$WI" && -n "${TRAUST_RUN_ID:-}" ]]; then
  # the order names the work item; never the repository's next one
  PREP="$(traust remediation prepare)" || { echo "[run_one] order $TRAUST_RUN_ID: no work item to prepare" >&2; exit 1; }
  WI="$(echo "$PREP" | python3 -c 'import sys,json; print(json.load(sys.stdin)["work_item"]["work_item_id"])')"
elif [[ "$WI" == "__next__" || -z "$WI" ]]; then
  WI="$(traust remediation next --repo-url "${REPO_URL:?--next needs --repo-url}" \
    | python3 -c 'import sys,json; d=json.load(sys.stdin); print(d["work_item_id"] if d else "")')"
  [[ -z "$WI" ]] && { echo "[run_one] no pending work item" >&2; exit 0; }
fi

# WI becomes a path component (log path, out dir): a work item id is a UUID
if [[ ! "$WI" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]]; then
  echo "[run_one] not a work item id: $WI" >&2
  exit 1
fi

if [[ -z "${PREP:-}" ]]; then
  PREP="$(traust remediation prepare "$WI")" || { echo "[run_one] unknown work item: $WI" >&2; exit 1; }
fi

field() { echo "$PREP" | python3 -c "import sys,json;d=json.load(sys.stdin)
for k in '$1'.split('.'): d=d[k]
print(d)"; }

UPSTREAM="$(field subject.repository_url)"
FORK_URL="https://$(field fork.url.host)/$(field fork.url.path)"
SHA="$(field subject.sha)"
FIX_BRANCH="$(field fix_branch)"
REPO="${UPSTREAM%/}"; REPO="${REPO##*/}"; REPO="${REPO%.git}"
# repository-derived names become path components under rm -rf / mkdir —
# no separators, no dot-runs (audit F6, plan P0.2)
if [[ ! "$REPO" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ || "$REPO" == *..* ]]; then
  echo "[run_one] unsafe repository name: $REPO" >&2
  exit 1
fi
OUT="$AR/remediations/$REPO/$WI"
mkdir -p "$OUT"
LOG="$OUT/run.log"
exec > >(tee -a "$LOG") 2>&1

echo "================================================================"
echo "[run_one] $(date -Is) work_item=$WI upstream=$UPSTREAM sha=$SHA"
echo "[run_one] fork=$FORK_URL fix_branch=$FIX_BRANCH out=$OUT"

traust remediation progress "$WI" forked >/dev/null

# --- 1. ensure private fork exists & is synced -----------------------------
FORK_INFO="$(bash "$HERE/ensure_fork.sh" "$UPSTREAM" "$FORK_URL" "$SHA")"
echo "[run_one] fork: $FORK_INFO"

# --- 2. working tree at audited commit -------------------------------------
# A checkout worktree shares the bare mirror's repository config and ref
# namespace, so remotes, credential helpers and locally-cut branches are
# never written here — a later mirror fetch would prune them, and config
# writes would contaminate every other consumer of that mirror. The worktree
# is detached at the audited commit; Phase 6 pushes
# HEAD:refs/heads/<fix_branch> to the fork by URL with a per-command
# credential helper.
WORK="$(traust repo checkout "$UPSTREAM" --ref "$SHA" --writable)"

# --- 3. the work item (findings, decisions, strategy) next to the worktree --
echo "$PREP" > "$OUT/prepared.json"

printf '{"work_item_id":"%s","worktree":"%s","fix_branch":"%s","fork_url":"%s","upstream_url":"%s","audited_commit":"%s","out":"%s","prepared":"%s"}\n' \
  "$WI" "$WORK" "$FIX_BRANCH" "$FORK_URL" "$UPSTREAM" "$SHA" "$OUT" "$OUT/prepared.json"

echo "[run_one] worktree ready — hand off to remediate-finding skill (Phase 2+)" >&2
