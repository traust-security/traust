#!/usr/bin/env bash
# Scaffold ONE remediation working tree for a traust-core work item.
#
# Pure shell/python — sets up the fork, working tree, and fix branch, then
# stops.  The actual code change is produced by the AI-driven
# `remediate-finding` skill (see SKILL.md), which calls this script for
# Phase 1 and ``emit_remediation_report.py`` + ``run_checks.sh`` for
# Phases 4–5.  Mirrors the structure of validate-operator-live/run_one.sh.
#
# Usage:
#   run_one.sh <work-item-id>
#   run_one.sh --next --repo-url <url>
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
WORKSPACE="$WS"
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

if [[ "$WI" == "__next__" || -z "$WI" ]]; then
  WI="$(traust remediation next --repo-url "${REPO_URL:?--next needs --repo-url}" \
    | python3 -c 'import sys,json; d=json.load(sys.stdin); print(d["work_item_id"] if d else "")')"
  [[ -z "$WI" ]] && { echo "[run_one] no pending work item" >&2; exit 0; }
fi

# WI becomes a path component (log path, out dir): a work item id is a UUID
if [[ ! "$WI" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]]; then
  echo "[run_one] not a work item id: $WI" >&2
  exit 1
fi

PREP="$(traust remediation prepare "$WI")" || { echo "[run_one] unknown work item: $WI" >&2; exit 1; }

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

# --- 2. prepare working tree at audited commit, cut fix branch -------------
WORK="$WORKSPACE/.fork-staging/work/$REPO"
# envtest / vendored toolchains can leave read-only dirs behind
[[ -d "$WORK" ]] && chmod -R u+w "$WORK" 2>/dev/null || true
rm -rf "$WORK"
# local bare-mirror clone — file transport only, made explicit
GIT_ALLOW_PROTOCOL=file \
  git clone --quiet "$WORKSPACE/.fork-staging/${REPO}.git" "$WORK"
# upstream is fetch-only; disable its push URL so an accidental `git push
# upstream` cannot reach the public repo even if ambient credentials exist.
git -C "$WORK" remote add upstream "$UPSTREAM" 2>/dev/null || true
git -C "$WORK" remote set-url --push upstream DISABLED_no_push_to_upstream
# fork remote uses a clean URL; auth is supplied at push time by an
# env-reading credential helper so the token is never written to
# .git/config, never visible in `git remote -v`, and never lands in the
# tee'd run log above.
case "$FORK_URL" in https://*) ;; *) echo "refuse: non-https FORK_URL" >&2; exit 1;; esac
git -C "$WORK" remote add fork "${FORK_URL%.git}.git" 2>/dev/null || \
  git -C "$WORK" remote set-url fork "${FORK_URL%.git}.git"
GH_CRED_HELPER='!f() { test "$1" = get && printf "username=x-access-token\npassword=%s\n" "${GITHUB_TOKEN:?GITHUB_TOKEN not set}"; }; f'
git -C "$WORK" config --local credential.useHttpPath false
git -C "$WORK" config --local --replace-all 'credential.https://github.com.helper' ''
git -C "$WORK" config --local --add         'credential.https://github.com.helper' "$GH_CRED_HELPER"

if [[ "$SHA" != "HEAD" ]] && git -C "$WORK" cat-file -e "${SHA}^{commit}" 2>/dev/null; then
  git -C "$WORK" checkout -B "$FIX_BRANCH" "$SHA"
else
  echo "[run_one] WARN: audited SHA unavailable; branching from default HEAD"
  git -C "$WORK" checkout -B "$FIX_BRANCH"
fi

# --- 3. the work item (findings, decisions, strategy) next to the worktree --
echo "$PREP" > "$OUT/prepared.json"

printf '{"work_item_id":"%s","worktree":"%s","fix_branch":"%s","fork_url":"%s","upstream_url":"%s","audited_commit":"%s","out":"%s","prepared":"%s"}\n' \
  "$WI" "$WORK" "$FIX_BRANCH" "$FORK_URL" "$UPSTREAM" "$SHA" "$OUT" "$OUT/prepared.json"

echo "[run_one] worktree ready — hand off to remediate-finding skill (Phase 2+)" >&2
