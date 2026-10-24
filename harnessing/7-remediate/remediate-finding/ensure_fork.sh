#!/usr/bin/env bash
# Ensure a *private mirror* of an upstream repo exists at the fork URL,
# is up to date, and contains the audited commit.  Idempotent.
#
# GitHub does not allow private forks of public repos, so this script
# creates an empty private repo (if missing) and mirror-pushes upstream
# branches + tags into it.  refs/pull/* are deliberately excluded.
#
# Usage:
#   ensure_fork.sh <upstream-url> [<fork-url>] [<audited-sha>]
#
# Env:
#   GITHUB_TOKEN   required for creating the repo and pushing.
#   FORK_STAGING   override staging dir (default: $WORKSPACE/.fork-staging).
#
# Output (stdout): JSON {upstream_url, fork_url, staging_dir, default_branch,
#                        audited_sha_present, created}.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HARNESS="${HERE}"
while [ ! -f "${HARNESS}/VERSION" ] && [ "${HARNESS}" != / ]; do
  HARNESS="$(dirname "${HARNESS}")"
done
[ -f "${HARNESS}/VERSION" ] || { echo "harness root not found above ${HERE}" >&2; exit 1; }
# shellcheck source=../../_lib/traust_paths.sh
source "${HARNESS}/harnessing/_lib/traust_paths.sh"
traust_load_paths
WORKSPACE="$WS"
STAGING="${FORK_STAGING:-$WORKSPACE/.fork-staging}"

UPSTREAM="${1:?usage: ensure_fork.sh <upstream-url> [<fork-url>] [<audited-sha>]}"
FORK_URL="${2:-}"
AUDITED_SHA="${3:-}"

# Upstream URL reaches `git clone`/`remote set-url` — manifest rows are
# not all produced by validating writers, so gate at the sink (audit A3,
# plan P0.1): https on an allowlisted host only, and https-only git
# transport for everything this script does.
#
# The allowlist defaults to github.com alone. A deployment that also forks
# from a private forge names it in FORK_UPSTREAM_HOSTS (space- or
# comma-separated); the host is deployment config, not a shipped constant.
# Widening is opt-in, so the default stays the narrower, fail-closed set.
UPSTREAM_HOSTS="${FORK_UPSTREAM_HOSTS:-github.com}"
_host_alt="$(printf '%s' "$UPSTREAM_HOSTS" | tr ', ' '||' | sed 's/||*/|/g; s/^|//; s/|$//; s/\./\\./g')"
if [[ ! "$UPSTREAM" =~ ^https://(${_host_alt})/[^[:space:]]+$ ]]; then
  echo "[ensure_fork] upstream must be https on one of: $UPSTREAM_HOSTS — got $UPSTREAM" >&2
  exit 1
fi
if [[ -n "$AUDITED_SHA" && ! "$AUDITED_SHA" =~ ^[0-9a-f]{7,40}$ ]]; then
  echo "[ensure_fork] audited-sha must be 7-40 hex chars: $AUDITED_SHA" >&2
  exit 1
fi
export GIT_ALLOW_PROTOCOL=https

if [[ -z "$FORK_URL" ]]; then
  FORK_URL="$(python3 -m traust.cli remediation fork --repo-url "$UPSTREAM" | python3 -c 'import sys,json;print(json.load(sys.stdin)["url"])')"
fi

: "${GITHUB_TOKEN:?GITHUB_TOKEN must be set to push to the private fork}"

# --- parse fork owner/repo (github only for now) ---------------------------
if [[ "$FORK_URL" =~ ^https://github\.com/([^/]+)/([^/]+?)(\.git)?/?$ ]]; then
  FORK_OWNER="${BASH_REMATCH[1]}"
  FORK_REPO="${BASH_REMATCH[2]}"
else
  echo "[ensure_fork] only github.com fork URLs are supported in the pilot: $FORK_URL" >&2
  exit 2
fi

api() {
  # api METHOD PATH [DATA] — token via --config on stdin, never argv
  # (argv is ps-visible to any local user; audit E2, plan P2.15)
  local method="$1" path="$2" data="${3:-}"
  printf 'header = "Authorization: Bearer %s"\n' "$GITHUB_TOKEN" | \
  curl -fsS -X "$method" \
       --config - \
       -H "Accept: application/vnd.github+json" \
       ${data:+-d "$data"} \
       "https://api.github.com$path"
}

# --- 1. create private repo if it doesn't exist ----------------------------
CREATED=false
if ! api GET "/repos/$FORK_OWNER/$FORK_REPO" >/dev/null 2>&1; then
  echo "[ensure_fork] creating private repo $FORK_OWNER/$FORK_REPO" >&2
  AUTH_USER="$(api GET /user 2>/dev/null | python3 -c 'import sys,json;print(json.load(sys.stdin).get("login",""))' 2>/dev/null || true)"
  # JSON via json.dumps — printf into a JSON template lets a crafted
  # value inject fields (audit F8, plan P2.15)
  BODY="$(python3 -c 'import json,sys; print(json.dumps({
      "name": sys.argv[1], "private": True, "visibility": "private",
      "has_issues": False, "has_wiki": False,
      "description": "Private mirror of %s for automated security remediation (traust)." % sys.argv[2]}))' "$FORK_REPO" "$UPSTREAM")"
  if [[ -n "$AUTH_USER" && "$FORK_OWNER" == "$AUTH_USER" ]]; then
    api POST "/user/repos" "$BODY" >/dev/null
  else
    # Fork owner is an org (or another user) — use the org endpoint.
    api POST "/orgs/$FORK_OWNER/repos" "$BODY" >/dev/null
  fi
  CREATED=true
fi
# Hard guard: the harness only ever pushes to private/internal mirrors.
VIS="$(api GET "/repos/$FORK_OWNER/$FORK_REPO" 2>/dev/null | python3 -c 'import sys,json;print(json.load(sys.stdin).get("visibility",""))' 2>/dev/null || true)"
if [[ "$VIS" != "private" && "$VIS" != "internal" ]]; then
  echo "[ensure_fork] REFUSING: $FORK_OWNER/$FORK_REPO visibility='$VIS' (must be private|internal)" >&2
  exit 3
fi

# --- 2. bare clone upstream into staging (or fetch if exists) --------------
# Upstream may be public (HTTPS anon) or a private forge (needs auth).
# Rewrite a private-forge HTTPS URL to SSH so the ambient SSH key handles
# auth without embedding a token in the URL or .git/config. The forge is
# named by FORK_SSH_REWRITE_HOST; unset means no rewrite. The DESTINATION mirror
# is always a private repo in the adopter's mirror organisation (remediation.yaml
# fork_org) regardless of upstream host — embargo perimeter stays uniform.
CLONE_URL="$UPSTREAM"
if [[ -n "${FORK_SSH_REWRITE_HOST:-}" ]]; then
  _rw="$(printf '%s' "$FORK_SSH_REWRITE_HOST" | sed 's/\./\\./g')"
  if [[ "$UPSTREAM" =~ ^https?://${_rw}/(.+?)/?$ ]]; then
    CLONE_URL="git@${FORK_SSH_REWRITE_HOST}:${BASH_REMATCH[1]%.git}.git"
    echo "[ensure_fork] private-forge upstream — cloning via SSH: $CLONE_URL" >&2
  fi
fi
mkdir -p "$STAGING"
BARE="$STAGING/${FORK_REPO}.git"
case "$CLONE_URL" in https://*) ;; *) echo "refuse: non-https CLONE_URL" >&2; exit 1;; esac
if [[ -d "$BARE" ]]; then
  git -C "$BARE" remote set-url origin "$CLONE_URL"
  GIT_ALLOW_PROTOCOL=https git -C "$BARE" fetch --prune --quiet origin '+refs/heads/*:refs/heads/*' '+refs/tags/*:refs/tags/*'
else
  GIT_ALLOW_PROTOCOL=https git clone --bare --quiet "$CLONE_URL" "$BARE"
fi

DEFAULT_BRANCH="$(git -C "$BARE" symbolic-ref --short HEAD 2>/dev/null || echo main)"

# --- 3. push branches+tags to the private fork -----------------------------
# Auth via an env-reading credential helper so the token never appears in a
# URL, in .git/config, in `git remote -v`, in process args (curl gets the
# header via --config on stdin — a -H argv header IS ps-visible), or in
# tee'd run logs.
CLEAN_FORK_URL="https://github.com/${FORK_OWNER}/${FORK_REPO}.git"
GH_CRED_HELPER='!f() { test "$1" = get && printf "username=x-access-token\npassword=%s\n" "${GITHUB_TOKEN:?GITHUB_TOKEN not set}"; }; f'
git -C "$BARE" config --local credential.useHttpPath false
git -C "$BARE" config --local --replace-all 'credential.https://github.com.helper' ''
git -C "$BARE" config --local --add         'credential.https://github.com.helper' "$GH_CRED_HELPER"
git -C "$BARE" push --quiet "$CLEAN_FORK_URL" 'refs/heads/*:refs/heads/*' \
  || echo "[ensure_fork] WARN: branch sync rejected (fork has diverged refs); continuing — fix branches are pushed independently" >&2
git -C "$BARE" push --quiet "$CLEAN_FORK_URL" 'refs/tags/*:refs/tags/*' \
  || echo "[ensure_fork] WARN: tag sync rejected; continuing" >&2

# --- 4. verify audited SHA is present in the fork --------------------------
SHA_PRESENT=false
if [[ -n "$AUDITED_SHA" ]]; then
  if git -C "$BARE" cat-file -e "${AUDITED_SHA}^{commit}" 2>/dev/null; then
    SHA_PRESENT=true
  else
    echo "[ensure_fork] WARN: audited SHA $AUDITED_SHA not found in upstream history" >&2
  fi
fi

printf '{"upstream_url":"%s","fork_url":"%s","staging_dir":"%s","default_branch":"%s","audited_sha_present":%s,"created":%s}\n' \
  "$UPSTREAM" "$FORK_URL" "$BARE" "$DEFAULT_BRANCH" "$SHA_PRESENT" "$CREATED"
