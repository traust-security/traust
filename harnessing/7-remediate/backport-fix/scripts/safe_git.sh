#!/usr/bin/env bash
# safe_git.sh — the only git entry point this skill grants to an agent.
#
# `git -C <path>` alone does NOT contain git's dispatch:
#   * `git -C <hostile> --exec-path=<hostile> <helper>` runs attacker code;
#   * `git show --textconv` / `--ext-diff` and `cat-file --filters/--textconv`
#     run diff/filter drivers the *checkout* configures (repo config and
#     .gitattributes), with the agent's environment.
#
# This wrapper accepts exactly one leading `-C <repo>`, a read-only
# subcommand allowlist, and a per-subcommand option allowlist. Unknown
# options are rejected, so --textconv/--ext-diff/--filters/--output/--path
# cannot be requested; `show` additionally always runs with --no-textconv and
# --no-ext-diff. Git runs with a scrubbed environment, hooks/fsmonitor/pager
# off, and no `safe.directory=*` override — ownership checks stay in force.
#
# Usage: safe_git.sh -C <repo> <cat-file|rev-parse|show|for-each-ref> [args...]
set -euo pipefail

usage() {
  echo "usage: safe_git.sh -C <repo> <cat-file|rev-parse|show|for-each-ref> [args...]" >&2
  exit 2
}

[[ $# -ge 3 ]] || usage
[[ "$1" == "-C" && -n "${2:-}" ]] || usage
repo="$2"
shift 2
[[ -d "$repo" ]] || { echo "safe_git: not a directory: $repo" >&2; exit 2; }

sub="${1:-}"
shift || true
case "$sub" in
  cat-file | rev-parse | show | for-each-ref) ;;
  *) echo "safe_git: subcommand not allowed: '${sub:-<none>}'" >&2; exit 2 ;;
esac

allowed_arg() {  # $1 = subcommand, $2 = argument
  case "$1:$2" in
    cat-file:-t | cat-file:-e | cat-file:-s | cat-file:-p | cat-file:--) return 0 ;;
    rev-parse:--verify | rev-parse:--quiet | rev-parse:--short \
      | rev-parse:--short=* | rev-parse:--abbrev-ref \
      | rev-parse:--symbolic | rev-parse:--) return 0 ;;
    show:--stat | show:--name-only | show:--name-status \
      | show:--oneline | show:--no-patch \
      | show:--no-textconv | show:--no-ext-diff | show:--) return 0 ;;
    for-each-ref:--format=* | for-each-ref:--count=* \
      | for-each-ref:--sort=* | for-each-ref:--) return 0 ;;
  esac
  return 1
}

for arg in "$@"; do
  case "$arg" in
    -*)
      allowed_arg "$sub" "$arg" || {
        echo "safe_git: option not allowed for '$sub': $arg" >&2
        exit 2
      }
      ;;
  esac
done

# Diff drivers are repository-selected; never let them run even if a future
# allowlist entry forgets the guard.
if [[ "$sub" == "show" ]]; then
  set -- --no-textconv --no-ext-diff "$@"
fi

# Git itself comes from a fixed system PATH, never the caller's: a writable
# directory early in an agent's PATH could otherwise supply its own `git`.
# The same fixed PATH is all git's own subprocesses see.
TRUSTED_PATH="/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin"
git_bin="$(PATH="$TRUSTED_PATH" command -v git || true)"
[[ "$git_bin" == /* && -x "$git_bin" ]] || {
  echo "safe_git: no git on the trusted PATH ($TRUSTED_PATH)" >&2
  exit 2
}
if [[ -n "$(find "$git_bin" "$(dirname "$git_bin")" -maxdepth 0 -perm -0002 2>/dev/null)" ]]; then
  echo "safe_git: refusing world-writable git or git directory: $git_bin" >&2
  exit 2
fi

exec env -i \
  PATH="$TRUSTED_PATH" \
  HOME="${HOME:-/tmp}" \
  TMPDIR="${TMPDIR:-/tmp}" \
  GIT_CONFIG_NOSYSTEM=1 \
  GIT_CONFIG_GLOBAL=/dev/null \
  GIT_ATTR_NOSYSTEM=1 \
  GIT_TERMINAL_PROMPT=0 \
  GIT_OPTIONAL_LOCKS=0 \
  "$git_bin" -C "$repo" \
    -c core.hooksPath=/dev/null \
    -c core.fsmonitor= \
    -c core.pager=cat \
    -c core.attributesFile=/dev/null \
    -c diff.external= \
    -c log.showSignature=false \
    -c gpg.program=/bin/false \
    -c gpg.openpgp.program=/bin/false \
    -c gpg.x509.program=/bin/false \
    -c gpg.ssh.program=/bin/false \
    "$sub" "$@"
