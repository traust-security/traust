#!/usr/bin/env bash
# safe_git.sh — the only git entry point this skill grants to an agent.
#
# `git -C <path>` on its own does NOT contain git's global-option dispatch:
#
#   git -C <hostile-checkout> --exec-path=<hostile-checkout> <helper>
#
# executes attacker-controlled binaries with the agent's environment. The old
# `Bash(git -C:*)` grant therefore allowed host code execution from a
# target-controlled repo. This wrapper accepts exactly one leading
# `-C <repo>`, a small read-only subcommand allowlist, and rejects the global
# options that redirect git at other binaries, config or repositories. It also
# runs git with a scrubbed environment and with hooks/fsmonitor/pager off.
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

# Reject global options that would re-point git (they are only meaningful
# before the subcommand, but be strict about the argument vector we forward).
for arg in "$@"; do
  case "$arg" in
    --exec-path | --exec-path=* | -c | --config-env | --config-env=* | \
    --git-dir | --git-dir=* | --work-tree | --work-tree=* | \
    --namespace | --namespace=* | --super-prefix | --super-prefix=* | \
    --upload-pack | --upload-pack=* | --receive-pack | --receive-pack=*)
      echo "safe_git: option not allowed: $arg" >&2
      exit 2
      ;;
  esac
done

exec env -i \
  PATH="${PATH:-/usr/bin:/bin}" \
  HOME="${HOME:-/tmp}" \
  TMPDIR="${TMPDIR:-/tmp}" \
  GIT_CONFIG_NOSYSTEM=1 \
  GIT_CONFIG_GLOBAL=/dev/null \
  GIT_TERMINAL_PROMPT=0 \
  GIT_OPTIONAL_LOCKS=0 \
  git -C "$repo" \
    -c safe.directory='*' \
    -c core.hooksPath=/dev/null \
    -c core.fsmonitor= \
    -c core.pager=cat \
    "$sub" "$@"
