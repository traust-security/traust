#!/usr/bin/env bash
# Copy reports/<id>-fuzzing-report.md into every
# analysis-results/findings/**/<id>/ dir that already holds a real
# (non-symlink) <id>-security-audit.md. Idempotent — overwrites prior copies.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPORTS="$HERE/reports"
HARNESS="${HERE}"
while [ ! -f "${HARNESS}/pyproject.toml" ] && [ "${HARNESS}" != / ]; do
  HARNESS="$(dirname "${HARNESS}")"
done
[ -f "${HARNESS}/pyproject.toml" ] || { echo "harness root not found above ${HERE}" >&2; exit 1; }
_FINDINGS_OVERRIDE="${FINDINGS:-}"
# shellcheck source=../../../_lib/traust_paths.sh
source "${HARNESS}/harnessing/_lib/traust_paths.sh"
traust_load_paths
[[ -n "$_FINDINGS_OVERRIDE" ]] && FINDINGS="$_FINDINGS_OVERRIDE"
MANIFEST="$HERE/targets.json"

jq -r '.targets[].id' "$MANIFEST" | while read -r id; do
  src="$REPORTS/${id}-fuzzing-report.md"
  [[ -f "$src" ]] || { echo "skip $id (no report yet)"; continue; }
  n=0
  # match both findings/<id>/<id>-security-audit.md and findings/<seg>/<id>/<id>-security-audit.md
  while IFS= read -r audit; do
    dst="$(dirname "$audit")/${id}-fuzzing-report.md"
    cp -f "$src" "$dst"
    n=$((n+1))
  done < <(find "$FINDINGS" -maxdepth 3 -name "${id}-security-audit.md" -not -type l 2>/dev/null)
  echo "copied $id -> $n findings/ dirs"
done
