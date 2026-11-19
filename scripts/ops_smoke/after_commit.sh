#!/usr/bin/env bash
# Crash only a claim process from the private smoke rig, only after its writer succeeds.
set -euo pipefail
asset=$1 order=$2 repo=$3
shift 3
case "$asset:$repo" in
    manifest_sbom:https://github.com/example/smoke-failure|manifest_sbom:https://github.com/example/smoke-containers)
        exec "$@" ;;
esac
[[ "$repo" = https://github.com/example/smoke-repo ]]
[[ "$asset" = manifest_sbom || "$asset" = smoke_triage || "$asset" = smoke_authored ]]
[[ "$order" =~ ^[0-9a-f-]{36}$ && "$OPS_SMOKE_RUN" = "$PWD"/.local-ops-smoke.????????/run ]]
grep -zqE '(^|/)traust-engine$' "/proc/$PPID/cmdline"
grep -zqx claim "/proc/$PPID/cmdline"
marker="$OPS_SMOKE_RUN/$asset"
result=$("$@" 2>"$marker.stderr")
if [[ ! -f "$marker.order" ]]; then
    printf '%s\n' "$order" > "$marker.order"
    printf '%s\n' "$result" > "$marker.receipt"
    kill -KILL "$PPID"
else
    [[ "$order" = "$(cat "$marker.order")" ]]
    cmp -s "$marker.receipt" <(printf '%s\n' "$result") || { echo 'replay receipt changed' >&2; exit 1; }
    printf '%s\n' "$order" > "$marker.replayed"
    printf '%s\n' "$result"
fi
