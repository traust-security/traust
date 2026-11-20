#!/usr/bin/env bash
# Crash only a claim process from the private smoke rig, only after its writer succeeds.
set -euo pipefail
asset=$1 order=$2 repo=$3 worker=$4
shift 4
# Capture the generation handed to the writer itself, never one read back from the DB.
[[ "${@: -2:1}" = --lease-generation && "${!#}" =~ ^[1-9][0-9]*$ ]]
generation=${!#}
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
if [[ -f "$marker.order" ]]; then
    first_worker=$(cat "$marker.worker")
    [[ "$order" = "$(cat "$marker.order")" && "$worker" = "$first_worker" ]]
    first=$(cat "$marker.generation")
    [[ "$first" = 1 && "$generation" = 2 ]]
    # Reuse the lost attempt's own arguments before running this fresh attempt.
    # A different error (including a missing flag) is not proof of fencing.
    python3 scripts/ops_smoke/records.py retry-stale "$asset" "$order" \
        --worker "$first_worker" --lease-generation "$first" 2>"$marker.stderr"
else
    [[ "$generation" = 1 ]]
fi
result=$("$@" 2>"$marker.stderr")
if [[ ! -f "$marker.order" ]]; then
    printf '%s\n' "$generation" > "$marker.generation"
    printf '%s\n' "$worker" > "$marker.worker"
    printf '%s\n' "$order" > "$marker.order"
    printf '%s\n' "$result" > "$marker.receipt"
    kill -KILL "$PPID"
else
    cmp -s "$marker.receipt" <(printf '%s\n' "$result") || { echo 'replay receipt changed' >&2; exit 1; }
    printf '%s\n' "$order" > "$marker.replayed"
    printf '%s\n' "$generation" > "$marker.replayed-generation"
    printf '%s\n' "$result" > "$marker.replayed-receipt"
    printf '%s\n' "$result"
fi
