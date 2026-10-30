#!/usr/bin/env bash
# local_ops — the local continuous-ops rig: one Postgres container, a config
# home and a compressed-cadence copy of the security pack, so `traust-engine
# run` and `claim` can be exercised on a laptop or in CI. See
# docs/continuous-operations.md, "The local rig".
#
# Usage (or the make ops-* targets):
#   scripts/local_ops.sh up                 start the rig (idempotent)
#   scripts/local_ops.sh run                the engine tick loop — pane 1
#   scripts/local_ops.sh claim              the claim loop — pane 2
#   scripts/local_ops.sh sh                 a shell with the rig's environment
#   scripts/local_ops.sh scan <repo-url>    onboard + observe + one vuln-scan session
#   scripts/local_ops.sh smoke              one bounded cycle with asserts (the CI entry)
#   scripts/local_ops.sh doctor             check the rig
#   scripts/local_ops.sh down               stop Postgres (data kept)
#   scripts/local_ops.sh reset              drop the volume, regenerate config and pack
#
# The rig never edits shipped files: config, traust.yaml and the overlay pack are
# generated under .local-ops/ (gitignored). The overlay pack is sed'd from
# packs/security/assets.yaml with cadences compressed to minutes; it is a test
# artifact, never committed. Tokens live in .local-ops/env (also gitignored).
#
# traust-engine is installed into this checkout's venv with --no-deps (it needs
# only traust-core and pyyaml, both present) and every command runs through
# `uv run --no-sync`, because a plain `uv run` would sync the extra package
# away. `up` reinstalls it when missing, so a `uv sync` in between is harmless.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

OPS_DIR="${OPS_DIR:-.local-ops}"
OPS_PORT="${OPS_PORT:-5433}"
OPS_CONTAINER="${OPS_CONTAINER:-traust-ops-local}"
OPS_VOLUME="${OPS_VOLUME:-traust-ops-local-data}"
OPS_IMAGE="${OPS_IMAGE:-docker.io/library/postgres:16}"
OPS_DB_USER="${OPS_DB_USER:-traust}"
OPS_DB_PASS="${OPS_DB_PASS:-traust}"
OPS_DB_NAME="${OPS_DB_NAME:-traust}"
OPS_DSN="postgresql://${OPS_DB_USER}:${OPS_DB_PASS}@localhost:${OPS_PORT}/${OPS_DB_NAME}"
OPS_EVERY="${OPS_EVERY:-1m}"            # engine --every: minutes, hours or days
OPS_ENGINE_SRC="${OPS_ENGINE_SRC:-git+https://github.com/traust-security/traust-engine@779471df5b9473bbf31cf0ad78d213f88bda9153}"
OPS_SMOKE_REPO="${OPS_SMOKE_REPO:-https://github.com/octocat/Hello-World}"

CONFIG_HOME="$REPO_ROOT/$OPS_DIR/config"
RUN_DIR="$REPO_ROOT/$OPS_DIR/run"

if command -v podman >/dev/null 2>&1; then CT=podman; else CT=docker; fi

# The cadence compression: pack value → rig value (sed pairs).
pack_overlay() {
    sed -e 's/every: 24h/every: 2m/' \
        -e 's/every: 7d/every: 5m/' \
        -e 's/every: 3d/every: 3m/' \
        -e 's/every: 30d/every: 6m/' \
        -e 's/every: 90d/every: 9m/' \
        packs/security/assets.yaml
}

container_running() {
    "$CT" ps --format '{{.Names}}' 2>/dev/null | grep -qx "$OPS_CONTAINER"
}

wait_for_db() {
    for _ in $(seq 1 30); do
        "$CT" exec "$OPS_CONTAINER" pg_isready -U "$OPS_DB_USER" -q 2>/dev/null && return 0
        sleep 1
    done
    echo "Postgres never became ready in $OPS_CONTAINER" >&2
    return 1
}

install_engine() {
    if uv run --no-sync python -c "import traust_engine" >/dev/null 2>&1; then
        return 0
    fi
    echo "installing traust-engine from $OPS_ENGINE_SRC"
    uv pip install --no-deps "$OPS_ENGINE_SRC" >/dev/null
    uv run --no-sync python -c "import traust_engine"
}

# Engine invocation shared by run/claim/smoke: the overlay pack, the feeds and
# tool pins traust-core ships, and the config home's traust.yaml + model registry.
shipped() {
    uv run --no-sync python -c "from traust_core.v1.context import config; print(config.$1)"
}
engine() {
    TRAUST_CONFIG_HOME="$CONFIG_HOME" uv run --no-sync traust-engine "$@" \
        --core "$CONFIG_HOME/traust.yaml" \
        --pack "$OPS_DIR/pack/assets.yaml" \
        --pin "$(shipped SHIPPED_EXTERNAL_TOOLS)" \
        --feeds "$(shipped SHIPPED_FEEDS)" \
        --models "$CONFIG_HOME/model-registry.yaml"
}

traust_cli() {
    TRAUST_CONFIG_HOME="$CONFIG_HOME" uv run --no-sync python -m traust.cli "$@"
}

source_env() {
    # shellcheck disable=SC1090
    [ -f "$REPO_ROOT/$OPS_DIR/env" ] && . "$REPO_ROOT/$OPS_DIR/env" || true
    return 0
}

cmd_up() {
    if ! container_running; then
        if "$CT" ps -a --format '{{.Names}}' 2>/dev/null | grep -qx "$OPS_CONTAINER"; then
            "$CT" start "$OPS_CONTAINER" >/dev/null
        else
            echo "starting $OPS_CONTAINER ($OPS_IMAGE) on 127.0.0.1:$OPS_PORT"
            "$CT" run --name "$OPS_CONTAINER" -d \
                -e POSTGRES_USER="$OPS_DB_USER" -e POSTGRES_PASSWORD="$OPS_DB_PASS" \
                -e POSTGRES_DB="$OPS_DB_NAME" \
                -p "127.0.0.1:${OPS_PORT}:5432" \
                -v "$OPS_VOLUME:/var/lib/postgresql/data" \
                "$OPS_IMAGE" >/dev/null
        fi
    fi
    wait_for_db

    uv sync --quiet
    install_engine

    # The rig's traust.yaml: its database and locations. `home` keeps core's credential
    # store and local-issuer key inside the rig: without it they land in ~/.traust, over a
    # real install's login there.
    if [ ! -f "$CONFIG_HOME/traust.yaml" ]; then
        bash scripts/install_traust --config-home "$CONFIG_HOME" \
            --yes --no-toolchain --no-profile-write >/dev/null
        cat > "$CONFIG_HOME/traust.yaml" <<EOF
# Written by scripts/local_ops.sh (make ops-up); the local rig's traust.yaml.
home: $RUN_DIR/home
database:
  url: $OPS_DSN
artifacts:
  path: $RUN_DIR/artifacts
identity:
  trust_local: true
locations:
  workspace: $RUN_DIR/workspace
  analysis_results: $RUN_DIR/analysis-results
  progress_tracker: $RUN_DIR/progress-tracker
# manifest_sbom runs syft through core's ProcessRunner, which runs only what is listed here.
process:
  allowed_binaries: [syft]
EOF
    fi
    mkdir -p "$RUN_DIR/home" "$RUN_DIR/workspace" "$RUN_DIR/analysis-results" "$RUN_DIR/progress-tracker" "$OPS_DIR/pack"
    pack_overlay > "$OPS_DIR/pack/assets.yaml"

    # Core applies its schema itself only for its local SQLite; a Postgres
    # deployment applies the contract DDL, so the rig does too (idempotent).
    OPS_DSN="$OPS_DSN" uv run --no-sync python - <<'PYEOF'
import os
from traust_core.v1 import contracts
from traust_core.v1.repositories import apply_schema, create_database_engine
from traust_core.v1.repositories.sql import contract_dialect
engine = create_database_engine(os.environ["OPS_DSN"])
apply_schema(engine, contracts.database_ddl(contract_dialect(engine)))
print("database contract applied")
PYEOF

    if [ ! -f "$REPO_ROOT/$OPS_DIR/env" ]; then
        cat > "$REPO_ROOT/$OPS_DIR/env" <<'EOF'
# Sourced by every local_ops command (gitignored). Fill what you use: without
# GITHUB_TOKEN, repo_state orders fail as no-credentials; without
# ANTHROPIC_API_KEY (or a login under <config home>/claude-runner), skill
# sessions fail as runner-crashed.
#export GITHUB_TOKEN=
#export ANTHROPIC_API_KEY=
EOF
    fi

    # A solo install accepts its own local tokens; make one so the traust CLI
    # can write (onboard, observe, record). Re-running refreshes the token.
    TRAUST_CONFIG_HOME="$CONFIG_HOME" uv run --no-sync python -m traust.cli auth local \
        --identity "${USER:-$(id -un)}@local-rig" >/dev/null

    echo "rig up: Postgres :$OPS_PORT, config home $OPS_DIR/config, overlay pack $OPS_DIR/pack"
    echo "next: make ops-run (pane 1) and make ops-claim (pane 2); or make ops-smoke"
}

cmd_down() {
    "$CT" stop "$OPS_CONTAINER" >/dev/null 2>&1 || true
    echo "rig down (volume $OPS_VOLUME kept; make ops-reset drops it)"
}

cmd_reset() {
    "$CT" rm -f "$OPS_CONTAINER" >/dev/null 2>&1 || true
    "$CT" volume rm "$OPS_VOLUME" >/dev/null 2>&1 || true
    # Keep the user's tokens (.local-ops/env); everything else regenerates.
    if [ -f "$REPO_ROOT/$OPS_DIR/env" ]; then
        mv "$REPO_ROOT/$OPS_DIR/env" "${TMPDIR:-/tmp}/local-ops-env.$$"
        rm -rf "$OPS_DIR"
        mkdir -p "$OPS_DIR"
        mv "${TMPDIR:-/tmp}/local-ops-env.$$" "$REPO_ROOT/$OPS_DIR/env"
    else
        rm -rf "$OPS_DIR"
    fi
    uv pip uninstall -q traust-engine >/dev/null 2>&1 || true
    echo "rig reset: volume, config home, overlay pack, credentials and the venv's"
    echo "traust-engine install are gone (.local-ops/env kept); nothing outside the repo touched"
}

cmd_run() {
    engine run --router traust.ops.router:SecurityRouter --every "$OPS_EVERY"
}

cmd_claim() {
    source_env
    while true; do
        engine claim || true
        sleep 5
    done
}

cmd_sh() {
    source_env
    export TRAUST_CONFIG_HOME="$CONFIG_HOME"
    exec "${SHELL:-/bin/bash}"
}

cmd_scan() {
    [ $# -eq 1 ] || { echo "usage: scripts/local_ops.sh scan <repo-url>" >&2; exit 2; }
    local repo="$1"
    source_env
    traust_cli portfolio onboard --product local-rig --label "Local rig" --repo "$repo"
    traust_cli portfolio observe --repo "$repo"
    traust_cli session run --skill vuln-scan --role vuln-scan --repo "$repo" --checkout
}

cmd_doctor() {
    local bad=0
    if container_running; then
        echo "Postgres: running ($OPS_CONTAINER :$OPS_PORT)"
    else
        echo "Postgres: NOT running (make ops-up)" >&2; bad=1
    fi
    if uv run --no-sync python -c "import traust_engine" >/dev/null 2>&1; then
        echo "traust-engine: importable"
    else
        echo "traust-engine: NOT importable (make ops-up reinstalls it)" >&2; bad=1
    fi
    if [ -f "$CONFIG_HOME/traust.yaml" ]; then
        echo "config home: $OPS_DIR/config"
    else
        echo "config home: missing (make ops-up)" >&2; bad=1
    fi
    source_env
    [ -n "${GITHUB_TOKEN:-}" ] && echo "GITHUB_TOKEN: set" \
        || echo "GITHUB_TOKEN: unset (repo_state orders will fail as no-credentials)"
    [ -n "${ANTHROPIC_API_KEY:-}" ] && echo "ANTHROPIC_API_KEY: set" \
        || echo "ANTHROPIC_API_KEY: unset (skill sessions will fail as runner-crashed)"
    TRAUST_CONFIG_HOME="$CONFIG_HOME" uv run --no-sync python -m traust.cli doctor 2>&1 | tail -5 || bad=1
    return $bad
}

cmd_smoke() {
    source_env
    if [ -z "${GITHUB_TOKEN:-}" ] && ! gh auth status >/dev/null 2>&1; then
        echo "smoke needs forge access: GITHUB_TOKEN or a gh login (repo_state reads the forge)" >&2
        exit 2
    fi
    cmd_reset
    cmd_up >/dev/null
    local repo="${1:-$OPS_SMOKE_REPO}"
    echo "smoke: onboarding $repo"
    traust_cli portfolio onboard --product local-rig --label "Local rig" --repo "$repo" >/dev/null
    # Two passes: the first observes the repository, the second plans what depends on it
    # (manifest_sbom waits on repo_state).
    local pass idle _
    for pass in 1 2; do
        echo "smoke: engine pass $pass (applies the schema, plans what is due)"
        engine run --router traust.ops.router:SecurityRouter --once >/dev/null
        echo "smoke: claiming until the queue drains"
        idle=0
        for _ in $(seq 1 40); do
            if engine claim | grep -q '"claimed": null'; then
                idle=$((idle + 1))
                [ "$idle" -ge 2 ] && break
            else
                idle=0
            fi
            sleep 2
        done
    done
    echo "smoke: orders by asset and state"
    "$CT" exec "$OPS_CONTAINER" psql -U "$OPS_DB_USER" -d "$OPS_DB_NAME" \
        -c "select asset, state, count(*) from traust_ops.run_order group by 1, 2 order by 1, 2"
    local bad=0
    "$CT" exec "$OPS_CONTAINER" psql -U "$OPS_DB_USER" -d "$OPS_DB_NAME" -tAc \
        "select count(*) from traust_ops.run_order where state in ('running', 'queued')" \
        | grep -qx 0 || { echo "smoke: orders left running or queued" >&2; bad=1; }
    "$CT" exec "$OPS_CONTAINER" psql -U "$OPS_DB_USER" -d "$OPS_DB_NAME" -tAc \
        "select count(*) from traust_ops.run_order where asset = 'feeds_cache' and state in ('succeeded', 'degraded')" \
        | grep -qx 0 && { echo "smoke: no completed feeds_cache order" >&2; bad=1; }
    "$CT" exec "$OPS_CONTAINER" psql -U "$OPS_DB_USER" -d "$OPS_DB_NAME" -tAc \
        "select count(*) from traust_ops.run_order where asset = 'repo_state' and state in ('succeeded', 'degraded')" \
        | grep -qx 0 && { echo "smoke: no completed repo_state order" >&2; bad=1; }
    "$CT" exec "$OPS_CONTAINER" psql -U "$OPS_DB_USER" -d "$OPS_DB_NAME" -tAc \
        "select count(*) from traust_ops.run_order where asset = 'manifest_sbom' and state in ('succeeded', 'degraded')" \
        | grep -qx 0 && { echo "smoke: no completed manifest_sbom order" >&2; bad=1; }
    if [ "${OPS_TEARDOWN:-0}" = "1" ]; then
        "$CT" rm -f "$OPS_CONTAINER" >/dev/null 2>&1 || true
        "$CT" volume rm "$OPS_VOLUME" >/dev/null 2>&1 || true
    fi
    [ "$bad" -eq 0 ] && echo "smoke: OK" || echo "smoke: FAILED" >&2
    return $bad
}

case "${1:-}" in
    up) shift; cmd_up "$@" ;;
    down) shift; cmd_down "$@" ;;
    reset) shift; cmd_reset "$@" ;;
    run) shift; cmd_run "$@" ;;
    claim) shift; cmd_claim "$@" ;;
    sh) shift; cmd_sh "$@" ;;
    scan) shift; cmd_scan "$@" ;;
    doctor) shift; cmd_doctor "$@" ;;
    smoke) shift; cmd_smoke "$@" ;;
    *) sed -n '2,20p' "$0"; exit 2 ;;
esac
