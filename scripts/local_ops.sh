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
#   scripts/local_ops.sh approve <id>       approve exactly one awaiting order
#   scripts/local_ops.sh approve --all      explicitly approve every awaiting order
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

# The toolchain installer (install-toolchain.sh) downloads pinned scanners into
# HARNESS_BIN_DIR (default ~/.local/bin). Keep it on PATH for every rig command
# so engine claims can run them even when the operator's shell profile doesn't.
# HOME can be unset (stripped CI environments); then there is no default bin
# dir to add, and the script must still dispatch — cleanup subcommands included.
OPS_BIN_DIR="${HARNESS_BIN_DIR:-${HOME:+$HOME/.local/bin}}"
if [ -n "$OPS_BIN_DIR" ]; then
    export PATH="$OPS_BIN_DIR:$PATH"
fi

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

    # The deterministic lanes' scanners, both named in the allowlist below:
    # manifest_sbom's syft and the observation tripwire's gitleaks (the pack
    # makes gitleaks a required tool for repo_state, so a fresh host without
    # it cannot even observe). A fresh host has neither: provision them
    # through the same pinned, checksum-verified download CI uses
    # (install-toolchain.sh's local-ops profile) instead of letting the
    # orders fail at claim time with an unexplained gap.
    if ! command -v syft >/dev/null 2>&1 || ! command -v gitleaks >/dev/null 2>&1; then
        # A failed download still falls through to the actionable message below.
        bash scripts/install-toolchain.sh local-ops || true
    fi
    local binary
    for binary in syft gitleaks; do
        command -v "$binary" >/dev/null 2>&1 || {
            echo "$binary is missing and could not be installed: the rig's orders need it." >&2
            echo "run: bash scripts/install-toolchain.sh local-ops" >&2
            echo "then make ops-up again (or add ${OPS_BIN_DIR:-the install-toolchain.sh bin dir} to PATH)" >&2
            return 1
        }
    done

    # Seed the rig's registry before install_traust can copy the shipped one.
    # The rig's key has no mythos-class entitlement; it proves the pipeline,
    # not audit quality. Generated once: operator edits survive every up.
    # Copy config/model-registry.yaml over it to restore shipped routing.
    if [ ! -f "$CONFIG_HOME/model-registry.yaml" ]; then
        mkdir -p "$CONFIG_HOME"
        OPS_REGISTRY_SRC="$REPO_ROOT/config/model-registry.yaml" \
        OPS_REGISTRY_OUT="$CONFIG_HOME/model-registry.yaml" uv run --no-sync python - <<'PYEOF'
import os

import yaml

with open(os.environ["OPS_REGISTRY_SRC"]) as f:
    registry = yaml.safe_load(f)
roles = registry.get("roles") or {}
models = {
    name: model
    for provider in (registry.get("providers") or {}).values()
    for name, model in (provider.get("models") or {}).items()
}
# Keep shipped approval priority, but require the exact tier: a model merely
# listed by a provider, a candidate, or an escalation above opus is ineligible.
opus = next(
    (
        name
        for role in roles.values()
        if role.get("floor") == "opus-class"
        for name in role.get("approved") or []
        if models.get(name, {}).get("tier") == "opus-class"
    ),
    None,
)
if opus is None:
    raise SystemExit(
        "cannot initialize the rig model registry: shipped registry has no "
        "approved opus-class model for an opus-class role"
    )
refloored = []
for name, role in roles.items():
    if role.get("floor") == "mythos-class":
        role["floor"] = "opus-class"
        role["approved"] = [opus]
        refloored.append(name)
header = (
    "# Generated by scripts/local_ops.sh (make ops-up): the rig's model registry.\n"
    "# RIG DEVIATION from the shipped config/model-registry.yaml: the roles\n"
    f"# {', '.join(refloored)} are re-floored to opus-class because the rig's\n"
    "# key has no mythos-class entitlement. Audit quality is NOT what the\n"
    "# rig proves. Generated once; edits survive up. Restore shipped routing\n"
    "# by copying the repo's config/model-registry.yaml over this file.\n"
)
with open(os.environ["OPS_REGISTRY_OUT"], "x") as f:
    f.write(header)
    yaml.safe_dump(registry, f, sort_keys=False)
print(f"model-registry.yaml: re-floored to opus-class: {', '.join(refloored)}")
PYEOF
    fi

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
# The deterministic lanes run through core's ProcessRunner, which runs only
# what is listed here: the manifest SBOM sweep's syft and the observation
# tripwire's gitleaks.
process:
  allowed_binaries: [syft, gitleaks]
EOF
    fi
    # A rig created before these grants has a traust.yaml without them — or
    # with a process section allowing other binaries (checkout's git): merge
    # the grants in so an upgraded rig runs the deterministic lanes (core's
    # ProcessRunner refuses unlisted binaries). Idempotent: a no-op for
    # binaries already allowed, and it keeps every operator addition.
    # The ledger joins the same pass: the rig's dev keypair (cosign) signs the
    # proof chain's layers; without cosign the layers record unsigned, but the
    # ledger is configured either way (ledger_audit stops refusing). A cosign
    # that is installed but fails is loud, never a silent unsigned fallback.
    OPS_CONFIG="$CONFIG_HOME/traust.yaml" OPS_LEDGER_DIR="$RUN_DIR/ledger" uv run --no-sync python - <<'PYEOF'
import os
import shutil
import subprocess
from pathlib import Path

import yaml

path = os.environ["OPS_CONFIG"]
with open(path) as f:
    cfg = yaml.safe_load(f) or {}
process = cfg.get("process") or {}
binaries = process.get("allowed_binaries") or []
added = [b for b in ("syft", "gitleaks") if b not in binaries]
if added:
    binaries.extend(added)
    process["allowed_binaries"] = binaries
    cfg["process"] = process
    print(f"traust.yaml: granted process.allowed_binaries {', '.join(added)}")
ledger = cfg.get("ledger")
key = Path(os.environ["OPS_LEDGER_DIR"]) / "dev-key.key"
pub = key.with_suffix(".pub")
# A non-empty operator section owns signing. Only check the rig's pair when
# bootstrapping it or when an earlier up configured that same private identity.
rig_configured = isinstance(ledger, dict) and (
    ledger.get("key_path") == str(key) or ledger.get("public_key_path") == str(pub)
)
if ledger in (None, {}) or rig_configured:
    complete = all(p.is_file() and p.stat().st_size > 0 for p in (key, pub))
    recovery = (
        f"Restore the matching non-empty key pair at {key} and {pub}. "
        "For a missing public key, restore it from backup or derive it from the "
        "existing private key with cosign public-key --key into a separate file. "
        "Never regenerate over an existing private key."
    )
    if not complete and (
        rig_configured or any(p.exists() or p.is_symlink() for p in (key, pub))
    ):
        raise SystemExit(f"The rig's ledger key pair is incomplete. {recovery}")
    if not complete:
        cosign = shutil.which("cosign")
        if cosign is not None:
            key.parent.mkdir(parents=True, exist_ok=True)
            result = subprocess.run(
                [cosign, "generate-key-pair", "--output-key-prefix", str(key.with_suffix(""))],
                env={**os.environ, "COSIGN_PASSWORD": ""},
                stdout=subprocess.DEVNULL,
                check=False,
            )
            if result.returncode:
                raise SystemExit(
                    f"cosign generate-key-pair failed (exit {result.returncode}); "
                    f"fix cosign before retrying make ops-up. {recovery}"
                )
            complete = all(p.is_file() and p.stat().st_size > 0 for p in (key, pub))
            if not complete:
                raise SystemExit(
                    f"cosign did not create a complete, non-empty ledger key pair. {recovery}"
                )
    if ledger in (None, {}):
        # Upgrade the rig's unsigned placeholder, never an operator's settings.
        if complete:
            cfg["ledger"] = {"key_path": str(key), "public_key_path": str(pub)}
            print("traust.yaml: ledger configured, layers signed by the rig's dev key")
        else:
            cfg["ledger"] = {}
            print("traust.yaml: cosign is not installed; ledger layers deliberately unsigned")
with open(path, "w") as f:
    yaml.safe_dump(cfg, f, sort_keys=False)
PYEOF
    mkdir -p "$RUN_DIR/home" "$RUN_DIR/workspace/inputs" "$RUN_DIR/analysis-results" \
        "$RUN_DIR/progress-tracker" "$OPS_DIR/pack"
    pack_overlay > "$OPS_DIR/pack/assets.yaml"

    # Repo-config isolation keeps checkout hooks/config out of headless sessions.
    # These tool grants and Read denials are defense in depth, not a sandbox:
    # granted Python/Bash can still access inherited credentials and host files.
    # Use disposable rig credentials; deployments need an execution boundary,
    # a scrubbed tool environment and enforced egress policy.
    if [ ! -f "$CONFIG_HOME/claude-runner/settings.json" ]; then
        mkdir -p "$CONFIG_HOME/claude-runner"
        cat > "$CONFIG_HOME/claude-runner/settings.json" <<'EOF'
{
  "permissions": {
    "allow": [
      "Bash(git:*)",
      "Bash(syft:*)",
      "Bash(gitleaks:*)",
      "Bash(grype:*)",
      "Bash(opengrep:*)",
      "Bash(govulncheck:*)",
      "Bash(python3:*)",
      "Bash(gh api:*)",
      "Bash(tokei:*)",
      "Bash(cloc:*)",
      "Bash(scc:*)",
      "WebFetch(domain:api.github.com)",
      "WebFetch(domain:osv.dev)",
      "WebFetch(domain:deps.dev)",
      "Read",
      "Write",
      "Edit",
      "Glob",
      "Grep"
    ],
    "deny": [
      "Read(./.local-ops/env)",
      "Read(**/.local-ops/env)",
      "Read(**/.local-ops/run/ledger/**)",
      "Read(~/.claude/.credentials.json)",
      "Read(~/.ssh/**)",
      "Read(~/.aws/**)"
    ]
  }
}
EOF
        echo "claude-runner: scoped tool grants and Read denials configured; environment is not isolated"
    fi

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

cmd_approve() {
    # Approval is an explicit human action; omission must never mean approve all.
    if [ "$#" -ne 1 ] || [ -z "${1:-}" ]; then
        echo "usage: scripts/local_ops.sh approve <id-prefix> | --all" >&2
        return 2
    fi
    local selector="$1"
    case "$selector" in
        --all) ;;
        *[!A-Za-z0-9_-]*)
            echo "order selector must be an id prefix (alphanumeric): $selector" >&2
            return 2
            ;;
    esac
    source_env
    TRAUST_CONFIG_HOME="$CONFIG_HOME" uv run --no-sync python - "$selector" <<'PYEOF'
import sys
from traust.context import load, load_caller
from traust_core.v1.errors import TraustError
from traust_core.v1.models.common import every_item
from traust_core.v1.models.operations import OrderFilter, OrderState

core = load(None)
caller = load_caller(core)
services = core.services()
awaiting = list(every_item(lambda p: services.ops.list(OrderFilter(states=(OrderState.AWAITING_APPROVAL,)), p)))
only = sys.argv[1]
approve_all = only == "--all"
if not approve_all:
    matching = [o for o in awaiting if str(o.id).startswith(only)]
    if len(matching) > 1:
        print(f"prefix {only} names {len(matching)} awaiting orders; approve by a longer prefix:", file=sys.stderr)
        for o in matching:
            repo = services.portfolio.get_repository(o.repository_id) if o.repository_id else None
            label = repo.url if repo else o.asset
            print(f"  {o.id} {o.asset}: {label}", file=sys.stderr)
        sys.exit(2)
    awaiting = matching
if not awaiting:
    print("no orders awaiting approval" if approve_all else f"no awaiting order {only}")
    sys.exit(0)
for order in awaiting:
    repo = services.portfolio.get_repository(order.repository_id) if order.repository_id else None
    label = repo.url if repo else order.asset
    try:
        approved = services.ops.approve(order.id, caller)
        print(f"approved {order.asset}: {label} ({approved.state})")
    except TraustError as e:
        print(f"skipped {order.asset}: {label} ({e})", file=sys.stderr)
        sys.exit(1)
PYEOF
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
    # The venv is the rig's truth: a `uv sync` between commands can silently
    # swap traust-core (and strip the engine) to whatever that checkout's lock
    # held — the 2026-11-02 fleet run observed a pre-fix core this way and its
    # orders wrote nothing. The doctor asserts what is installed matches what
    # THIS checkout's lock resolves, the only code the rig claims to run.
    OPS_EXPECTED_ENGINE="$OPS_ENGINE_SRC" uv run --no-sync python - <<'PYEOF'
import json
import os
import sys
import tomllib
from importlib.metadata import distribution
from pathlib import Path

bad = 0
lock = Path("uv.lock")
expected = {}
if lock.is_file():
    doc = tomllib.loads(lock.read_text())
    for pkg in doc.get("package", []):
        if pkg["name"] in ("traust-core", "traust-engine"):
            source = pkg.get("source") or {}
            rev = source.get("rev") or source.get("git") or ""
            if "#" in rev:
                rev = rev.split("#")[-1]
            elif "?rev=" in rev:
                rev = rev.split("?rev=")[-1]
            if rev:
                expected[pkg["name"]] = rev[:40]
for name in ("traust-core", "traust-engine"):
    try:
        installed = distribution(name)
    except Exception:
        print(f"{name}: NOT installed (make ops-up)", file=sys.stderr)
        bad = 1
        continue
    direct = json.loads((Path(installed._path) / "direct_url.json").read_text())
    commit = (direct.get("vcs_info") or {}).get("commit_id")
    want = expected.get(name)
    if want and commit and not commit.startswith(want):
        print(
            f"{name}: STALE — venv has {commit[:12]}, this checkout's lock wants {want[:12]};"
            " a uv sync swapped it (make ops-up restores)",
            file=sys.stderr,
        )
        bad = 1
    else:
        print(f"{name}: {commit[:12] if commit else 'installed (no vcs info)'}")
engine_src = os.environ.get("OPS_EXPECTED_ENGINE", "")
if engine_src and "@" in engine_src:
    want = engine_src.split("@", 1)[1][:12]
    try:
        installed = distribution("traust-engine")
        direct = json.loads((Path(installed._path) / "direct_url.json").read_text())
        commit = (direct.get("vcs_info") or {}).get("commit_id") or ""
        if not commit.startswith(want):
            print(
                f"traust-engine: PIN MISMATCH — venv has {commit[:12]}, the rig pins {want};"
                " make ops-up reinstalls",
                file=sys.stderr,
            )
            bad = 1
    except Exception:
        pass
sys.exit(bad)
PYEOF
    [ $? -ne 0 ] && bad=1
    # The DB volume and the artifacts dir age together: a volume that survives
    # a worktree removal holds rows pointing at artifacts that no longer exist
    # (orders refuse not_found; claims can crash on unregistered degraded keys).
    if container_running && [ -d "$OPS_DIR/run/artifacts" ]; then
        OPS_DB_CREATED=$(podman volume inspect "$OPS_VOLUME" --format '{{.CreatedAt}}' 2>/dev/null | cut -d" " -f1)
        OPS_ARTIFACTS_CREATED=$(stat -f "%Sm" -t "%Y-%m-%d" "$OPS_DIR/run/artifacts" 2>/dev/null)
        if [ -n "$OPS_DB_CREATED" ] && [ -n "$OPS_ARTIFACTS_CREATED" ] \
            && [ "$OPS_DB_CREATED" != "$OPS_ARTIFACTS_CREATED" ]; then
            echo "warning: DB volume ($OPS_DB_CREATED) and artifacts ($OPS_ARTIFACTS_CREATED) disagree in age —" >&2
            echo "         one survived a reset the other did not; make ops-reset realigns them" >&2
        fi
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
    approve) shift; cmd_approve "$@" ;;
    run) shift; cmd_run "$@" ;;
    claim) shift; cmd_claim "$@" ;;
    sh) shift; cmd_sh "$@" ;;
    scan) shift; cmd_scan "$@" ;;
    doctor) shift; cmd_doctor "$@" ;;
    smoke) shift; cmd_smoke "$@" ;;
    *) sed -n '2,20p' "$0"; exit 2 ;;
esac
