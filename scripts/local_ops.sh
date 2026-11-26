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
OPS_ENGINE_SRC="${OPS_ENGINE_SRC:-git+https://github.com/traust-security/traust-engine@b9b438574afa582908c42e4bb234f974bdeb80e2}"

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
    if [ "${OPS_SIGNED_SMOKE:-}" = 1 ]; then
        # A working import doesn't identify a build; don't reuse a cached local wheel either.
        uv pip install --no-deps --reinstall --no-cache "$OPS_ENGINE_SRC" >/dev/null
    else
        if uv run --no-sync python - "$OPS_ENGINE_SRC" <<'PY' >/dev/null 2>&1
import importlib.metadata, json, re, sys
import traust_engine  # noqa: F401
src = sys.argv[1]
m = re.search(r"@([0-9a-f]{40})(?:$|[#?])", src)
if not m:
    sys.exit(0)
raw = importlib.metadata.distribution("traust-engine").read_text("direct_url.json") or "{}"
commit = (json.loads(raw).get("vcs_info") or {}).get("commit_id")
sys.exit(0 if commit == m.group(1) else 1)
PY
        then
            return 0
        fi
        echo "installing traust-engine from $OPS_ENGINE_SRC"
        uv pip install --no-deps --reinstall --no-cache "$OPS_ENGINE_SRC" >/dev/null
    fi
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

# The claim's label opt-in, one probe per command: `--label llm` on an engine
# that knows the runner-label vocabulary, nothing on one that does not. The
# label is an include, not a filter — with it the claim still leases every
# deterministic asset and adds the llm-labeled skill sessions, which the rig
# (the one claim host that carries the agent harness, claude under the config
# home's claude-runner) is also the executor of; the deployed claim workers
# claim without it and leave those orders to the runner pools. The engine pin
# can trail the vocabulary's engine PR, and a pre-vocabulary engine rejects
# the flag outright (argparse exit 2, nothing leased — the smoke's drain
# would never idle), while its plain claim already takes every asset, labels
# or none. Probing --help keeps the rig draining both classes on either
# engine; when the pin passes the vocabulary, the probe simply always wins.
claim_label_args() {
    if engine claim --help 2>&1 | grep -q -- '--label'; then
        printf '%s\n' --label llm
    fi
}

source_env() {
    # shellcheck disable=SC1090
    [ -f "$REPO_ROOT/$OPS_DIR/env" ] && . "$REPO_ROOT/$OPS_DIR/env" || true
    if [ -f "$RUN_DIR/review-salt" ]; then
        export TRAUST_OPS_VALVE_SALT
        TRAUST_OPS_VALVE_SALT=$(cat "$RUN_DIR/review-salt")
    fi
    # A rig-generated key has an empty passphrase. Without an explicit value
    # cosign may prompt on the tick/claim host. Leave operator-owned keys alone.
    local dev_key="$RUN_DIR/ledger/dev-key.key"
    if [[ -z "${COSIGN_PASSWORD+set}" && -f "$dev_key" && -f "$CONFIG_HOME/traust.yaml" ]] &&
        uv run --no-sync python - "$CONFIG_HOME/traust.yaml" "$dev_key" <<'PY'
import sys
from pathlib import Path
import yaml

ledger = yaml.safe_load(Path(sys.argv[1]).read_text()).get("ledger") or {}
sys.exit(0 if ledger.get("key_path") == sys.argv[2] else 1)
PY
    then
        export COSIGN_PASSWORD=""
    fi
    return 0
}

cmd_up() {
    umask 077
    # Refuse redirected rig paths before creating keys, credentials, or config.
    local part path="$REPO_ROOT"
    local -a rig_parts
    IFS='/' read -r -a rig_parts <<< "$OPS_DIR/run/home"
    for part in "${rig_parts[@]}"; do
        [ -n "$part" ] || continue
        path="$path/$part"
        if [ -L "$path" ]; then
            echo "local rig path must not contain symlinks: $path" >&2
            return 1
        fi
    done
    for path in "$RUN_DIR/home/local-key.pem" "$RUN_DIR/home/local-jwks.json"; do
        if [ -L "$path" ]; then
            echo "local rig issuer must not use a symlink: $path" >&2
            return 1
        fi
    done
    if ! container_running; then
        if "$CT" ps -a --format '{{.Names}}' 2>/dev/null | grep -qx "$OPS_CONTAINER"; then
            "$CT" start "$OPS_CONTAINER" >/dev/null
        else
            echo "starting $OPS_CONTAINER ($OPS_IMAGE) on 127.0.0.1:$OPS_PORT"
            POSTGRES_PASSWORD="$OPS_DB_PASS" "$CT" run --name "$OPS_CONTAINER" -d \
                -e POSTGRES_USER="$OPS_DB_USER" -e POSTGRES_PASSWORD \
                -e POSTGRES_DB="$OPS_DB_NAME" \
                -p "127.0.0.1:${OPS_PORT}:5432" \
                -v "$OPS_VOLUME:/var/lib/postgresql/data" \
                "$OPS_IMAGE" >/dev/null
        fi
    fi
    wait_for_db

    uv sync --locked --quiet
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
import secrets
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
            cfg["ledger"] = {"key_path": str(key), "public_key_path": str(pub), "required": True}
            print("traust.yaml: ledger configured, layers signed by the rig's dev key")
        else:
            cfg["ledger"] = {}
            print("traust.yaml: cosign is not installed; ledger layers deliberately unsigned")
    elif ledger.get("key_path") == str(key) and ledger.get("public_key_path") == str(pub):
        # Rigs created before required signing already have both paths. Do not rotate them.
        ledger.setdefault("required", True)
if "review" not in cfg:
    salt = key.parent.parent / "review-salt"
    salt.parent.mkdir(parents=True, exist_ok=True)
    if not salt.exists():
        with os.fdopen(os.open(salt, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as f:
            f.write(secrets.token_hex(32))
    cfg["review"] = {"valve_salt_env": "TRAUST_OPS_VALVE_SALT"}
if cfg.get("home") != str(key.parent.parent / "home") or (
    (cfg.get("identity") or {}).get("trust_local") is not True
):
    raise SystemExit("local rig bootstrap requires its own home and trusted local issuer")
if os.environ.get("OPS_SIGNED_SMOKE") == "1":
    if not cfg.get("ledger", {}).get("key_path"):
        raise SystemExit("ops-smoke requires the rig's cosign key pair")
    cfg["ledger"]["required"] = True
else:
    # Only initialize a missing policy. An operator-supplied allowlist (even empty) owns access.
    cfg.setdefault("recording", {
        "assessment": ["full_audit"], "triage": ["sci_triage"],
        "validation": ["external_report_validation"], "verification": ["verify_remediation"],
    })
with open(path, "w") as f:
    yaml.safe_dump(cfg, f, sort_keys=False)
PYEOF
    mkdir -p "$RUN_DIR/home" "$RUN_DIR/workspace/inputs" "$RUN_DIR/analysis-results" \
        "$RUN_DIR/progress-tracker" "$OPS_DIR/pack"
    # The doctor compares the DB volume's age with the artifacts tree's; that tree's own
    # mtime moves whenever an artifact lands, so the rig marks its birth once instead.
    if [ ! -e "$RUN_DIR/.artifacts-created" ]; then
        : >>"$RUN_DIR/.artifacts-created"
    fi
    # The events file must exist (a missing one is refused). Created empty, never truncated:
    # events an operator appends to the rig survive the next up — under the analysis-results
    # the rig's traust.yaml configures, which an operator may have pointed elsewhere.
    # The same resolver the intake uses (core's locations, not a raw YAML read that could
    # diverge from it), failing loudly on a config that cannot be read or resolved.
    EVENTS_DIR=$(TRAUST_CONFIG_HOME="$CONFIG_HOME" uv run --no-sync python - <<'PY'
from traust.context import findings_tree_dir, load

print(findings_tree_dir(load()))
PY
)
    mkdir -p "$EVENTS_DIR/_manifest"
    : >>"$EVENTS_DIR/_manifest/rescan-events.jsonl"
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
      "Read(**/.local-ops/run/recorder.token)",
      "Read(**/.local-ops/run/home/credentials.json)",
      "Read(**/.local-ops/run/review-salt)",
      "Read(~/.claude/.credentials.json)",
      "Read(~/.ssh/**)",
      "Read(~/.aws/**)"
    ]
  }
}
EOF
        echo "claude-runner: scoped tool grants and Read denials configured; environment is not isolated"
    fi

    # Fresh Postgres needs both the baseline and the channel; Core gates existing stores.
    OPS_DSN="$OPS_DSN" uv run --no-sync python - <<'PYEOF'
import os
from traust_core.v1 import contracts
from traust_core.v1.context import Config, Context, DatabaseConfig, StoreState
from traust_core.v1.repositories import apply_schema, on_driver_connection

context = Context(Config(database=DatabaseConfig(url=os.environ["OPS_DSN"])))
fresh = context.store_status().state is StoreState.EMPTY
engine = context.database
if fresh:
    dialect = context.dialect
    apply_schema(engine, contracts.database_ddl(dialect))
    on_driver_connection(engine, lambda dbapi: contracts.run_db_upgrades(dbapi, dialect))
    print("database contract applied")
else:
    print("database contract already current")
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

    # The rig's isolated home was checked above. Preserve existing entries,
    # including dangling symlinks, rather than replacing an operator's login.
    if [ ! -e "$RUN_DIR/home/credentials.json" ] && \
        [ ! -L "$RUN_DIR/home/credentials.json" ]; then
        TRAUST_CONFIG_HOME="$CONFIG_HOME" uv run --no-sync python -m traust.cli auth local \
            --identity "${USER:-$(id -un)}@local-rig" >/dev/null
    else
        echo "human login preserved in the rig home"
        echo "use make ops-sh and traust auth status; renew or create the login explicitly if needed"
        echo "for a local login: traust auth local --identity YOUR_IDENTITY; for an external login use its renewal flow"
    fi
    if [[ "${OPS_SIGNED_SMOKE:-}" != 1 ]]; then
        uv run --no-sync python - "$CONFIG_HOME/traust.yaml" "$RUN_DIR" <<'PY'
import sys
from pathlib import Path
from tempfile import NamedTemporaryFile

from traust_core.v1.context import Context

run = Path(sys.argv[2])
core = Context.from_file(Path(sys.argv[1]))
credential = core.local_issuer.mint("local-ops-recorder", machine=True)
with NamedTemporaryFile(dir=run, mode="w", delete=False) as out:
    out.write(credential.token.get_secret_value())
Path(out.name).replace(run / "recorder.token")
PY
    fi

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
    source_env
    engine run --router traust.ops.router:SecurityRouter --every "$OPS_EVERY"
}

cmd_claim() {
    source_env
    if (( $# > 1 )) || [[ $# == 1 && $1 != --once ]]; then
        echo "usage: scripts/local_ops.sh claim [--once]" >&2
        return 2
    fi
    export TRAUST_RECORDER_TOKEN_FILE="$RUN_DIR/recorder.token"
    local worker
    worker=$(TRAUST_CONFIG_HOME="$CONFIG_HOME" uv run --no-sync python - <<'PY'
from traust.context import load, load_recorder

print(load_recorder(load()).ref)
PY
)
    # The rig claims both executor classes: it is the one claim host that
    # carries the agent harness (claude under the config home's claude-runner),
    # so its claim loop is also the skill lanes' executor — the deployed claim
    # workers have no harness and leave llm-labeled assets to the runner pools.
    # claim_label_args probes the installed engine for the label opt-in.
    local -a labels=()
    mapfile -t labels < <(claim_label_args)
    if [[ "${1:-}" == --once ]]; then
        engine claim --worker "$worker" "${labels[@]}"
        return
    fi
    while true; do
        engine claim --worker "$worker" "${labels[@]}" || true
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

installed_revisions() {
    # Use the interpreter that will run the rig, including the --no-deps
    # engine. The same checker reads the candidate manifests and PEP 610 data.
    OPS_ENGINE_SRC="$OPS_ENGINE_SRC" uv run --no-sync python "$SCRIPT_DIR/check_ops_pins.py" "$@"
}

cmd_doctor() {
    local bad=0
    if container_running; then
        echo "Postgres: running ($OPS_CONTAINER :$OPS_PORT)"
    else
        echo "Postgres: NOT running (make ops-up)" >&2; bad=1
    fi
    installed_revisions --doctor || bad=1
    # The DB volume and the artifacts dir age together: a volume that survives
    # a worktree removal holds rows pointing at artifacts that no longer exist
    # (orders refuse not_found; claims can crash on unregistered degraded keys).
    if container_running && [ -e "$OPS_DIR/run/.artifacts-created" ]; then
        # Podman prints "2026-11-04 12:00:00 +00:00 UTC", Docker RFC3339 "2026-11-04T12:00:00Z":
        # the first ten characters are the date either way (a space cut would keep Docker's
        # whole timestamp and warn on every healthy Docker rig).
        OPS_DB_CREATED=$("$CT" volume inspect "$OPS_VOLUME" --format '{{.CreatedAt}}' 2>/dev/null | cut -c1-10)
        OPS_ARTIFACTS_CREATED=$(uv run --no-sync python -c \
            'import datetime, os, sys; print(datetime.datetime.fromtimestamp(os.path.getmtime(sys.argv[1]), datetime.UTC).strftime("%Y-%m-%d"))' \
            "$OPS_DIR/run/.artifacts-created" 2>/dev/null)
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

smoke_sql() {
    "$CT" exec "$OPS_CONTAINER" psql -X -v ON_ERROR_STOP=1 \
        -U "$OPS_DB_USER" -d "$OPS_DB_NAME" -tAc "$1"
}

smoke_expect() {
    local got
    got=$(smoke_sql "$2")
    if [[ "$got" != "$1" ]]; then
        printf 'smoke: expected <%s>, got <%s> from: %s\n' "$1" "$got" "$2" >&2
        return 1
    fi
}

smoke_uuid() {
    [[ "$1" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] ||
        { echo "smoke: expected one UUID, got <$1>" >&2; return 1; }
}

smoke_records() {
    uv run --no-sync python scripts/ops_smoke/records.py "$@"
}

smoke_audit() {
    local finding
    finding=$(cat "$RUN_DIR/smoke-finding-id")
    smoke_uuid "$finding"
    smoke_expect 3 "select count(*) from traust.decision"
    smoke_expect 3 "select count(*) from traust_ledger.events"
    smoke_expect 3 "select count(*) from traust.decision d
        join traust.finding f on f.id = d.finding_id
        join traust_ledger.events e on e.decision_id = d.id
        join traust_ledger.layers l on l.id = e.layer_id and l.repository_id = f.repository_id
        where f.id = '$finding' and l.merkle_root_signature <> ''
        and convert_from(e.event_payload, 'UTF8')::jsonb ->> 'id' = d.id::text"
    smoke_expect 1 "select count(*) from traust_ops.run_order where asset='ledger_audit'
        and state='succeeded' and lease_generation=1 and completed_by='machine:smoke-recorder'
        and started_at >= (select max(created_at) from traust.decision)"
    # This fault is visible to the next scheduled claim, never to the normal rig.
    smoke_sql "begin;
        alter table traust_ledger.events disable trigger ledger_events_reject_mutation;
        update traust_ledger.events set event_payload = convert_to('{}', 'UTF8')
        where decision_id = (select id from traust.decision where finding_id = '$finding' order by id limit 1);
        alter table traust_ledger.events enable trigger ledger_events_reject_mutation;
        commit;" >/dev/null
    # Pass two must run the real audit, record degraded on its order AND persist
    # the failed-layer count (checked at the end, not inferred from an exit code).
}

smoke_teardown() {
    "$CT" rm -f "$OPS_CONTAINER" >/dev/null 2>&1 || true
    "$CT" volume rm "$OPS_VOLUME" >/dev/null 2>&1 || true
}

smoke_wait_db() {
    local description=$1 sql=$2 answer _
    for _ in $(seq 1 80); do
        answer=$(smoke_sql "$sql")
        [[ "$answer" = t ]] && return 0
        [[ "$answer" = f ]] || { echo "smoke: missing $description" >&2; return 1; }
        sleep 1
    done
    echo "smoke: timed out waiting for $description" >&2; return 1
}

smoke_snapshot() {
    local asset=$1 order=$2 sbom
    if [[ "$asset" = manifest_sbom ]]; then
        sbom=$(uv run --no-sync python -c \
            'import json,sys; r=json.load(sys.stdin); [sbom]=r["written"]; sys.exit(1) if r["outcome"]!="succeeded" else print(sbom)' \
            < "$RUN_DIR/$asset.receipt")
        smoke_uuid "$sbom" || return 1
        smoke_sql "select r.id, a.id, s.id, c.id, d.id
            from traust_ops.run_order o join traust.repository_ref r on r.repository_id=o.repository_id
            join traust.assessment a on a.id=r.manifest_sbom_assessment_id and a.repository_ref_id=r.id
                and a.run_order_id=o.id
            join traust.sbom s on s.id=r.manifest_sbom_id
            join traust.artifact c on c.assessment_id=a.id and c.kind='manifest-coverage'
            join traust.dependency d on d.sbom_id=s.id join traust.package p on p.id=d.package_id
            where o.id='$order' and o.asset='manifest_sbom' and r.is_default and r.sha=repeat('a',40)
            and a.kind='manifest_sbom' and a.assessor='traust-manifest-coverage' and a.assessor_version='2'
            and s.id='$sbom' and p.ecosystem='pypi' and p.name='packaging' and d.version='24.2'"
    elif [[ "$asset" = smoke_authored ]]; then
        smoke_sql "select a.id, c.id, f.id, x.id, l.id,
            (select count(*) from traust.assessment where kind='secure_code'),
            (select count(*) from traust.artifact where digest=c.digest),
            (select count(*) from traust.finding), (select count(*) from traust.occurrence),
            (select count(*) from traust.location)
            from traust_ops.run_order o join traust.assessment a on a.run_order_id=o.id
            join traust.repository_ref r on r.id=a.repository_ref_id and r.repository_id=o.repository_id
            join traust.artifact c on c.assessment_id=a.id
            join traust.occurrence x on x.assessment_id=a.id join traust.finding f on f.id=x.finding_id
            join traust.location l on l.occurrence_id=x.id
            where o.id='$order' and o.asset='smoke_authored' and a.kind='secure_code'
            and r.is_default and r.sha=repeat('a',40) and f.repository_id=r.repository_id
            and f.title='Synthetic dependency review marker' and x.severity='high'
            and l.path='requirements.txt' and l.line_start=1"
    else
        smoke_sql "select a.id, c.id, d.id, e.id,
            (select count(*) from traust.assessment where kind='triage'),
            (select count(*) from traust.artifact where kind='triage'),
            (select count(*) from traust.decision), (select count(*) from traust_ledger.events)
            from traust.assessment a join traust.artifact c on c.assessment_id=a.id
            join traust.decision d on d.assessment_id=a.id and d.artifact_id=c.id
            join traust_ledger.events e on e.decision_id=d.id
            where a.run_order_id='$order' and a.kind='triage' and c.kind='triage'
            and d.validity='confirmed' and d.severity='critical'"
    fi
}

smoke_crash() {
    local asset=$1 order snapshot generation worker
    order=$(cat "$RUN_DIR/$asset.order")
    smoke_uuid "$order"
    generation=$(cat "$RUN_DIR/$asset.generation")
    worker=$(cat "$RUN_DIR/$asset.worker")
    smoke_expect "$worker|$generation" "select lease_holder,lease_generation
        from traust_ops.run_order where id='$order'"
    smoke_expect 1 "select count(*) from traust_ops.run_order o join traust.repository r
        on r.id=o.repository_id where o.id='$order' and o.asset='$asset'
        and r.url='$good' and o.state='leased' and o.finished_at is null"
    snapshot=$(smoke_snapshot "$asset" "$order")
    [[ -n "$snapshot" && "$snapshot" != *$'\n'* ]] ||
        { echo "smoke: $asset has no unique committed record before expiry" >&2; return 1; }
    printf '%s\n' "$snapshot" > "$RUN_DIR/$asset.before"
    echo "smoke: $asset committed under lease $order generation $generation; waiting for natural expiry"
    smoke_wait_db "$asset lease expiry" "select lease_expires_at <= statement_timestamp()
        from traust_ops.run_order where id='$order' and state='leased'"
}

run_with_timeout() {
    local limit=$1
    shift
    python3 -c '
import os, signal, subprocess, sys
limit = float(sys.argv[1].rstrip("s"))
proc = subprocess.Popen(sys.argv[2:], start_new_session=True)
def _terminate(signum, _frame):
    try:
        os.killpg(proc.pid, signum)
    except ProcessLookupError:
        pass
    sys.exit(128 + signum)
for sig in (signal.SIGINT, signal.SIGTERM):
    signal.signal(sig, _terminate)
try:
    sys.exit(proc.wait(timeout=limit))
except subprocess.TimeoutExpired:
    os.killpg(proc.pid, signal.SIGTERM)
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        os.killpg(proc.pid, signal.SIGKILL)
        proc.wait()
    sys.exit(124)
' "$limit" "$@"
}

smoke_drain() {
    local crash_asset=$1 worker=$2 stop_after=${3:-} claim rc _
    for _ in $(seq 1 16); do
        rc=0
        claim=$(run_with_timeout 180s bash "$SCRIPT_DIR/local_ops.sh" smoke-engine \
            claim --worker "$worker" --lease 1m) || rc=$?
        case "$rc" in
            137)
                [[ -n "$crash_asset" && ! -e "$RUN_DIR/$crash_asset.before" ]] ||
                    { echo 'smoke: unexpected claim termination' >&2; return 1; }
                smoke_crash "$crash_asset"
                ;;
            0)
                if [[ "$claim" = '{"claimed": null}' ]]; then return 0; fi
                echo "smoke: $claim"
                if [[ -n "$stop_after" && "$(smoke_sql "select state from traust_ops.run_order
                    where id='$stop_after'")" = succeeded ]]; then return 0; fi
                ;;
            1|4)
                # Only the deliberate source failure and scheduled tamper audit
                # may finish non-green. Check the persisted subject/reason below.
                if ! uv run --no-sync python -c '
import json, sys
r = json.load(sys.stdin)
expected = {"1": ("manifest_sbom", "failed", "source_unavailable"), "4": ("ledger_audit", "degraded", None)}
sys.exit(0 if (r["asset"], r["state"], r["reason"]) == expected[sys.argv[1]] else str(r))
' "$rc" <<<"$claim"; then
                    if [[ -s "$RUN_DIR/$crash_asset.stderr" ]]; then cat "$RUN_DIR/$crash_asset.stderr" >&2; fi
                    return 1
                fi
                ;;
            *) printf 'smoke: claim exited %s: %s\n' "$rc" "$claim" >&2; return 1 ;;
        esac
    done
    echo "smoke: claim limit reached" >&2; return 1
}

smoke_replayed() {
    local asset=$1 order generation worker
    order=$(cat "$RUN_DIR/$asset.order")
    smoke_uuid "$order"
    generation=$(cat "$RUN_DIR/$asset.replayed-generation")
    worker=$(cat "$RUN_DIR/$asset.worker")
    smoke_expect "succeeded|$worker|$generation" "select state,completed_by,lease_generation
        from traust_ops.run_order where id='$order' and asset='$asset'"
    cmp "$RUN_DIR/$asset.order" "$RUN_DIR/$asset.replayed"
    smoke_snapshot "$asset" "$order" > "$RUN_DIR/$asset.after"
    cmp "$RUN_DIR/$asset.before" "$RUN_DIR/$asset.after"
    echo "smoke: reclaimed $asset $order at generation $generation with unchanged receipts, rows and counts"
}

cmd_smoke() {
    [[ $# = 0 ]] || { echo "smoke takes no input or target overrides" >&2; return 2; }
    unset GITHUB_TOKEN GH_TOKEN GITLAB_TOKEN ANTHROPIC_API_KEY OPENAI_API_KEY TRAUST_TOKEN
    unset TRAUST_RUN_ID TRAUST_RECORDER_TOKEN_FILE
    if [[ "${OPS_ACCEPTANCE:-0}" = 1 ]]; then
        if [[ -n "${PYTHONPATH:-}" || -n "${PYTHONHOME:-}" ]]; then
            echo "smoke: unset PYTHONPATH and PYTHONHOME; acceptance must import the locked build" >&2
            return 2
        fi
        # Fail before creating a DB even when invoked without the Make wrapper.
        python3 "$SCRIPT_DIR/check_ops_pins.py" --preflight
    fi
    command -v cosign >/dev/null || {
        echo "smoke needs cosign (scripts/install-toolchain.sh ledger-signing)" >&2; return 2;
    }
    # Fresh names and config, even if the operator already has an ops-up rig.
    # An occupied host port fails startup; it never selects the existing DB.
    OPS_DIR=$(mktemp -d .local-ops-smoke.XXXXXXXX)
    OPS_CONTAINER="traust-${OPS_DIR#.}"
    OPS_VOLUME="$OPS_CONTAINER-data"
    CONFIG_HOME="$REPO_ROOT/$OPS_DIR/config"
    RUN_DIR="$REPO_ROOT/$OPS_DIR/run"
    export OPS_DIR OPS_CONTAINER OPS_VOLUME OPS_ENGINE_SRC OPS_PORT
    trap 'smoke_teardown; rm -rf -- "$OPS_DIR"' EXIT
    export OPS_SIGNED_SMOKE=1 COSIGN_PASSWORD=""
    cmd_up >/dev/null
    if [[ "${OPS_ACCEPTANCE:-0}" = 1 ]]; then
        installed_revisions
        TRAUST_TEST_DATABASE_URL="postgresql+psycopg://${OPS_DB_USER}:${OPS_DB_PASS}@127.0.0.1:${OPS_PORT}/${OPS_DB_NAME}" \
            python3 -m scripts.check_ops_recording
    else
        installed_revisions --probe
    fi
    source_env
    export TRAUST_CONFIG_HOME="$CONFIG_HOME" OPS_SMOKE_RUN="$RUN_DIR"
    export UV_OFFLINE=1
    export SYFT_CHECK_FOR_APP_UPDATE=false
    # Core's ProcessRunner otherwise strips the syft setting. Also deny HTTP
    # fallthrough outside the fixture opener, including from a tool subprocess.
    export http_proxy=http://127.0.0.1:1 https_proxy=http://127.0.0.1:1
    export HTTP_PROXY="$http_proxy" HTTPS_PROXY="$https_proxy" ALL_PROXY="$http_proxy"
    export no_proxy=localhost,127.0.0.1,::1 NO_PROXY=localhost,127.0.0.1,::1
    uv run --no-sync python - "$CONFIG_HOME/traust.yaml" <<'PY'
import sys
from pathlib import Path
import yaml

path = Path(sys.argv[1])
cfg = yaml.safe_load(path.read_text())
cfg["process"]["keep_env"] = [
    "PATH", "HOME", "LC_ALL", "LANG", "TMPDIR", "SYFT_CHECK_FOR_APP_UPDATE",
    "http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "no_proxy", "NO_PROXY",
]
path.write_text(yaml.safe_dump(cfg, sort_keys=False))
PY
    # Only this checked-in allowlist is planned or claimed; no live feeds, router,
    # checkout, approvals, LLM labels or security sessions. No operator env file.
    cp scripts/ops_smoke/assets.yaml "$OPS_DIR/pack/assets.yaml"
    local good=https://github.com/example/smoke-repo failed=https://github.com/example/smoke-failure
    local partial=https://github.com/example/smoke-containers
    local worker triage audit
    uv run --no-sync python scripts/ops_smoke/forge.py portfolio onboard \
        --product local-rig --label "Local rig" --repo "$good" --repo "$failed" --repo "$partial" |
        uv run --no-sync python -c 'import json,sys; r=json.load(sys.stdin); sys.exit(0 if len(r["repository_ids"])==3 and not r["skipped"] else str(r))'
    echo "smoke: first pass observes three fixture heads"
    run_with_timeout 180s bash "$SCRIPT_DIR/local_ops.sh" smoke-engine run --once
    # Leave the first tick's audit queued until it has a signed decision layer
    # to verify. Observation priority precedes triage, which precedes audit.
    local i
    for i in 1 2 3; do
        run_with_timeout 180s bash "$SCRIPT_DIR/local_ops.sh" smoke-engine \
            claim --worker smoke-observer --lease 1m
    done
    smoke_expect 3 "select count(*) from traust_ops.run_order where asset='repo_state' and state='succeeded'
        and completed_by='smoke-observer' and lease_generation=1"
    smoke_expect 1 "select count(*) from traust_ops.run_order where asset='ledger_audit' and state='queued'
        and lease_generation=0"

    # Triage depends on the completed authored assessment. Leave the scheduled
    # ledger audit queued across these two explicitly submitted recording orders.
    local authored
    authored=$(smoke_records submit-authored)
    smoke_uuid "$authored"
    worker=$(smoke_records worker)
    smoke_drain smoke_authored "$worker" "$authored"
    smoke_replayed smoke_authored
    smoke_expect '1|1|1' "select (select count(*) from traust.finding),
        (select count(*) from traust.occurrence), (select count(*) from traust.location)"
    triage=$(smoke_records prepare)
    smoke_uuid "$triage"
    smoke_drain smoke_triage "$worker"
    smoke_expect "$triage" "select id from traust_ops.run_order where asset='smoke_triage'"
    smoke_replayed smoke_triage
    smoke_audit
    smoke_wait_db 'scheduled audit cadence' "select finished_at + interval '1 minute' < statement_timestamp()
        from traust_ops.run_order where asset='ledger_audit' and state='succeeded'"

    echo "smoke: second pass scans fixture manifests and audits the edited event"
    run_with_timeout 180s bash "$SCRIPT_DIR/local_ops.sh" smoke-engine run --once
    smoke_drain manifest_sbom smoke-manifest
    smoke_replayed manifest_sbom
    # Exact order multiset: no unexpected, stuck, refused or extra successful orders.
    smoke_expect "$(printf '%s\n' 'ledger_audit|degraded|1' 'ledger_audit|succeeded|1' \
        'manifest_sbom|failed|1' 'manifest_sbom|succeeded|2' 'manifest_sbom|withheld|3' 'repo_state|succeeded|3' \
        'smoke_authored|succeeded|1' 'smoke_triage|succeeded|1')" \
        "select asset,state,count(*) from traust_ops.run_order group by 1,2 order by 1,2"
    smoke_expect 3 "select count(distinct repository_id) from traust_ops.run_order
        where asset='manifest_sbom' and state='withheld' and reason='upstream-stale' and lease_generation=0"
    smoke_expect 1 "select count(*) from traust_ops.run_order o join traust.repository r on r.id=o.repository_id
        where r.url='$failed' and o.asset='manifest_sbom' and o.state='failed' and o.reason='source_unavailable'
        and o.completed_by='smoke-manifest' and o.lease_generation=1"
    smoke_expect 1 "select count(*) from traust.repository r join traust.repository_ref h on h.repository_id=r.id
        where r.url='$failed' and h.is_default and h.sha=repeat('a',40)
        and h.manifest_sbom_id is null and h.manifest_sbom_assessment_id is null"
    smoke_expect '2|2|2|1' "select (select count(*) from traust.sbom),
        (select count(*) from traust.assessment where kind='manifest_sbom'),
        (select count(*) from traust.artifact where kind='manifest-coverage'),
        (select count(*) from traust.dependency)"
    smoke_expect 1 "select count(*) from traust_ops.run_order o join traust.repository r on r.id=o.repository_id
        join traust.repository_ref h on h.repository_id=r.id and h.is_default
        join traust.assessment a on a.id=h.manifest_sbom_assessment_id and a.run_order_id=o.id
        where r.url='$partial' and o.asset='manifest_sbom' and o.state='succeeded'
        and o.completed_by='smoke-manifest' and o.lease_generation=1"
    smoke_records verify-coverage
    audit=$(smoke_sql "select id from traust_ops.run_order where asset='ledger_audit' and state='degraded'
        and completed_by='smoke-manifest' and lease_generation=1")
    smoke_uuid "$audit"
    uv run --no-sync python - "$audit" <<'PY'
import sys
from uuid import UUID
from traust.context import load

degraded = load(None).services().ops.manifest(UUID(sys.argv[1])).degraded
if degraded != {"failed": 1}:
    raise SystemExit(f"smoke: expected one failed layer in the audit order manifest, got {degraded}")
PY
    smoke_records verify
    if [[ "${OPS_ACCEPTANCE:-0}" = 1 ]]; then
        echo "smoke: pinned rig passed all three order replays and ledger/disposition checks"
    else
        echo "smoke: diagnostic probes passed (not pin or SDK acceptance)"
    fi
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
    smoke-engine) shift; source_env; engine "$@" ;;
    *) sed -n '2,20p' "$0"; exit 2 ;;
esac
