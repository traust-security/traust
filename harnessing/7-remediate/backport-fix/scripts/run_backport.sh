#!/usr/bin/env bash
# run_backport.sh — Run Amalgamator pipeline for each generated config.
#
# Iterates over every YAML in the config directory, runs the Amalgamator
# auto_bug_fix pipeline for each, and collects results into the output
# directory organized per target branch.
#
# Usage (local):
#   bash run_backport.sh --config-dir /tmp/backport-fix/configs \
#                        --output-dir /tmp/backport-fix/results
#
# Usage (containerized):
#   bash run_backport.sh --config-dir /tmp/backport-fix/configs \
#                        --output-dir /tmp/backport-fix/results \
#                        --container-image quay.io/supathak/crio-backport-test:latest \
#                        --repo /path/to/local/clone
#
# Prerequisites (local):
#   - Amalgamator must be on PYTHONPATH or installed via pip
#   - CLAUDE_CODE_USE_VERTEX=1 + Vertex creds, or ANTHROPIC_API_KEY
#
# Prerequisites (containerized):
#   - Docker or Podman installed
#   - Container image with repo build deps + Amalgamator
#   - Vertex/Anthropic credentials accessible to the container

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

CONFIG_DIR=""
SINGLE_CONFIG=""
OUTPUT_DIR="/tmp/backport-fix/results"
CONTAINER_IMAGE=""
REPO_PATH=""
CONTAINER_RUNTIME=""
AMALGAMATOR_PATH=""
SELINUX_RELABEL=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --config-dir)       CONFIG_DIR="$2"; shift 2;;
    --config)           SINGLE_CONFIG="$2"; shift 2;;
    --output-dir)       OUTPUT_DIR="$2"; shift 2;;
    --container-image)  CONTAINER_IMAGE="$2"; shift 2;;
    --repo)             REPO_PATH="$2"; shift 2;;
    --amalgamator)      AMALGAMATOR_PATH="$2"; shift 2;;
    --selinux-relabel)  SELINUX_RELABEL=true; shift;;
    *) echo "Unknown argument: $1" >&2; exit 1;;
  esac
done

if [[ -z "$CONFIG_DIR" && -z "$SINGLE_CONFIG" ]]; then
  echo "Usage: run_backport.sh --config-dir <dir> | --config <file> [options]" >&2
  echo >&2
  echo "Options:" >&2
  echo "  --output-dir <dir>          Where to store results (default: /tmp/backport-fix/results)" >&2
  echo "  --container-image <image>   Run Amalgamator inside this container image" >&2
  echo "  --repo <path>               Local repo clone to mount into container" >&2
  echo "  --amalgamator <path>        Path to Amalgamator source (mounted into container)" >&2
  echo "  --selinux-relabel           Let podman relabel host mounts (:z). Recursively" >&2
  echo "                              changes host labels and persists." >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# Detect container runtime
# ---------------------------------------------------------------------------
if [[ -n "$CONTAINER_IMAGE" ]]; then
  if command -v podman &>/dev/null; then
    CONTAINER_RUNTIME="podman"
  elif command -v docker &>/dev/null; then
    CONTAINER_RUNTIME="docker"
  else
    echo "[run_backport] ERROR: --container-image requires docker or podman." >&2
    exit 1
  fi
  echo "[run_backport] Using container runtime: $CONTAINER_RUNTIME"
  echo "[run_backport] Image: $CONTAINER_IMAGE"

  if [[ -z "$REPO_PATH" ]]; then
    echo "[run_backport] ERROR: --container-image requires --repo <path> to mount the repo." >&2
    exit 1
  fi
else
  # Local mode: verify Amalgamator is importable
  if ! python3 -c "import auto_bug_fix" 2>/dev/null; then
    echo "[run_backport] ERROR: Cannot import auto_bug_fix." >&2
    echo "  Ensure Amalgamator is installed or set PYTHONPATH." >&2
    exit 1
  fi
fi

if [[ -z "${ANTHROPIC_API_KEY:-}" && -z "${CLAUDE_CODE_USE_VERTEX:-}" ]]; then
  echo "[run_backport] WARNING: Neither ANTHROPIC_API_KEY nor CLAUDE_CODE_USE_VERTEX is set." >&2
  echo "  Set Vertex AI credentials or ANTHROPIC_API_KEY for Amalgamator." >&2
fi

mkdir -p "$OUTPUT_DIR"

# Canonicalize every path handed to the container runtime: podman needs
# absolute mount sources, and the podman-machine VM on macOS shares
# /private but not the literal /tmp symlink — pwd -P resolves both
# (relative paths and symlinked /tmp) to something the VM can statfs.
abs_dir() { (CDPATH= cd -- "$1" 2>/dev/null && pwd -P); }
OUTPUT_DIR="$(abs_dir "$OUTPUT_DIR")" || { echo "[run_backport] ERROR: bad --output-dir" >&2; exit 1; }
if [[ -n "$REPO_PATH" ]]; then
  REPO_PATH="$(abs_dir "$REPO_PATH")" || { echo "[run_backport] ERROR: --repo path not found" >&2; exit 1; }
fi
if [[ -n "$AMALGAMATOR_PATH" ]]; then
  AMALGAMATOR_PATH="$(abs_dir "$AMALGAMATOR_PATH")" || { echo "[run_backport] ERROR: --amalgamator path not found" >&2; exit 1; }
fi

# Collect config files
CONFIGS=()
if [[ -n "$SINGLE_CONFIG" ]]; then
  CONFIGS+=("$SINGLE_CONFIG")
elif [[ -n "$CONFIG_DIR" ]]; then
  for f in "$CONFIG_DIR"/*.yaml "$CONFIG_DIR"/*.yml; do
    [[ -f "$f" ]] && CONFIGS+=("$f")
  done
fi

if [[ ${#CONFIGS[@]} -eq 0 ]]; then
  echo "[run_backport] No config files found." >&2
  exit 1
fi

echo "============================================================"
echo "  BACKPORT PIPELINE"
echo "============================================================"
echo "  Configs:    ${#CONFIGS[@]}"
echo "  Output:     $OUTPUT_DIR"
if [[ -n "$CONTAINER_IMAGE" ]]; then
  echo "  Runtime:    $CONTAINER_RUNTIME"
  echo "  Image:      $CONTAINER_IMAGE"
  echo "  Repo:       $REPO_PATH"
fi
echo "============================================================"
echo

# ---------------------------------------------------------------------------
# run_amalgamator — execute pipeline locally or in a container
# ---------------------------------------------------------------------------

# SELinux helpers. On an enforcing host a bind mount without a container_file_t
# label is invisible to the confined container. :z relabels recursively and
# persists, affecting other host processes, so it is never applied implicitly
# to user-owned paths.
selinux_enforcing() {
  case "${BACKPORT_SELINUX:-}" in
    enforcing|Enforcing) return 0 ;;
    permissive|Permissive|disabled|Disabled) return 1 ;;
  esac
  if [[ -r /sys/fs/selinux/enforce ]]; then
    [[ "$(cat /sys/fs/selinux/enforce)" == "1" ]]
    return
  fi
  if command -v getenforce >/dev/null 2>&1; then
    [[ "$(getenforce 2>/dev/null)" == "Enforcing" ]]
    return
  fi
  return 1
}

path_has_container_label() {  # succeeds when stat reports container_file_t
  local ctx
  ctx="$(stat -c '%C' "$1" 2>/dev/null || true)"
  [[ "$ctx" == *container_file_t* ]]
}


# Credentials that must never reach the pipeline, even when an operator adds
# them to BACKPORT_ENV_ALLOW: fork/mirror and GitHub tokens.
is_denied_env() {
  case "$1" in
    GITHUB_TOKEN | GH_TOKEN | GH_ENTERPRISE_TOKEN | GITHUB_ENTERPRISE_TOKEN | \
    GITHUB_AGENT_TOKEN_*)
      return 0
      ;;
  esac
  return 1
}

run_amalgamator() {
  local config_file="$1"
  local log_file="$2"
  local branch_name="$3"

  # Which LLM auth mechanism is in use? Both modes forward exactly ONE
  # (least privilege): Vertex reads ADC, the direct API path uses
  # ANTHROPIC_API_KEY. Sending both only doubles what untrusted build/agent
  # code can read.
  local use_vertex=false
  case "${CLAUDE_CODE_USE_VERTEX:-}" in
    ""|0|false|False) ;;
    *) use_vertex=true ;;
  esac

  if [[ -n "$CONTAINER_IMAGE" ]]; then
    # --- Containerized mode ---
    # Rewrite the config YAML to use container-internal paths.
    # The host config has host paths (e.g. /Users/.../cri-o); inside the
    # container the repo lives at /workspace/repo.
    local container_config_dir
    container_config_dir=$(mktemp -d)
    local container_config="$container_config_dir/$(basename "$config_file")"

    # Paths go through argv: config filenames are branch-derived, and a git
    # branch name may legally contain quotes. Interpolating them into -c
    # source was host code execution.
    python3 -c '
import sys, yaml
src, dst = sys.argv[1], sys.argv[2]
with open(src) as f:
    cfg = yaml.safe_load(f)
cfg.setdefault("repository", {})["source_path"] = "/workspace/repo"
cfg["repository"]["workdir"] = "/workspace/workdir"
# no output.directory rewrite: the pipeline ignores it for artifacts
# (results are collected from /workspace/runs via podman cp + find)
with open(dst, "w") as f:
    yaml.dump(cfg, f, default_flow_style=False, sort_keys=False)
' "$config_file" "$container_config"

    # LLM auth file: mount ONLY the credential file, never the whole gcloud
    # tree. Prefer an explicitly configured ADC path when it exists — the old
    # order let a stale default directory mask a valid override.
    local adc=""
    if [[ -n "${GOOGLE_APPLICATION_CREDENTIALS:-}" ]]; then
      if [[ -f "$GOOGLE_APPLICATION_CREDENTIALS" ]]; then
        adc="$GOOGLE_APPLICATION_CREDENTIALS"
      else
        echo "[run_backport] WARNING: GOOGLE_APPLICATION_CREDENTIALS does not exist: $GOOGLE_APPLICATION_CREDENTIALS" >&2
      fi
    fi
    if [[ -z "$adc" && -f "$HOME/.config/gcloud/application_default_credentials.json" ]]; then
      adc="$HOME/.config/gcloud/application_default_credentials.json"
    fi
    if $use_vertex && [[ -n "${ANTHROPIC_API_KEY:-}" ]]; then
      echo "[run_backport] NOTE: Vertex is selected; ANTHROPIC_API_KEY is not forwarded into the container" >&2
    fi
    if $use_vertex && [[ -n "$adc" ]]; then
      adc="$(cd "$(dirname "$adc")" && pwd -P)/$(basename "$adc")"
    fi

    # SELinux-aware bind mounts. The temp config dir and the results dir are
    # ours to label; the user's checkout, Amalgamator source and credential
    # file are labeled only on explicit request (--selinux-relabel), because
    # :z recurses over host paths and persists.
    local enforcing=false
    if selinux_enforcing; then
      enforcing=true
    fi
    local cfg_opts="ro" res_opts="rw"
    local repo_opts="rw" amg_opts="ro" adc_opts="ro"
    local mount_adc=false
    if $use_vertex && [[ -n "$adc" ]]; then
      mount_adc=true
    fi
    if $enforcing; then
      cfg_opts="ro,z"
      res_opts="rw,z"
      local -a unlabeled=()
      if [[ -n "$REPO_PATH" ]] && ! path_has_container_label "$REPO_PATH"; then
        unlabeled+=("$REPO_PATH")
      fi
      if [[ -n "$AMALGAMATOR_PATH" ]] && ! path_has_container_label "$AMALGAMATOR_PATH"; then
        unlabeled+=("$AMALGAMATOR_PATH")
      fi
      if $mount_adc && ! path_has_container_label "$adc"; then
        unlabeled+=("$adc")
      fi
      if [[ ${#unlabeled[@]} -gt 0 ]]; then
        if $SELINUX_RELABEL; then
          echo "[run_backport] WARNING: --selinux-relabel recursively relabels these host paths (container_file_t); the change persists and affects other host processes:" >&2
          printf '    %s\n' "${unlabeled[@]}" >&2
          repo_opts="rw,z"
          amg_opts="ro,z"
          adc_opts="ro,z"
        else
          echo "[run_backport] SELinux is enforcing and these host paths are not labeled container_file_t:" >&2
          printf '    %s\n' "${unlabeled[@]}" >&2
          echo "  Either pre-label them (chcon -Rt container_file_t <path>; affects other host processes)," >&2
          echo "  or pass --selinux-relabel to let podman relabel them recursively for this run." >&2
          exit 2
        fi
      fi
    elif $SELINUX_RELABEL; then
      echo "[run_backport] NOTE: SELinux is not enforcing; --selinux-relabel has no effect" >&2
    fi

    local -a volumes=(
      -v "$REPO_PATH:/workspace/repo:$repo_opts"
      -v "$container_config_dir:/workspace/configs:$cfg_opts"
      -v "$OUTPUT_DIR:/workspace/results:$res_opts"
    )
    if [[ -n "$AMALGAMATOR_PATH" ]]; then
      volumes+=(-v "$AMALGAMATOR_PATH:/workspace/amalgamator:$amg_opts")
    fi
    if $mount_adc; then
      volumes+=(-v "$adc:/workspace/adc.json:$adc_opts")
    fi

    # Build env vars. GITHUB_TOKEN is deliberately NOT forwarded: the
    # container runs untrusted build/agent code; fork ops stay host-side.
    local -a env_args=()
    # Every forwarded variable passes the credential denylist, including
    # name-only `-e VAR` (the value is copied by the runtime, not argv).
    add_env() {
      local spec="$1"
      local name="${spec%%=*}"
      if is_denied_env "$name"; then
        echo "[run_backport] WARNING: refusing to forward $name into the container" >&2
        return 0
      fi
      env_args+=(-e "$spec")
    }
    # Names only: `-e VAR` copies the value from this process's environment.
    # `-e VAR=value` would put the secret in the runtime's argv (ps-visible).
    if $use_vertex; then
      add_env "CLAUDE_CODE_USE_VERTEX=$CLAUDE_CODE_USE_VERTEX"
      [[ -n "${ANTHROPIC_VERTEX_PROJECT_ID:-}" ]] && add_env "ANTHROPIC_VERTEX_PROJECT_ID=$ANTHROPIC_VERTEX_PROJECT_ID"
      [[ -n "${CLOUD_ML_REGION:-}" ]] && add_env "CLOUD_ML_REGION=$CLOUD_ML_REGION"
      if [[ -n "$adc" ]]; then
        add_env "GOOGLE_APPLICATION_CREDENTIALS=/workspace/adc.json"
      fi
    else
      [[ -n "${ANTHROPIC_API_KEY:-}" ]] && add_env ANTHROPIC_API_KEY
    fi

    # Add PYTHONPATH for mounted Amalgamator
    if [[ -n "$AMALGAMATOR_PATH" ]]; then
      add_env "PYTHONPATH=/workspace/amalgamator:\${PYTHONPATH:-}"
    fi

    # Run container WITHOUT --rm so we can copy results out after it exits.
    local container_name="backport-${branch_name}-$$"

    # Aborted runs must not leave a stopped container or a temp config tree
    # behind. EXIT covers set -e failures and error returns; INT/TERM cover an
    # operator abort (Ctrl-C reaches the whole process group). The normal path
    # disarms the traps only after the artifacts are copied out.
    cleanup_container() {
      if [[ -n "${container_config_dir:-}" && -d "$container_config_dir" ]]; then
        rm -rf "$container_config_dir"
      fi
      if [[ -n "${container_name:-}" ]]; then
        "$CONTAINER_RUNTIME" rm -f "$container_name" >/dev/null 2>&1 || true
      fi
    }
    on_signal() {
      cleanup_container
      trap - EXIT INT TERM
      exit 130
    }
    trap cleanup_container EXIT
    trap on_signal INT TERM

    local run_rc=0
    set +e
    "$CONTAINER_RUNTIME" run \
      --name "$container_name" \
      "${volumes[@]}" \
      ${env_args[@]+"${env_args[@]}"} \
      -w /workspace \
      "$CONTAINER_IMAGE" \
      python3 -m auto_bug_fix.run_bug_fix "/workspace/configs/$(basename "$config_file")" \
      2>&1 | tee "$log_file"
    run_rc=$?   # podman/pipeline status — a mount error must not read as success
    set -e

    # Copy the entire runs/ directory out of the stopped container
    local host_branch_results="$OUTPUT_DIR/$branch_name"
    mkdir -p "$host_branch_results"

    # podman/docker cp copies the runs/ tree from the container to host
    $CONTAINER_RUNTIME cp "$container_name:/workspace/runs" "$host_branch_results/runs" 2>/dev/null && \
      echo "[run_backport] Copied runs/ directory from container" || true

    # Flatten: find key artifacts and copy them up to branch_results/
    if [[ -d "$host_branch_results/runs" ]]; then
      find "$host_branch_results/runs" -name 'summary.json' -exec cp {} "$host_branch_results/summary.json" \;
      find "$host_branch_results/runs" -name 'candidate.patch' -exec cp {} "$host_branch_results/candidate.patch" \;
      find "$host_branch_results/runs" -name 'dossier.md' -exec cp {} "$host_branch_results/dossier.md" \;
      # Tracker json (issue_id_<ts>.json) holds backport_commit for the
      # emitter. It lives in the per-target subdir: runs/<run>/<target>/ —
      # depth 3 from here.
      find "$host_branch_results/runs" -maxdepth 3 -name '*.json' \
        ! -name 'summary.json' ! -name 'semantic_triage.json' \
        -exec cp {} "$host_branch_results/tracker.json" \; 2>/dev/null || true
      echo "[run_backport] Extracted artifacts to $host_branch_results/"
    fi

    # Artifacts are safely out of the container: remove it and the rewritten
    # config, then disarm the traps.
    cleanup_container
    trap - EXIT INT TERM
    return "$run_rc"
  else
    # --- Local mode ---
    # The pipeline executes the target's build/test commands and agent-issued
    # shell. Construct the environment explicitly (env -i + a short allowlist)
    # like the harness's safe_exec practice: subtracting two token names would
    # still let anything else the caller exported (cloud creds, kube context,
    # other tokens) reach untrusted code.
    local -a keep_env=(
      PATH HOME TMPDIR PWD USER LOGNAME LANG LC_ALL LC_CTYPE TERM
      PYTHONPATH PYTHONHOME VIRTUAL_ENV
      SSL_CERT_FILE SSL_CERT_DIR REQUESTS_CA_BUNDLE CURL_CA_BUNDLE
      HTTP_PROXY HTTPS_PROXY NO_PROXY http_proxy https_proxy no_proxy
      # toolchain knobs a target may legitimately need to build
      CC CXX CFLAGS CXXFLAGS CPPFLAGS LDFLAGS PKG_CONFIG_PATH
      GOFLAGS GOPATH GOMODCACHE GOCACHE GOPROXY GOSUMDB
      GONOSUMDB GONOSUMCHECK GOMAXPROCS GOMEMLIMIT CGO_ENABLED
      CARGO_HOME RUSTUP_HOME RUSTFLAGS
      NODE_OPTIONS NPM_CONFIG_CACHE
      MAKEFLAGS
    )
    if $use_vertex; then
      keep_env+=(CLAUDE_CODE_USE_VERTEX ANTHROPIC_VERTEX_PROJECT_ID
                 CLOUD_ML_REGION GOOGLE_APPLICATION_CREDENTIALS)
    else
      keep_env+=(ANTHROPIC_API_KEY)
    fi
    # Deliberate extension point for provider-specific variables, e.g.
    # BACKPORT_ENV_ALLOW="ANTHROPIC_BASE_URL LITELLM_API_KEY".
    if [[ -n "${BACKPORT_ENV_ALLOW:-}" ]]; then
      read -r -a extra_env <<<"${BACKPORT_ENV_ALLOW}"
      keep_env+=("${extra_env[@]}")
    fi

    local -a env_pairs=()
    local var
    for var in "${keep_env[@]}"; do
      # Never, even when explicitly allowlisted.
      if is_denied_env "$var"; then
        if [[ -n "${!var+x}" ]]; then
          echo "[run_backport] WARNING: refusing to pass $var into the pipeline (credential)" >&2
        fi
        continue
      fi
      if [[ -n "${!var+x}" ]]; then
        env_pairs+=("$var=${!var}")
      fi
    done
    if [[ ${#env_pairs[@]} -eq 0 ]]; then
      env_pairs=("PATH=${PATH:-/usr/bin:/bin}")
    fi

    env -i "${env_pairs[@]}" \
      python3 -m auto_bug_fix.run_bug_fix "$config_file" 2>&1 | tee "$log_file"
  fi
}

TOTAL=${#CONFIGS[@]}
PASSED=0
FAILED=0
SKIPPED=0

for config in "${CONFIGS[@]}"; do
  branch_name=$(basename "$config" .yaml)
  branch_name=$(basename "$branch_name" .yml)
  # The basename becomes a directory name under --output-dir. A manual config
  # named "...yaml" yields "..", which would clean/write in the parent.
  if [[ ! "$branch_name" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ || "$branch_name" == *..* ]]; then
    echo "[run_backport] refusing config with unsafe basename: '$branch_name'" >&2
    exit 1
  fi
  branch_dir="$OUTPUT_DIR/$branch_name"
  mkdir -p "$branch_dir"

  echo "------------------------------------------------------------"
  echo "  [$((PASSED + FAILED + SKIPPED + 1))/$TOTAL] Running: $branch_name"
  echo "  Config: $config"
  echo "  Output: $branch_dir"
  echo "------------------------------------------------------------"

  log_file="$branch_dir/pipeline.log"
  # Fresh per-branch artifacts: leftovers from a previous run in a reused
  # output dir would poison collection and the report's provenance.
  rm -f "$branch_dir/summary.json" "$branch_dir/candidate.patch" \
        "$branch_dir/dossier.md" "$branch_dir/tracker.json" \
        "$branch_dir/config.yaml" "$branch_dir/result.json"
  # A leftover runs/ tree makes container-mode `podman cp` nest the fresh
  # copy at runs/runs/, resurrecting the previous run's artifacts.
  rm -rf "$branch_dir/runs"
  # Keep the config beside its results: it is the record of what ran, and
  # the emitter resolves fix commit / source branch from it.
  cp "$config" "$branch_dir/config.yaml"

  # Invocation marker: only run directories created AFTER this point can
  # belong to this config's run. Never collect from "the newest directory" —
  # that is how one branch inherits another branch's summary and patch.
  marker="$branch_dir/.run-start"
  : > "$marker"

  run_rc=0
  if run_amalgamator "$config" "$log_file" "$branch_name"; then
    echo "[run_backport] $branch_name: pipeline completed"
  else
    run_rc=$?
    echo "[run_backport] $branch_name: pipeline exited with error (status $run_rc)" >&2
  fi

  # Collect Amalgamator outputs.
  # The pipeline writes results to the workdir specified in the config,
  # or to a runs/ directory relative to where it was invoked.
  workdir=$(python3 -c '
import sys, yaml
with open(sys.argv[1]) as f:
    c = yaml.safe_load(f)
print(c.get("repository", {}).get("workdir", "/tmp/bugfix-workdir"))
' "$config" 2>/dev/null || echo "/tmp/bugfix-workdir")

  # Search for summary.json in multiple locations:
  # 1. The branch results directory (container mode copies here)
  # 2. Amalgamator's runs/ directory (relative to cwd)
  # 3. workdir/runs/ directory
  # 4. Output dir's runs/ subdir (container mode with output.directory)
  #
  # Every candidate must belong to THIS invocation: its directory name is
  # <config basename>_<timestamp> (the pipeline names run dirs after the YAML
  # it was given) AND it must be newer than the marker written just before
  # this config started. There is deliberately no "newest directory"
  # fallback: that let a branch that produced nothing inherit another
  # branch's summary and candidate.patch, and be reported as passed.
  summary_found=""

  # Check direct copy from container first
  if [[ -f "$branch_dir/summary.json" ]]; then
    echo "[run_backport] Collected summary.json from $branch_dir/summary.json"
    summary_found="yes"
  fi

  if [[ -z "$summary_found" ]]; then
    for search_dir in "runs" "$workdir/runs" "$OUTPUT_DIR/runs"; do
      [[ -d "$search_dir" ]] || continue
      while IFS= read -r run_cand; do
        [[ -n "$run_cand" ]] || continue
        # summary.json sits at the run root (single/multi target) or one
        # level deeper in the per-target directory.
        candidate=""
        if [[ -f "$run_cand/summary.json" ]]; then
          candidate="$run_cand/summary.json"
        else
          for deeper in "$run_cand"/*/summary.json; do
            [[ -f "$deeper" ]] && { candidate="$deeper"; break; }
          done
        fi
        [[ -n "$candidate" ]] || continue
        # Defense in depth: the summary must describe the config that ran.
        if ! python3 - "$candidate" "$config" <<'PY'
import json, sys, yaml
summary, cfg_path = sys.argv[1], sys.argv[2]
s = json.load(open(summary))
cfg = yaml.safe_load(open(cfg_path)) or {}
t = (s.get("targets") or [{}])[0]
def norm(v):
    return str(v or "").removeprefix("origin/")
want_target = norm((cfg.get("branches") or {}).get("target"))
got_target = norm(t.get("target_branch"))
want_id = str(cfg.get("issue_id") or "")
got_id = str(t.get("issue_id") or "")
if want_target and got_target and want_target != got_target:
    sys.exit(1)
if want_id and got_id and want_id != got_id:
    sys.exit(1)
PY
        then
          echo "[run_backport] Skipping $candidate: does not describe $branch_name" >&2
          continue
        fi
        cp "$candidate" "$branch_dir/summary.json"
        echo "[run_backport] Collected summary.json from $candidate"
        # The pipeline writes these into the run dir and deletes its
        # worktrees — collect from here, not just the workdir.
        run_root="$(dirname "$candidate")"
        find "$run_root" -name 'candidate.patch' -exec cp {} "$branch_dir/candidate.patch" \; 2>/dev/null || true
        find "$run_root" -name 'dossier.md' -exec cp {} "$branch_dir/dossier.md" \; 2>/dev/null || true
        find "$run_root" -maxdepth 2 -name '*.json' \
          ! -name 'summary.json' ! -name 'semantic_triage.json' \
          -exec cp {} "$branch_dir/tracker.json" \; 2>/dev/null || true
        summary_found="yes"
        break
      done < <(find "$search_dir" -maxdepth 1 -type d \
                 -name "${branch_name}_*" -newer "$marker" 2>/dev/null | sort)
      if [[ -n "$summary_found" ]]; then
        break
      fi
    done
  fi  # end of summary_found check

  # Canonical verdict for THIS run. The engine's summary is not authoritative
  # on its own: a nonzero exit can leave a success-shaped summary (and even a
  # candidate.patch) behind. Consumers (report, delivery) read the verdict
  # persisted below, not the summary.
  summary_outcome="none"
  if [[ -n "$summary_found" ]]; then
    summary_outcome=$(python3 -c '
import json, sys
with open(sys.argv[1]) as f:
    s = json.load(f)
if "targets" in s:
    t = s["targets"][0] if s.get("targets") else {}
    print(t.get("outcome", "unknown"))
else:
    print(s.get("status", "unknown"))
' "$branch_dir/summary.json" 2>/dev/null || echo "unknown")
  fi

  canonical="$summary_outcome"
  case "$canonical" in
    success|passed|partial_success|pipeline_stop|pipeline_escalation|worktree_error|failed|error|skipped|timeout|unknown) ;;
    *) canonical="unknown" ;;
  esac
  if [[ $run_rc -ne 0 && ( "$canonical" == "success" || "$canonical" == "passed" ) ]]; then
    echo "[run_backport] $branch_name: engine exited $run_rc but its summary says '$canonical' — recording as failed" >&2
    canonical="failed"
  fi
  if [[ "$summary_outcome" == "none" ]]; then
    canonical="failed"
  fi

  if [[ "$canonical" == "success" || "$canonical" == "passed" ]]; then
    PASSED=$((PASSED + 1))
  elif [[ "$canonical" == "pipeline_stop" ]]; then
    echo "[run_backport] $branch_name: fix already present on target (pipeline_stop)"
    SKIPPED=$((SKIPPED + 1))
  else
    FAILED=$((FAILED + 1))
  fi

  # Persist provenance AND the canonical verdict at collection time. This is
  # written even when no summary was collected, so a consumer can never fall
  # back to the engine's (possibly success-shaped) artifacts.
  python3 - "$branch_dir" "$branch_dir/config.yaml" \
           "$canonical" "${run_rc:-0}" "$summary_outcome" <<'PY' 2>/dev/null || true
import json, subprocess, sys, yaml
from pathlib import Path
bd = Path(sys.argv[1])
cfg = yaml.safe_load(open(sys.argv[2])) or {}
canonical, run_rc, summary_outcome = sys.argv[3], int(sys.argv[4] or 0), sys.argv[5]
summary_path = bd / "summary.json"
summary = json.load(open(summary_path)) if summary_path.is_file() else {}
t = (summary.get("targets") or [{}])[0]
issue_id = str(t.get("issue_id") or cfg.get("issue_id") or "")
src = (cfg.get("repository") or {}).get("source_path") or ""
target = str((cfg.get("branches") or {}).get("target") or "").removeprefix("origin/")
head = ""
if canonical in ("success", "passed", "partial_success") and issue_id and src:
    r = subprocess.run(
        ["git", "-C", src, "rev-parse", "--verify", "--quiet",
         f"refs/heads/amalgamator/{issue_id}"],
        capture_output=True, text=True,
    )
    head = r.stdout.strip()
rec = {
    "issue_id": issue_id,
    "target_branch": target,
    "outcome": canonical,
    "summary_outcome": summary_outcome,
    "engine_exit_code": run_rc,
    "head_sha": head,
}
(bd / "result.json").write_text(json.dumps(rec, indent=2) + "\n")
PY


  # Collect candidate.patch — workdir-diff fallback, only when the run-dir
  # collection produced nothing AND the canonical verdict says the pipeline
  # succeeded. The worktree is pipeline-controlled (untrusted build code ran
  # in it), so git runs with an empty environment and every repo-selected
  # diff driver disabled: a planted .gitattributes/textconv, a repo
  # diff.<driver>.command, GIT_EXTERNAL_DIFF or an fsmonitor program would
  # otherwise execute on the host, outside the env -i boundary the pipeline
  # itself ran under. Diffs write to a temp file so a failed diff can never
  # truncate an already-collected patch.
  patch_fallback=false
  case "$canonical" in
    success | passed | partial_success) patch_fallback=true ;;
  esac
  if [[ "$patch_fallback" == true && ! -s "$branch_dir/candidate.patch" && -d "$workdir" ]]; then
    target_branch=$(python3 -c '
import sys, yaml
with open(sys.argv[1]) as f:
    c = yaml.safe_load(f)
print(c.get("branches", {}).get("target", ""))
' "$config" 2>/dev/null || echo "")

    if [[ -n "$target_branch" ]]; then
      patch_tmp="$branch_dir/candidate.patch.tmp"
      # Look for the worktree subdirectory that Amalgamator creates
      for wt_dir in "$workdir"/*; do
        if [[ -d "$wt_dir/.git" || -f "$wt_dir/.git" ]]; then
          (cd "$wt_dir" && env -i PATH="$PATH" HOME="${HOME:-/tmp}" \
             git -c core.hooksPath=/dev/null -c core.fsmonitor= \
                 -c diff.external= diff --no-ext-diff --no-textconv \
                 "$target_branch"..HEAD > "$patch_tmp" 2>/dev/null) || true
          break
        fi
      done
      # Fallback: try workdir itself
      if [[ ! -s "$patch_tmp" && -d "$workdir/.git" ]]; then
        (cd "$workdir" && env -i PATH="$PATH" HOME="${HOME:-/tmp}" \
           git -c core.hooksPath=/dev/null -c core.fsmonitor= \
               -c diff.external= diff --no-ext-diff --no-textconv \
               "$target_branch"..HEAD > "$patch_tmp" 2>/dev/null) || true
      fi
      if [[ -s "$patch_tmp" ]]; then
        mv "$patch_tmp" "$branch_dir/candidate.patch"
      else
        rm -f "$patch_tmp"
      fi
    fi
  fi
  if [[ -s "$branch_dir/candidate.patch" ]]; then
    echo "[run_backport] Collected candidate.patch ($(wc -l < "$branch_dir/candidate.patch") lines)"
  fi

  echo
done

# Machine-readable summary, then the human block from the same counts.
# Statuses come from each branch's persisted result.json (the canonical
# verdict), never from the engine's summary, which can stay success-shaped
# after a nonzero exit. A missing or malformed record is an explicit
# "unknown", counted as failed, so the file cannot disagree with the exit
# code or the emitted report. Built in one python3 call: branch names come
# from config filenames and are pipeline-controlled, so quoting them into JSON
# by hand let a crafted name corrupt or forge the document.
summary_args=(--output-dir "$OUTPUT_DIR")
if [[ -n "${CONTAINER_IMAGE:-}" ]]; then
  summary_args+=(--container-image "$CONTAINER_IMAGE")
fi
for config in "${CONFIGS[@]}"; do
  bn=$(basename "$config" .yaml)
  bn=$(basename "$bn" .yml)
  summary_args+=(--branch "$bn")
done
summary_counts="$(python3 "$HERE/write_run_summary.py" "${summary_args[@]}")" || {
  echo "[run_backport] ERROR: could not write run_summary.json" >&2
  exit 2
}
read -r TOTAL PASSED FAILED SKIPPED <<< "$summary_counts"

echo "============================================================"
echo "  BACKPORT SUMMARY"
echo "============================================================"
echo "  Total:   $TOTAL"
echo "  Passed:  $PASSED"
echo "  Failed:  $FAILED"
echo "  Skipped: $SKIPPED"
echo "============================================================"

echo
echo "  Results:  $OUTPUT_DIR/"
echo "  Summary:  $OUTPUT_DIR/run_summary.json"

# A batch with failures must not exit 0 — callers and CI would read the whole
# run as successful. The summary is written first, so the detail survives.
if [[ $FAILED -gt 0 ]]; then
  echo "[run_backport] $FAILED branch(es) failed — exiting nonzero" >&2
  exit 1
fi
