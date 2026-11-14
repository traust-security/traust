#!/usr/bin/env bash
# Run local build/lint/test checks for a remediation worktree and emit a
# JSON array of check objects matching remediation.schema.json#/$defs/check.
#
# Heuristic, language-aware.  Designed to be cheap and deterministic so the
# remediate-finding skill can call it after every patch iteration.
#
# Usage:
#   run_checks.sh <worktree> [<out-dir>]
#
# Output (stdout): JSON array of checks.
# Logs:            <out-dir>/check-<name>.log

set -uo pipefail

WORK="${1:?usage: run_checks.sh <worktree> [<out-dir>]}"
OUT="${2:-$WORK/.remediation-checks}"
mkdir -p "$OUT"

# --- execution mode (audit C1, plan P2.11) ----------------------------------
# Container leg is the default when podman exists: the target's own
# build/test code runs rootless, cap-dropped, credential-free, and the
# TEST phase runs with --network=none (dependency prefetch runs in a
# separate networked-but-scriptless container step first). The native
# fallback below keeps env-stripping + PATH shims and warns loudly —
# shims are bypassable by absolute paths and are NOT a boundary.
# Digest-pinned toolchain images (refresh deliberately):
IMG_GO="${REMEDIATION_IMG_GO:-docker.io/library/golang@sha256:1a6d4452c65dea36aac2e2d606b01b4a029ec90cc1ae53890540ce6173ea77ac}"      # golang:1.24-bookworm
IMG_NODE="${REMEDIATION_IMG_NODE:-docker.io/library/node@sha256:5647be709086c696ff32edaaf1c70cd26d1da6ab2b39c32f3c7b4c4a31957e37}"    # node:22-bookworm
IMG_RUST="${REMEDIATION_IMG_RUST:-docker.io/library/rust@sha256:77fac8b98f9f46062bb680b6d25d5bcaabfc400143952ebc572e924bcbedc3fa}"    # rust:1-bookworm
IMG_PY="${REMEDIATION_IMG_PY:-docker.io/library/python@sha256:9bed8554e926c07c6f908841d5ee88c33e8df9236b191526bbce81a9062ab43a}"      # python:3.12-bookworm
RUNNER="${REMEDIATION_CHECK_RUNNER:-auto}"   # auto | container | native
CONTAINER_IMG=""
if [[ "$RUNNER" != "native" ]] && command -v podman >/dev/null 2>&1; then
  if   [[ -f "$WORK/go.mod" ]];       then CONTAINER_IMG="$IMG_GO"
  elif [[ -f "$WORK/package.json" ]]; then CONTAINER_IMG="$IMG_NODE"
  elif [[ -f "$WORK/Cargo.toml" ]];   then CONTAINER_IMG="$IMG_RUST"
  elif [[ -f "$WORK/pyproject.toml" || -f "$WORK/setup.py" ]]; then CONTAINER_IMG="$IMG_PY"
  fi
fi
if [[ "$RUNNER" == "container" && -z "$CONTAINER_IMG" ]]; then
  echo "[run_checks] REMEDIATION_CHECK_RUNNER=container but no podman/ecosystem image — refusing" >&2
  exit 1
fi
if [[ -z "$CONTAINER_IMG" ]]; then
  echo "[run_checks] WARN: native fallback (no podman) — PATH shims + env stripping only; not a boundary (plan P2.11)" >&2
fi

in_container() {
  # in_container <netmode> <cmd...> — rootless, cap-dropped, creds-free
  local netmode="$1"; shift
  podman run --rm --network="$netmode" \
    --security-opt=no-new-privileges --cap-drop=ALL \
    --user "$(id -u):$(id -g)" --userns=keep-id \
    --tmpfs /home/runner:rw,mode=700 -e HOME=/home/runner \
    -e GOFLAGS -e GOMEMLIMIT -e GOMAXPROCS \
    -e NODE_OPTIONS -e CARGO_BUILD_JOBS -e GOPROXY \
    -v "$WORK":/work:Z \
    -v "$WORK/.git":/work/.git:ro,Z \
    -w /work "$CONTAINER_IMG" bash -c "$*"
  # A read-only .git prevents hostile tests from planting executable git
  # configuration or hooks for a later host command. Reads (go -buildvcs
  # etc.) remain possible; writes fail loudly.
}

egress_netmode() {
  # podman 5 removed slirp4netns in favour of pasta. Picking the wrong one is
  # not a loud failure: the prefetch below is `|| true`, so egress dies
  # silently and the offline test run then fails to resolve dependencies,
  # which reads as a genuine test failure. Probe instead of assuming.
  if [[ -n "${REMEDIATION_EGRESS_NET:-}" ]]; then printf '%s' "$REMEDIATION_EGRESS_NET"; return; fi
  if [[ -n "$(podman info --format '{{.Host.Pasta.Executable}}' 2>/dev/null)" ]]; then
    printf 'pasta'
  else
    printf 'slirp4netns'
  fi
}

prefetch_deps() {
  # networked but script-less dependency fetch; tests then run offline
  [[ -z "$CONTAINER_IMG" ]] && return 0
  if   [[ -f "$WORK/go.mod" ]];       then in_container "$(egress_netmode)" "go mod download" || true
  elif [[ -f "$WORK/package.json" ]]; then in_container "$(egress_netmode)" "npm ci --ignore-scripts || npm install --ignore-scripts" || true
  elif [[ -f "$WORK/Cargo.toml" ]];   then in_container "$(egress_netmode)" "cargo fetch" || true
  fi
}

# --- host-isolation guards --------------------------------------------------
# Cloned-repo test suites are untrusted relative to this host. Neuter the
# common side-effecting binaries so a `make test` or `go test ./...` that
# shells out (e.g. flightctl's safe_executer_test → `systemctl start …`)
# cannot interact with the host's init system, package manager, or sudo.
export SYSTEMD_OFFLINE=1               # systemctl behaves as if no systemd is running
export DBUS_SESSION_BUS_ADDRESS=/dev/null
export DBUS_SYSTEM_BUS_ADDRESS=/dev/null
export SUDO_ASKPASS=/bin/false
NOOP_BIN="$OUT/.noop-bin"
mkdir -p "$NOOP_BIN"
for b in systemctl journalctl loginctl sudo dnf yum apt apt-get rpm-ostree shutdown reboot \
         xdg-open gio gnome-open kde-open kde-open5 sensible-browser x-www-browser wslview \
         firefox google-chrome chromium chromium-browser open \
         notify-send zenity kdialog xmessage; do
  printf '#!/bin/sh\necho "[run_checks noop] %s $*" >&2\nexit 0\n' "$b" > "$NOOP_BIN/$b"
  chmod +x "$NOOP_BIN/$b"
done
export PATH="$NOOP_BIN:$PATH"
# Many tools (python webbrowser, npm 'open', go 'browser') respect $BROWSER.
export BROWSER="$NOOP_BIN/xdg-open"

# --- memory caps -----------------------------------------------------------
# At campaign scale (~32-48 concurrent worktree agents on one host) the
# default go build -p=$(nproc) can spawn 32 compile processes per agent
# and OOM the host. Bound each agent's build/test to ~2 GiB and 4-way
# package parallelism so 32 agents × 2 GiB ≈ 64 GiB peak.
export GOMEMLIMIT="${GOMEMLIMIT:-2000MiB}"
export GOFLAGS="${GOFLAGS:-} -p=4"
export GOMAXPROCS="${GOMAXPROCS:-4}"
export GOCACHE="${GOCACHE:-$HOME/.cache/go-build}"
# Node: cap V8 heap so npm install / jest on large monorepos doesn't balloon.
export NODE_OPTIONS="${NODE_OPTIONS:-} --max-old-space-size=2048"
# Cargo: cap codegen + job parallelism.
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-4}"
# Cover python's webbrowser.open() by importing a no-op stub first on PYTHONSTARTUP? Too invasive —
# the BROWSER env var + xdg-open shim covers the common path.

declare -a CHECKS=()

# The target repo's own build/test code runs here — hostile by the
# threat model. Interim containment (audit C1, plan P0.3): strip every
# credential from its environment so test code cannot read and
# exfiltrate tokens or push anywhere. Push credentials are injected
# only at push time by the caller (env-reading credential helper).
# Full containerization is plan P2.11.
CRED_ENV_STRIP=(
  -u GITHUB_TOKEN -u GH_TOKEN -u GITLAB_TOKEN -u GITLAB_API_TOKEN
  -u AWS_ACCESS_KEY_ID -u AWS_SECRET_ACCESS_KEY -u AWS_SESSION_TOKEN
  -u ANTHROPIC_API_KEY -u OPENAI_API_KEY -u JIRA_API_TOKEN
  -u KUBECONFIG -u IC_API_KEY -u OCM_TOKEN
)

run_check() {
  # run_check <name> <cmd...>
  local name="$1"; shift
  local cmd="$*"
  local log="$OUT/check-${name}.log"
  local t0 t1 rc
  t0=$(date +%s)
  if [[ -n "$CONTAINER_IMG" ]]; then
    # container leg: offline, rootless, creds-free (plan P2.11)
    in_container none "$cmd" >"$log" 2>&1
  else
    ( cd "$WORK" && env "${CRED_ENV_STRIP[@]}" bash -c "$cmd" ) >"$log" 2>&1
  fi
  rc=$?
  t1=$(date +%s)
  local outcome
  if [[ $rc -eq 0 ]]; then outcome=pass
  elif [[ $rc -eq 127 ]]; then outcome=skip   # tool not installed
  else outcome=fail; fi
  local summary
  summary=$(tail -n 3 "$log" 2>/dev/null | tr -d '\000-\037' | tr '\n' ' ' | sed 's/\\/\\\\/g; s/"/\\"/g' | cut -c1-200)
  CHECKS+=("$(printf '{"name":"%s","command":"%s","outcome":"%s","duration_seconds":%d,"log_path":"%s","summary":"%s"}' \
    "$name" "$(echo "$cmd" | sed 's/\\/\\\\/g; s/"/\\"/g')" "$outcome" "$((t1-t0))" "$(basename "$log")" "$summary")")
  echo "[run_checks] $name → $outcome (${rc}, $((t1-t0))s)" >&2
}

# dependency prefetch (networked, script-less) before offline checks
prefetch_deps

# --- Go --------------------------------------------------------------------
if [[ -f "$WORK/go.mod" ]]; then
  run_check go-build  "go build ./..."
  run_check go-vet    "go vet ./..."
  if [[ -f "$WORK/Makefile" ]] && grep -qE '^test:' "$WORK/Makefile"; then
    run_check make-test "make test"
  else
    # Exclude e2e/integration packages that require live infrastructure;
    # those belong to the revalidation phase, not local checks.
    run_check go-test   "go test \$(go list ./... | grep -Ev '/(e2e|integration)(/|\$)') -count=1 -short"
  fi
  if command -v golangci-lint >/dev/null 2>&1; then
    run_check golangci-lint "golangci-lint run --timeout 5m"
  fi
fi

# --- Java / Maven ----------------------------------------------------------
if [[ -f "$WORK/pom.xml" ]]; then
  if command -v mvn >/dev/null 2>&1; then
    run_check mvn-compile "mvn -B -q -DskipTests compile"
    run_check mvn-test    "mvn -B -q test"
  else
    run_check mvn-compile "echo 'mvn not installed' && false"  # → fail→skip via 127? no — record skip explicitly:
    CHECKS+=('{"name":"mvn","command":"mvn -B compile test","outcome":"skip","duration_seconds":0,"log_path":"","summary":"mvn not on PATH; Java change not compile-verified locally"}')
  fi
fi

# --- Node / npm ------------------------------------------------------------
if [[ -f "$WORK/package.json" && ! -f "$WORK/go.mod" ]]; then
  if command -v npm >/dev/null 2>&1; then
    run_check npm-ci    "npm ci --no-audit --no-fund || npm install --no-audit --no-fund"
    if node -e 'process.exit(require("./package.json").scripts?.test?0:1)' 2>/dev/null; then
      run_check npm-test "npm test --silent"
    fi
  fi
fi

# --- Rust ------------------------------------------------------------------
if [[ -f "$WORK/Cargo.toml" ]]; then
  run_check cargo-check "cargo check --all-targets"
  run_check cargo-test  "cargo test --all"
  if command -v cargo-clippy >/dev/null 2>&1; then
    run_check cargo-clippy "cargo clippy --all-targets -- -D warnings"
  fi
fi

# --- Python ----------------------------------------------------------------
if [[ -f "$WORK/pyproject.toml" || -f "$WORK/setup.py" ]]; then
  run_check py-compile "python3 -m compileall -q ."
  if [[ -d "$WORK/tests" ]] || ls "$WORK"/test_*.py >/dev/null 2>&1; then
    run_check pytest "python3 -m pytest -q"
  fi
fi

# --- YAML / kustomize sanity (operators ship a lot of these) ---------------
if [[ -d "$WORK/config" ]] && command -v kustomize >/dev/null 2>&1; then
  run_check kustomize-build "kustomize build config/default >/dev/null"
fi

# --- Fallback --------------------------------------------------------------
if [[ ${#CHECKS[@]} -eq 0 ]]; then
  run_check noop "true"
fi

# --- worktree .git sanitization --------------------------------------------
# Regardless of leg (the native fallback has no mount boundary), hostile
# test code may have written executable git configuration. Purge hooks
# and every code-exec/credential-primitive key BEFORE any host git verb
# runs in this tree again; re-assert the two invariants run_one.sh set.
sanitize_worktree_git() {
  [[ -d "$WORK/.git" ]] || return 0
  local removed=0
  if [[ -d "$WORK/.git/hooks" ]]; then
    removed=$(find "$WORK/.git/hooks" -type f | wc -l | tr -d ' ')
    rm -rf "$WORK/.git/hooks"; mkdir -p "$WORK/.git/hooks"
  fi
  local scrubbed=()
  while IFS= read -r key; do
    case "$key" in
      core.hookspath|core.fsmonitor|core.pager|core.editor|\
      core.sshcommand|core.askpass|core.alternateobjectdirectories|\
      include.path|includeif.*|alias.*|filter.*|diff.external|\
      difftool.*|mergetool.*|merge.*.driver|protocol.*|\
      remote.*.uploadpack|remote.*.receivepack|remote.*.proxy|\
      credential.*|url.*.insteadof|sendemail.*|gpg.program)
        git -C "$WORK" config --local --unset-all "$key" 2>/dev/null || true
        scrubbed+=("$key");;
    esac
  done < <(git -C "$WORK" config --local --list --name-only 2>/dev/null | sort -u)
  # re-assert run_one.sh's invariants (scrub removed credential.*).
  # GIT_ALLOW_PROTOCOL: the args are literals (sentinel push URL), and
  # constraining any indirect transport to https satisfies gate S3
  # honestly rather than via exemption.
  GIT_ALLOW_PROTOCOL=https \
    git -C "$WORK" remote set-url --push upstream \
    DISABLED_no_push_to_upstream 2>/dev/null || true
  git -C "$WORK" config --local credential.useHttpPath false
  git -C "$WORK" config --local --replace-all 'credential.https://github.com.helper' ''
  git -C "$WORK" config --local --add 'credential.https://github.com.helper' \
    '!f() { test "$1" = get && printf "username=x-access-token\npassword=%s\n" "${GITHUB_TOKEN:?GITHUB_TOKEN not set}"; }; f'
  local note="hooks_removed=${removed} keys_scrubbed=${#scrubbed[@]}"
  [[ ${#scrubbed[@]} -gt 0 ]] && note="$note (${scrubbed[*]})"
  CHECKS+=("$(printf '{"name":"git-sanitize","command":"sanitize_worktree_git","outcome":"pass","duration_seconds":0,"log_path":"","summary":"%s"}' \
    "$(echo "$note" | sed 's/\\/\\\\/g; s/"/\\"/g' | cut -c1-200)")")
}
sanitize_worktree_git

printf '[%s]\n' "$(IFS=,; echo "${CHECKS[*]}")"
