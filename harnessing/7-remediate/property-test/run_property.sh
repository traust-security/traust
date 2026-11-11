#!/usr/bin/env bash
# Run a property test against the UNPATCHED and PATCHED revisions and emit one
# evidence item matching remediation.schema.json#/$defs/patch_evidence
# (kind: property).
#
# The evidence is the asymmetry, not the pass: a property that fails on the
# base revision and passes on the patched one witnesses the finding and now
# guards it. A property that passes on both may be a fine test but says
# nothing about this fix. `traust remediation property-evidence` holds that logic.
#
# Containment (S9/S10). Both runs execute the target's test suite, which is
# hostile-input execution, so this inherits run_checks.sh's boundary:
# rootless, cap-dropped, no-new-privileges, credential-free, digest-pinned
# image, --network=none for the test runs. Dependencies are fetched in a
# separate networked, script-less step (pip --no-deps on a pinned version,
# rule S7) exactly as run_checks.sh prefetches. The mode comes from
# `execution.sandbox` in $TRAUST_CONFIG_HOME/traust.yaml (default
# `none`); a configured `podman` mode is never silently downgraded.
#
# Neither run touches the caller's worktree. Both are disposable copies —
# the patched one as-is, the base one reset to <base-ref> with the property
# test injected, because the test does not exist at that revision.
#
# Usage:
#   run_property.sh <worktree> <base-ref> <test-path> [<out-dir>] [<timeout-s>]
#
# <test-path> is relative to the worktree root.
# Output (stdout): one JSON object (a patch_evidence item).

set -uo pipefail

WORK="${1:?usage: run_property.sh <worktree> <base-ref> <test-path> [<out>] [<timeout-s>]}"
BASE_REF="${2:?usage: run_property.sh <worktree> <base-ref> <test-path> [<out>] [<timeout-s>]}"
TEST_PATH="${3:?usage: run_property.sh <worktree> <base-ref> <test-path> [<out>] [<timeout-s>]}"
OUT="${4:-$WORK/.remediation-checks}"
TIMEOUT_S="${5:-${REMEDIATION_PROPERTY_TIMEOUT:-900}}"
mkdir -p "$OUT"

# Pinned exactly (rule S7), and the WHOLE closure is pinned, not just the two
# packages we name. An earlier version used `--no-deps` with a guessed list and
# missed pluggy, so pytest could not import itself — which then looked like a
# failing property. Resolved in the pinned image on 2026-09-16; re-resolve
# deliberately when bumping, never let it float.
HYPOTHESIS_PIN="${REMEDIATION_HYPOTHESIS_PIN:-6.168.0}"
PROP_DEPS=(
  "hypothesis==$HYPOTHESIS_PIN"
  "pytest==8.4.2"
  "iniconfig==2.3.0"
  "packaging==26.3"
  "pluggy==1.6.0"
  "pygments==2.21.0"
  "sortedcontainers==2.4.0"
)
IMG_PY="${REMEDIATION_IMG_PY:-docker.io/library/python@sha256:9bed8554e926c07c6f908841d5ee88c33e8df9236b191526bbce81a9062ab43a}"


emit_not_attempted() {
  python3 - "$1" <<'INNER'
import json, sys
print(json.dumps({
    "kind": "property",
    "outcome": f"not_attempted: {sys.argv[1]}",
    "tool": "hypothesis",
    "deterministic_steps": f"skipped: {sys.argv[1]}",
}))
INNER
  exit 0
}

# --- execution boundary (config, not environment) ----------------------------
# How target build/test code runs is a deployment decision, read once from
# `execution.sandbox` in $TRAUST_CONFIG_HOME/traust.yaml:
#
#   none    (default) run directly — scrubbed env, disposable copy
#   podman  nested rootless container, --network=none, digest-pinned image
#
# `podman` is not silently downgraded: if the mode asks for a container and no
# working runtime exists, the lane reports `not_attempted`, because quietly
# weakening the boundary someone configured is worse than producing no
# evidence. Detection is `podman info` rather than `command -v podman` — the
# client binary exists on a host whose VM is stopped and in images that ship
# the CLI with no runtime.
#
# The resolved mode is recorded in the emitted evidence.
resolve_boundary() {
  local cfg="${TRAUST_CONFIG_HOME:-$HOME/.traust/config}/traust.yaml"
  local mode
  mode="$(python3 - "$cfg" <<'CFG'
import sys
mode = "none"
try:
    import yaml
    with open(sys.argv[1], encoding="utf-8") as fh:
        doc = yaml.safe_load(fh) or {}
    mode = str((doc.get("execution") or {}).get("sandbox") or "none").strip().lower()
except Exception:
    pass  # absent or unreadable config -> the documented default
print(mode if mode in ("none", "podman") else "none")
CFG
)"
  printf '%s' "$mode"
}

BOUNDARY="$(resolve_boundary)"
if [[ "$BOUNDARY" == podman ]] && ! podman info >/dev/null 2>&1; then
  emit_not_attempted "traust.yaml asks for execution.sandbox: podman but no working podman runtime is available"
fi
[[ -f "$WORK/pyproject.toml" || -f "$WORK/setup.py" || -f "$WORK/setup.cfg" ]] \
  || emit_not_attempted "not a Python project; Go (rapid) and TS (fast-check) are not wired yet"
[[ -f "$WORK/$TEST_PATH" ]] || emit_not_attempted "property test not found at $TEST_PATH"

SB_PATCHED="$(mktemp -d "${TMPDIR:-/tmp}/prop-patched-XXXXXX")"
SB_BASE="$(mktemp -d "${TMPDIR:-/tmp}/prop-base-XXXXXX")"
cleanup() {
  chmod -R u+w "$SB_PATCHED" "$SB_BASE" 2>/dev/null
  rm -rf "$SB_PATCHED" "$SB_BASE"
}
trap cleanup EXIT INT TERM

cp -a "$WORK/." "$SB_PATCHED/" 2>/dev/null || emit_not_attempted "could not copy the worktree"
cp -a "$WORK/." "$SB_BASE/"    2>/dev/null || emit_not_attempted "could not copy the worktree"

# Reset the base copy to the pre-patch revision, then put the property test
# back: it does not exist at that revision, and without it there is nothing
# to compare.
git -C "$SB_BASE" checkout --quiet --force "$BASE_REF" -- . \
  || emit_not_attempted "could not reset the base copy to $BASE_REF"
mkdir -p "$(dirname "$SB_BASE/$TEST_PATH")"
cp "$WORK/$TEST_PATH" "$SB_BASE/$TEST_PATH" \
  || emit_not_attempted "could not inject the property test into the base copy"

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

# Import path for the target's own package. run_checks.sh relies on the repo
# being importable from the rootdir, which holds for a flat layout and fails
# for a src/ layout; adding both covers the common cases without a network
# install of the project.
PYPATH="/work/.prop-deps:/work:/work/src"   # /work rewritten on the attested path

in_boundary() {
  # in_boundary <netmode> <sandbox> <cmd...> — netmode applies to the podman
  # path; on the attested path the surrounding job owns the network policy.
  local netmode="$1" sandbox="$2"; shift 2
  if [[ "$BOUNDARY" == podman ]]; then
    podman run --rm --network="$netmode" \
      --security-opt=no-new-privileges --cap-drop=ALL \
      --user "$(id -u):$(id -g)" --userns=keep-id \
      --tmpfs /home/runner:rw,mode=700 -e HOME=/home/runner \
      -e PYTHONDONTWRITEBYTECODE=1 \
      -v "$sandbox":/work:Z \
      -w /work "$IMG_PY" bash -c "$*"
  else
    # sandbox: none — /work is the container path baked into the commands, so
    # rewrite it to the real sandbox directory.
    local cmd="${*//\/work/$sandbox}"
    ( cd "$sandbox" && env -i PATH="$PATH" HOME="${HOME:-/tmp}" \
        PYTHONDONTWRITEBYTECODE=1 bash -c "$cmd" )
  fi
}

# Networked, script-less dependency step; the test runs offline afterwards.
# --no-deps and an exact pin keep this from becoming an open install.
EGRESS="$(egress_netmode)"
for sb in "$SB_PATCHED" "$SB_BASE"; do
  in_boundary "$EGRESS" "$sb" \
    "python3 -m pip install --quiet --no-deps --target /work/.prop-deps ${PROP_DEPS[*]}" \
    >>"$OUT/property-deps.log" 2>&1 || true
done

# Precondition, not an afterthought: prove the test harness itself runs before
# running the differential. Without this an environmental failure (pytest
# unable to import its own dependency) exits 1 and is indistinguishable from
# "the property found a counterexample" — which is exactly how a broken
# sandbox once produced a confident `fails_to_prove`.
for sb in "$SB_PATCHED" "$SB_BASE"; do
  in_boundary none "$sb" \
    "PYTHONPATH=$PYPATH python3 -m pytest --version >/dev/null 2>&1 && \
     PYTHONPATH=$PYPATH python3 -c 'import hypothesis' >/dev/null 2>&1" \
    >>"$OUT/property-deps.log" 2>&1 \
    || emit_not_attempted "pytest+hypothesis could not run in the sandbox (see $OUT/property-deps.log)"
done

HYPO_VERSION="$(in_boundary none "$SB_PATCHED" \
  "PYTHONPATH=$PYPATH python3 -c 'import hypothesis; print(hypothesis.__version__)'" 2>/dev/null | tr -d '\r')"

run_one() {
  # run_one <sandbox> <logfile> -> pytest exit code
  local sandbox="$1" log="$2"
  in_boundary none "$sandbox" \
    "PYTHONPATH=$PYPATH timeout --signal=TERM --kill-after=30 $TIMEOUT_S \
       python3 -m pytest -p no:cacheprovider -q '$TEST_PATH'" >"$log" 2>&1
  echo $?
}

BASE_LOG="$OUT/property-base.log"
PATCHED_LOG="$OUT/property-patched.log"
BASE_RC="$(run_one "$SB_BASE" "$BASE_LOG")"
PATCHED_RC="$(run_one "$SB_PATCHED" "$PATCHED_LOG")"

python3 -m traust.cli remediation property-evidence \
  --test-path "$TEST_PATH" --base-ref "$BASE_REF" \
  --base-rc "$BASE_RC" --patched-rc "$PATCHED_RC" \
  --tool-version "${HYPO_VERSION:+hypothesis $HYPO_VERSION}" \
  --base-log "$BASE_LOG" --patched-log "$PATCHED_LOG" \
  --boundary "$BOUNDARY"
