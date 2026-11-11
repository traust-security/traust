#!/usr/bin/env bash
# Build the split toolchain images: traust-toolchain (pinned scanner binaries) and
# traust-runtime (FROM it, by digest, plus the pinned traust Python stack).
#
# Usage:
#   ./scripts/build-toolchain-image.sh                      # both images
#   ./scripts/build-toolchain-image.sh --tools-only          # just traust-toolchain
#   ./scripts/build-toolchain-image.sh --tag myregistry/traust-runtime:v0.37.1
#   ./scripts/build-toolchain-image.sh --tools-tag myregistry/traust-toolchain:latest
#
# Scanner versions and the pin-set hash come from the external-tools.yaml traust-core ships
# (scripts/containerfile-build-args.py); the Python stack's pinned Git SHAs come from
# pyproject.toml / uv.lock. Never edit the Containerfiles' scanner ARGs directly.
#
# traust-runtime always builds FROM the tools image it just built, by digest — never by a
# floating tag — so a stale local :latest tag can't silently supply the wrong pin set.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Prefer the repo's own uv-managed environment (pyyaml is a project dependency, not necessarily
# on a bare system python3); fall back to plain python3 for a CI runner that installs deps
# globally instead.
if command -v uv >/dev/null 2>&1; then
  PYTHON=(uv run --project "$REPO_ROOT" python3)
else
  PYTHON=(python3)
fi

TOOLS_ONLY="false"
RUNTIME_TAG=""
TOOLS_TAG=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --tools-only)  TOOLS_ONLY="true"; shift ;;
    --tag=*)       RUNTIME_TAG="${1#--tag=}"; shift ;;
    --tag)         RUNTIME_TAG="$2"; shift 2 ;;
    --tools-tag=*) TOOLS_TAG="${1#--tools-tag=}"; shift ;;
    --tools-tag)   TOOLS_TAG="$2"; shift 2 ;;
    *)             echo "Unknown argument: $1" >&2; exit 1 ;;
  esac
done

PIN_HASH="$("${PYTHON[@]}" "$SCRIPT_DIR/containerfile-build-args.py" --pin-hash)"
TOOLS_TAG="${TOOLS_TAG:-traust-toolchain:toolchain-$PIN_HASH}"
RUNTIME_TAG="${RUNTIME_TAG:-traust-runtime:$PIN_HASH}"

BUILD_ARGS=$("${PYTHON[@]}" "$SCRIPT_DIR/containerfile-build-args.py")

echo "Pin-set hash: $PIN_HASH"
echo "Building $TOOLS_TAG from configured pins..."
echo "  $BUILD_ARGS"
echo ""

# shellcheck disable=SC2086
podman build -f "$REPO_ROOT/Containerfile.tools" \
  $BUILD_ARGS \
  -t "$TOOLS_TAG" \
  "$REPO_ROOT"

echo ""
echo "Built: $TOOLS_TAG"
echo "Verify: podman run --rm --entrypoint grype $TOOLS_TAG --version"

if [[ "$TOOLS_ONLY" == "true" ]]; then
  exit 0
fi

# Build FROM the tools image this run just produced, by its local digest — not the tag, which
# a later build could move. `podman image inspect --format '{{.Digest}}'` computes the manifest
# digest of a local image without requiring a push.
TOOLS_DIGEST="$(podman image inspect "$TOOLS_TAG" --format '{{.Digest}}')"
VCS_REF="$(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null || echo unknown)"
# Strip the trailing :tag only (the last colon), so a registry host with a port
# (registry.io:5000/name:tag) keeps its port. Resolves from local storage either way — no
# "localhost/" qualifier needed, verified against both a bare and a registry-qualified name.
TOOLS_REPO="${TOOLS_TAG%:*}"

echo ""
echo "Building $RUNTIME_TAG FROM ${TOOLS_REPO}@$TOOLS_DIGEST..."

podman build -f "$REPO_ROOT/Containerfile.runtime" \
  --build-arg "TOOLS_IMAGE=${TOOLS_REPO}@${TOOLS_DIGEST}" \
  --build-arg "TOOLCHAIN_HASH=$PIN_HASH" \
  --build-arg "VCS_REF=$VCS_REF" \
  -t "$RUNTIME_TAG" \
  "$REPO_ROOT"

echo ""
echo "Built: $TOOLS_TAG (digest $TOOLS_DIGEST)"
echo "Built: $RUNTIME_TAG (FROM $TOOLS_TAG by digest, commit $VCS_REF)"
echo "Verify: podman run --rm $RUNTIME_TAG admin toolchain doctor --profile secure-code-audit"
