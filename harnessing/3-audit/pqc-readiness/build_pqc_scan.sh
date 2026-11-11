#!/usr/bin/env bash
# Build the pinned pqc-scan binary into harnessing/3-audit/pqc-readiness/bin/.
# Supply-chain posture: pinned commit, --locked build, sha256 recorded.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
HARNESS="${HERE}"
while [ ! -f "${HARNESS}/pyproject.toml" ] && [ "${HARNESS}" != / ]; do
  HARNESS="$(dirname "${HARNESS}")"
done
[ -f "${HARNESS}/pyproject.toml" ] || { echo "harness root not found above ${HERE}" >&2; exit 1; }
# shellcheck source=../../_lib/traust_paths.sh
source "${HARNESS}/harnessing/_lib/traust_paths.sh"
PIN="be5c760adb7d1d4d99e39d35d87d2956079db76e"

# cargo writes target/ inside the checkout, so it must be writable
SRC="$("$(_traust_py)" -m traust.cli repo checkout \
  https://github.com/wakaken/pqc-scan --ref "$PIN" --writable)"
ACTUAL="$(git -C "$SRC" rev-parse HEAD)"
[ "$ACTUAL" = "$PIN" ] || { echo "pin mismatch: $ACTUAL != $PIN" >&2; exit 1; }

( cd "$SRC" && cargo build --release --locked )
mkdir -p "$HERE/bin"
cp "$SRC/target/release/pqc-scan" "$HERE/bin/pqc-scan"
shasum -a 256 "$HERE/bin/pqc-scan" | tee "$HERE/bin/pqc-scan.sha256"
echo "pqc-scan built at $HERE/bin/pqc-scan (commit $PIN)"
