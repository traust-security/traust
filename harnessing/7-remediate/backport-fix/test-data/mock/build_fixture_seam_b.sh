#!/usr/bin/env bash
# Build the Seam B fixture: a cri-o stand-in with a remediate-finding-style
# fix commit, plus a schema-valid *-remediation.json authored from the real
# cri-o triage finding f001.
#
#   main       vulnerable internal/lib/restore.go
#   fix-f001   the remediation commit (ex-wing message, path validation)
#   release-a  still vulnerable            -> scanner: AMBIGUOUS without LLM
#   release-b  fix cherry-picked (-x)      -> scanner: ALREADY_FIXED (patch-id)
#
# Usage: build_fixture_seam_b.sh <work-dir>
set -euo pipefail
WORK="${1:?usage: build_fixture_seam_b.sh <work-dir>}"
# Resolve this script's directory BEFORE the cd below: a relative BASH_SOURCE
# stops resolving once the working directory moves into the fixture repo.
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FR="$WORK/seamB-repo"
rm -rf "$FR"; mkdir -p "$FR"; cd "$FR"
g() { git -c user.email=t@t -c user.name=t "$@"; }

git init -q -b main
mkdir -p internal/lib
cat > internal/lib/restore.go <<'GO'
package lib

import "os"

// restoreMounts recreates bind mounts from the checkpoint manifest.
func restoreMounts(dests []string) error {
	for _, d := range dests {
		// VULN: dest comes from the untrusted bind.mounts manifest and is
		// used to create host paths without validation.
		if err := os.MkdirAll(d, 0o755); err != nil {
			return err
		}
	}
	return nil
}
GO
printf 'module github.com/cri-o/cri-o\n\ngo 1.21\n' > go.mod
g add -A && g commit -qm "baseline with vulnerable restoreMounts"
BASE=$(git rev-parse HEAD)

git checkout -q -b fix-f001
cat > internal/lib/restore.go <<'GO'
package lib

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// restoreMounts recreates bind mounts from the checkpoint manifest.
func restoreMounts(dests []string) error {
	for _, d := range dests {
		clean := filepath.Clean(d)
		if !strings.HasPrefix(clean, "/run/crio/restore/") {
			return fmt.Errorf("refusing bind mount outside restore root: %q", d)
		}
		if err := os.MkdirAll(clean, 0o755); err != nil {
			return err
		}
	}
	return nil
}
GO
g add -A && g commit -qm "ex-wing: fix f001 — validate bind.mounts destinations against restore root

Reject checkpoint manifest destinations that escape the restore root
before creating host paths.

Addresses: cri-o-triage.json#f001
CWEs: CWE-22, CWE-73"
FIX=$(git rev-parse HEAD)

git checkout -q -b release-a "$BASE"
printf '4.15\n' > VERSION && g add -A && g commit -qm "release-a version marker"
RA=$(git rev-parse HEAD)
git checkout -q -b release-b "$BASE"
printf '4.16\n' > VERSION && g add -A && g commit -qm "release-b version marker"
g cherry-pick -x "$FIX" >/dev/null
RB=$(git rev-parse HEAD)
# release-c: fix applied with a drift (extra comment) — patch-id differs,
# so the scanner's file-diff heuristic yields LIKELY_PRESENT
git checkout -q -b release-c "$BASE"
printf '4.17\n' > VERSION && g add -A && g commit -qm "release-c version marker"
g cherry-pick --no-commit "$FIX" >/dev/null
printf '\n// drift: backported with local adjustments\n' >> internal/lib/restore.go
g add -A && g commit -qm "backport restore-root validation with local drift"
RC=$(git rev-parse HEAD)

git checkout -q main
git remote add origin https://github.com/cri-o/cri-o
git update-ref refs/remotes/origin/main "$BASE"
git update-ref refs/remotes/origin/fix-f001 "$FIX"
git update-ref refs/remotes/origin/release-a "$RA"
git update-ref refs/remotes/origin/release-b "$RB"
git update-ref refs/remotes/origin/release-c "$RC"
git symbolic-ref refs/remotes/origin/HEAD refs/remotes/origin/main

# Audit + triage fixtures mirroring the real cri-o f001 finding, then the
# remediation JSON built from them by make_remediation.py (dogfooding the
# "generate one from a finding" path rather than hardcoding the artifact).
python3 - "$WORK" <<'EOF'
import json, sys
work = sys.argv[1]
title = ("Checkpoint restore creates arbitrary host paths from untrusted "
         "bind.mounts manifest")
json.dump({
  "title": "cri-o Security Audit",
  "metadata": {"date": "2026-08-13", "harness_version": "0.265.0-abcdef1",
               "repository": "https://github.com/cri-o/cri-o"},
  "findings": [{
    "id": "FIND-001", "title": title, "severity": "medium",
    "cwes": ["CWE-22", "CWE-73"],
    "locations": [{"path": "internal/lib/restore.go", "lines": "143-216"}],
    "description": "Destinations from the untrusted checkpoint manifest reach "
                   "os.MkdirAll without validation, creating arbitrary host paths.",
    "remediation": "Canonicalize and confine destinations to the restore root."}],
}, open(work + "/cri-o-security-audit.json", "w"), indent=2)
json.dump({
  "title": "cri-o Triage",
  "metadata": {"date": "2026-08-13", "harness_version": "0.265.0-abcdef1",
               "repository": "https://github.com/cri-o/cri-o"},
  "findings": [{
    "id": "f001", "title": title, "severity": "medium",
    "file": "internal/lib/restore.go", "line": 143,
    "verdict": "true_positive",
    "source": "cri-o-security-audit.json#FIND-001"}],
}, open(work + "/cri-o-triage.json", "w"), indent=2)
EOF

# 5 levels up: mock → test-data → backport-fix → 7-remediate → harnessing → repo root
HARNESS_ROOT="$(cd "$HERE/../../../../.." && pwd)"
python3 "$HARNESS_ROOT/harnessing/7-remediate/backport-fix/scripts/make_remediation.py" \
  --triage "$WORK/cri-o-triage.json" --finding f001 \
  --fix-commit "$FIX" --repo "$FR" \
  --strategy input-validation \
  --rationale "Reject checkpoint manifest bind-mount destinations that escape the restore root before any host path is created." \
  --build-cmd "GOMAXPROCS=2 make" --test-cmd "go build ./..." \
  --check-outcome pass --status checks_passed \
  --product cri-o --language Go --operator seam-b-mock \
  --no-validate \
  --out "$WORK/cri-o.f001-remediation.json" >/dev/null

echo "seam B fixture ready: $FR (+ cri-o.f001-remediation.json via make_remediation.py); fix commit: $FIX"
