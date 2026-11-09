#!/usr/bin/env bash
# Build the Seam A fixture: a Go-module repo with a bump history plus an
# impact-analysis JSON in the REAL artifact shape (bare fixed_version).
#
# Branch archetypes (module google.golang.org/grpc, fixed_version 1.71.3):
#   release-1  v1.50.0                    -> NEEDS_FIX
#   release-2  v1.71.3 (different z-stream than main) -> ALREADY_FIXED
#   release-3  module absent              -> NOT_AFFECTED
#   release-4  replace => local path      -> AMBIGUOUS
#   release-5  modules.txt versioned-LHS path replace -> AMBIGUOUS
#   release-6  vanity replacement path with version   -> ALREADY_FIXED
#   main       c1(v1.50.0) -> c2 BUMP(v1.79.3) -> c3 unrelated go.mod touch
#
# Usage: build_fixture_seam_a.sh <work-dir>
set -euo pipefail
WORK="${1:?usage: build_fixture_seam_a.sh <work-dir>}"
FR="$WORK/seamA-repo"
rm -rf "$FR"; mkdir -p "$FR"; cd "$FR"
g() { git -c user.email=t@t -c user.name=t "$@"; }

git init -q -b main
printf 'module example.com/myrepo\n\ngo 1.21\n\nrequire google.golang.org/grpc v1.50.0\n' > go.mod
mkdir vendor && printf '# google.golang.org/grpc v1.50.0\n## explicit\n' > vendor/modules.txt
g add -A && g commit -qm "c1 grpc 1.50.0"; C1=$(git rev-parse HEAD)
printf 'module example.com/myrepo\n\ngo 1.21\n\nrequire google.golang.org/grpc v1.79.3\n' > go.mod
printf '# google.golang.org/grpc v1.79.3\n## explicit\n' > vendor/modules.txt
g add -A && g commit -qm "c2 bump grpc 1.79.3"; C2=$(git rev-parse HEAD)
printf 'module example.com/myrepo\n\ngo 1.21\n\nrequire google.golang.org/grpc v1.79.3\n// trailing comment\n' > go.mod
g add -A && g commit -qm "c3 unrelated go.mod touch"; C3=$(git rev-parse HEAD)

git checkout -q -b release-2 "$C1"
printf 'module example.com/myrepo\n\ngo 1.21\n\nrequire google.golang.org/grpc v1.71.3\n' > go.mod
printf '# google.golang.org/grpc v1.71.3\n## explicit\n' > vendor/modules.txt
g add -A && g commit -qm "r2 z-stream 1.71.3"; R2=$(git rev-parse HEAD)
git checkout -q -b release-3 "$C1"
printf 'module example.com/myrepo\n\ngo 1.21\n' > go.mod; git rm -qr vendor
g add -A && g commit -qm "r3 no grpc"; R3=$(git rev-parse HEAD)
git checkout -q -b release-4 "$C1"
printf 'module example.com/myrepo\n\ngo 1.21\n\nrequire google.golang.org/grpc v1.50.0\n\nreplace google.golang.org/grpc => ../local-grpc\n' > go.mod
git rm -qr vendor
g add -A && g commit -qm "r4 path replace"; R4=$(git rev-parse HEAD)
git checkout -q -b release-5 "$C1"
printf '# google.golang.org/grpc v1.50.0 => ./local-grpc\n## explicit\n' > vendor/modules.txt
g add -A && g commit -qm "r5 versioned-LHS path replace"; R5=$(git rev-parse HEAD)
git checkout -q -b release-6 "$C1"
printf '# google.golang.org/grpc v1.50.0 => vitess.io/grpc v1.79.9\n## explicit\n' > vendor/modules.txt
g add -A && g commit -qm "r6 vanity replacement with version"; R6=$(git rev-parse HEAD)

git checkout -q main
git remote add origin https://github.com/example/myrepo
git update-ref refs/remotes/origin/main "$C3"
git update-ref refs/remotes/origin/release-1 "$C1"
git update-ref refs/remotes/origin/release-2 "$R2"
git update-ref refs/remotes/origin/release-3 "$R3"
git update-ref refs/remotes/origin/release-4 "$R4"
git update-ref refs/remotes/origin/release-5 "$R5"
git update-ref refs/remotes/origin/release-6 "$R6"
git symbolic-ref refs/remotes/origin/HEAD refs/remotes/origin/main

# Impact artifact in the REAL shape: bare (un-prefixed) fixed_version.
python3 - "$WORK" <<'EOF'
import json, sys
json.dump({
    "metadata": {"cve": "CVE-2026-4242", "module": "google.golang.org/grpc",
                 "ecosystem": "go", "vulnerable_range": "< 1.71.3",
                 "fixed_version": "1.71.3"},
    "repos": [{"repo": "repo:github.com/example/myrepo",
               "products": ["example-product"],
               "classification": "version_not_in_range",
               "version": "v1.79.3", "direct": True, "evidence": {}}],
}, open(sys.argv[1] + "/seamA-impact.json", "w"), indent=2)
EOF
echo "seam A fixture ready: $FR (+ seamA-impact.json); bump commit: $C2"
