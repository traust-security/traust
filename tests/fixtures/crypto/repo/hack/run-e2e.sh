#!/usr/bin/env bash
set -euo pipefail
GODEBUG=tlsmlkem=0 go test ./test/e2e/...
GODEBUG=fips140=on ./bin/manager --health-probe-bind-address=:8081
update-crypto-policies --set FIPS
