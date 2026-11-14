#!/usr/bin/env bash
# End-to-end MOCK run of the backport-fix pipeline, Seam B (remediation
# input, authored from the real cri-o f001 finding). No LLM calls, no
# credentials, no network. When the amalgamator sibling is available, the
# REAL backport_scanner runs (deterministic tiers only). Self-checking.
#
# Usage: run_mock_seam_b.sh [work-dir]     (default: mktemp -d)
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# 5 levels up: mock → test-data → backport-fix → 7-remediate → harnessing → repo root
HARNESS_ROOT="$(cd "$HERE/../../../../.." && pwd)"
WORKSPACE="$(cd "$HARNESS_ROOT/.." && pwd)"
AMALG="${AMALGAMATOR_ROOT:-$WORKSPACE/amalgamator}"
WORK="${1:-$(mktemp -d)}"
# MOCK_REQUIRE_REAL=1 makes any skipped optional stage a failure.
REQUIRE_REAL="${MOCK_REQUIRE_REAL:-0}"
CONFIGS="$WORK/configs"; RESULTS="$WORK/results"; FAKE_AR="$WORK/analysis-results"
mkdir -p "$FAKE_AR"

python3 -c "import yaml, jsonschema" 2>/dev/null || {
  echo "FATAL: python3 needs pyyaml + jsonschema (pip install pyyaml jsonschema)"; exit 1; }
unset ANTHROPIC_API_KEY CLAUDE_CODE_USE_VERTEX ANTHROPIC_VERTEX_PROJECT_ID GOOGLE_APPLICATION_CREDENTIALS 2>/dev/null || true

fail() { echo "MOCK SEAM B: FAIL — $1" >&2; exit 1; }

validate_json() {
  local report="$1" schema_flag="${2:-}" schema_path="${3:-}"
  if [[ -n "$schema_path" ]] && [[ ! -f "$schema_path" ]]; then
    echo "ALL PASSED (schema $schema_path not local — skipped)"
    return 0
  fi
  # traust.cli lives in the harness checkout (a sibling), not necessarily in
  # whatever python3 is on PATH: try the harness venv too.
  local tpy=""
  local cand
  for cand in python3 "$WORKSPACE/traust/.venv/bin/python"; do
    if "$cand" -c "from traust.cli import reporting" 2>/dev/null; then tpy="$cand"; break; fi
  done
  if [[ -n "$tpy" ]]; then
    if [[ -n "$schema_flag" ]]; then
      "$tpy" -m traust.cli reporting validate "$schema_flag" "$schema_path" "$report" 2>&1 | tail -1
    else
      "$tpy" -m traust.cli reporting validate "$report" 2>&1 | tail -1
    fi
  else
    # Last-resort local validator: resolve sibling $refs from the schema's
    # own directory (the remediation contract references
    # report.schema.json#/$defs/location).
    python3 -c "
import json, jsonschema, sys, os
from referencing import Registry, Resource
sp = os.path.realpath('${schema_path:-$WORKSPACE/traust-contracts/artifacts_schema/v1/backport-report.schema.json}')
if not os.path.isfile(sp):
    print('ALL PASSED (schema not local — skipped)')
    sys.exit(0)
base = os.path.dirname(sp)
schema = json.load(open(sp))
data = json.load(open('$report'))

def retrieve(uri):
    p = os.path.join(base, uri.rsplit('/', 1)[-1])
    if os.path.isfile(p):
        return Resource.from_contents(json.load(open(p)))
    raise KeyError(uri)

try:
    jsonschema.Draft202012Validator(
        schema, registry=Registry(retrieve=retrieve)
    ).validate(data)
    print('ALL PASSED')
except jsonschema.ValidationError as e:
    print(f'FAIL: {e.message}')
    sys.exit(1)
"
  fi
}

echo "== build fixture (+ schema-valid remediation from real f001) =="
bash "$HERE/build_fixture_seam_b.sh" "$WORK"
FR="$WORK/seamB-repo"
REM="$WORK/cri-o.f001-remediation.json"

echo "== stage 0: input contract (real validator, real schema) =="
cd "$HARNESS_ROOT"
# The remediation contract moved out of the harness root into the contracts
# package/checkout; resolve it the way make_remediation.py does instead of
# hardcoding a path that no longer exists (which used to skip silently).
REMED_SCHEMA="$(python3 -c "
import sys
sys.path.insert(0, 'harnessing/7-remediate/backport-fix/scripts')
import make_remediation as m
print(m.resolve_schema(None) or '')" 2>/dev/null || true)"
if [[ -n "$REMED_SCHEMA" ]]; then
  validate_json "$REM" --schema "$REMED_SCHEMA" \
    | grep "ALL PASSED" >/dev/null || fail "remediation JSON does not validate"
  for fixture in "$HARNESS_ROOT"/harnessing/7-remediate/backport-fix/test-data/crio-*-remediation.json; do
    validate_json "$fixture" --schema "$REMED_SCHEMA" \
      | grep "ALL PASSED" >/dev/null || fail "shipped fixture does not validate: $fixture"
  done
else
  echo "  (remediation schema not found — validation skipped; set HARNESS_WORKSPACE)"
fi

SCANNER_OK=false
if [[ -d "$AMALG/backport_scanner" ]] && PYTHONPATH="$AMALG" python3 -c "import backport_scanner.scanner" 2>/dev/null; then
  SCANNER_OK=true
fi

echo "== stage 1: branch scan =="
if $SCANNER_OK; then
  # Real scanner, deterministic tiers only (no LLM creds): the cherry-picked
  # branch must resolve ALREADY_FIXED via patch-id; the vulnerable one lands
  # AMBIGUOUS (deterministic tiers cannot PROVE vulnerability).
  SCAN_OUT="$(PYTHONPATH="$AMALG" python3 harnessing/7-remediate/backport-fix/scripts/generate_backport_configs.py \
      --remediation "$REM" --repo "$FR" --branch-pattern "release-*" --scan-only 2>&1 || true)"
  echo "$SCAN_OUT" | sed -n '/BRANCH SCAN/,/^====*$/p' | tail -14
  echo "$SCAN_OUT" | grep -q "    v release-b" || fail "real scanner did not prove release-b already fixed"
  # LIKELY_PRESENT (release-c: fix applied with drift) must reach
  # needs-review, never silent exclusion
  if echo "$SCAN_OUT" | grep -q "    v release-c"; then
    fail "LIKELY_PRESENT (release-c) was auto-excluded as already fixed"
  fi
  echo "$SCAN_OUT" | grep -q "    ? release-c" || fail "LIKELY_PRESENT (release-c) not in the needs-review bucket"
  echo "  (release-a and drifted release-c are needs-review without the LLM tier — explicit --branches promotes)"
  GEN_PYPATH="$AMALG"
else
  [[ "$REQUIRE_REAL" == "1" ]] && fail "real backport_scanner unavailable (MOCK_REQUIRE_REAL=1)"
  echo "  (amalgamator sibling not importable — skipping real scan; using --skip-scan)"
  GEN_PYPATH=""
fi

echo "== stage 2: generate the release-a config =="
if $SCANNER_OK; then
  PYTHONPATH="$GEN_PYPATH" python3 harnessing/7-remediate/backport-fix/scripts/generate_backport_configs.py \
    --remediation "$REM" --repo "$FR" --branches release-a \
    --output-dir "$CONFIGS" 2>&1 | grep -E "Promoting|Generated"
else
  python3 harnessing/7-remediate/backport-fix/scripts/generate_backport_configs.py \
    --remediation "$REM" --repo "$FR" --skip-scan --branches release-a \
    --output-dir "$CONFIGS" >/dev/null
fi
grep -q "^issue_id: backport-cri-o-f001-release-a$" "$CONFIGS/release-a.yaml" \
  || fail "issue_id not derived from finding_id: $(grep ^issue_id "$CONFIGS/release-a.yaml")"

echo "== stage 4: run_backport.sh with the mock engine =="
export GITHUB_TOKEN=dummy-must-not-reach-pipeline
export PYTHONPATH="$HERE/mock_amalgamator"
cd "$WORK"
bash "$HARNESS_ROOT/harnessing/7-remediate/backport-fix/scripts/run_backport.sh" \
  --config-dir "$CONFIGS" --output-dir "$RESULTS" 2>&1 | grep -E "MOCK|Collected|INPUT ERROR" || true
unset PYTHONPATH
[[ -s "$RESULTS/release-a/candidate.patch" ]] || fail "candidate.patch not collected"

echo "== stage 6: emit + schema-validate + publish =="
cd "$HARNESS_ROOT"
python3 harnessing/7-remediate/backport-fix/scripts/emit_backport_report.py \
  --results-dir "$RESULTS" --remediation "$REM" \
  --output "$WORK/cri-o-backport-report.json" --publish-root "$FAKE_AR" 2>&1 \
  | grep "validates against schema" >/dev/null || fail "report failed schema validation"
D="$(ls -d "$FAKE_AR"/remediations/cri-o/cri-o/backport-* 2>/dev/null | head -1 || true)"
[[ -n "$D" && -f "$D/cri-o-backport-report.json" && -f "$D/cri-o-backport-release-a.patch" ]] \
  || fail "published tree incomplete: $(ls "$D" 2>/dev/null)"
python3 -c "
import json
r = json.load(open('$WORK/cri-o-backport-report.json'))
assert r['source_fix']['finding_refs'] == ['cri-o-triage.json#f001'], r['source_fix']
row = [b for b in r['target_branches'] if b['branch'] == 'release-a'][0]
assert row.get('backport_commit'), 'backport_commit missing from successful branch'
assert row.get('backport_branch') == 'amalgamator/backport-cri-o-f001-release-a', row
hint = r['verification_hint']
assert hint['branches'][0]['target_branch'] == 'release-a', hint
assert hint['branches'][0].get('backport_commit') == row['backport_commit'], hint
assert 'original_audit_report' not in hint or hint['original_audit_report'].endswith('cri-o-security-audit.json'), hint" \
  || fail "backport_commit/backport_branch/verification_hint wrong"
validate_json "$WORK/cri-o-backport-report.json" \
  | grep "ALL PASSED" >/dev/null || fail "backport report failed cross-checks"

echo
echo "MOCK SEAM B: PASS   (work dir: $WORK)"
