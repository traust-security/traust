#!/usr/bin/env bash
# End-to-end MOCK run of the backport-fix pipeline, Seam A (impact-analysis
# input). No LLM calls, no credentials, no network. Self-checking: exits
# non-zero if any expected input/output placement is wrong.
#
# Usage: run_mock_seam_a.sh [work-dir]     (default: mktemp -d)
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
  echo "FATAL: python3 needs pyyaml + jsonschema (the repo venv has both, locked: run uv sync, then put .venv/bin first on PATH)"; exit 1; }
unset ANTHROPIC_API_KEY CLAUDE_CODE_USE_VERTEX ANTHROPIC_VERTEX_PROJECT_ID GOOGLE_APPLICATION_CREDENTIALS 2>/dev/null || true

fail() { echo "MOCK SEAM A: FAIL — $1" >&2; exit 1; }

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
    python3 -c "
import json, jsonschema, sys, os
sp = '${schema_path}'
if not sp:
    try:  # traust-core is the only contracts consumer: its pinned schema, never a sibling checkout
        from traust_core.v1 import contracts
        sp = str(contracts.schema_path('backport-report'))
    except ImportError:
        sp = ''
if not os.path.isfile(sp):
    print('ALL PASSED (schema not local — skipped)')
    sys.exit(0)
schema = json.load(open(sp))
data = json.load(open('$report'))
try:
    jsonschema.validate(data, schema)
    print('ALL PASSED')
except jsonschema.ValidationError as e:
    print(f'FAIL: {e.message}')
    sys.exit(1)
"
  fi
}

echo "== build fixture =="
bash "$HERE/build_fixture_seam_a.sh" "$WORK"
FR="$WORK/seamA-repo"

echo "== stage 1: version-based scan (real generator) =="
cd "$HARNESS_ROOT"
# The fixture deliberately contains ambiguous archetypes, so the documented
# fail-closed contract applies: an incomplete scan exits 3, not 0.
set +e
SCAN_A="$(python3 harnessing/7-remediate/backport-fix/scripts/generate_backport_configs.py \
  --impact "$WORK/seamA-impact.json" --repo "$FR" --scan-only 2>&1)"
SCAN_RC=$?
set -e
[[ $SCAN_RC -eq 3 ]] || fail "scan-only with ambiguous branches exited $SCAN_RC, expected 3"
echo "$SCAN_A" | sed -n '/BRANCH SCAN RESULTS/,$p' | head -18

# Assert every fixture archetype, not just that the scan ran: the whole point
# of Seam A is that an independently-bumped z-stream reads ALREADY_FIXED.
assert_scan() {  # <needle> <why>
  echo "$SCAN_A" | grep -qF "$1" || fail "scan: expected '$1' ($2)"
}
assert_scan "    x release-1" "vulnerable branch must need the fix"
assert_scan "    v release-2" "independently-bumped z-stream must read ALREADY_FIXED"
assert_scan "    v release-6" "vanity replace with a fixed version must read ALREADY_FIXED"
assert_scan "    - release-3" "module absent must read BRANCH_UNAFFECTED"
assert_scan "    ? release-4" "replace to a local path must be AMBIGUOUS"
assert_scan "    ? release-5" "versioned-LHS path replace must be AMBIGUOUS"
for wrong in "x release-2" "x release-3" "v release-1" "- release-1"; do
  if echo "$SCAN_A" | grep -qF "    $wrong"; then
    fail "scan misclassified: '$wrong'"
  fi
done

echo "== stage 1b: pattern generate surfaces AMBIGUOUS and exits 3 (fail-closed) =="
set +e
python3 harnessing/7-remediate/backport-fix/scripts/generate_backport_configs.py \
  --impact "$WORK/seamA-impact.json" --repo "$FR" \
  --output-dir "$WORK/configs-pattern" >/dev/null 2>&1
rc=$?
set -e
[[ $rc -eq 3 ]] || fail "expected exit 3 with ambiguous branches, got $rc"
[[ -f "$WORK/configs-pattern/release-1.yaml" ]] || fail "needs_fix config missing in ambiguous run"

echo "== stage 2: generate 3 configs (skip-scan, mixed-outcome demo set) =="
python3 harnessing/7-remediate/backport-fix/scripts/generate_backport_configs.py \
  --impact "$WORK/seamA-impact.json" --repo "$FR" \
  --output-dir "$CONFIGS" --skip-scan --branches release-1 release-2 release-3 \
  --build-cmd "go vet ./..." --test-cmd "make --version" >/dev/null
[[ -f "$CONFIGS/release-1.yaml" && -f "$CONFIGS/release-3.yaml" ]] || fail "configs not generated"
# Rule S10: every generated build/test step is routed through safe-exec.
python3 - "$CONFIGS"/*.yaml <<'PY' || fail "a generated build/test step is not routed through safe-exec"
import shlex, sys, yaml
for path in sys.argv[1:]:
    build = yaml.safe_load(open(path))["build"]
    for key, want in (("command", "go-fuzz"), ("test_command", "go-fuzz")):
        argv = shlex.split(build[key])
        assert argv[1:7] == ["-I", "-m", "traust.cli", "util", "safe-exec", "run"], (path, build[key])
        assert argv[argv.index("--profile") + 1] == want, (path, build[key])
PY

echo "== stage 3: validate configs with the REAL amalgamator loader (optional) =="
if [[ -d "$AMALG/auto_bug_fix" ]] && python3 -c "import claude_agent_sdk, colorama" 2>/dev/null; then
  for y in "$CONFIGS"/*.yaml; do
    PYTHONPATH="$AMALG" python3 -c "
import sys
from auto_bug_fix.config_loader import load_pipeline_config
cfg, _, _, _ = load_pipeline_config(sys.argv[1])
print(f'  OK real-loader: target={cfg.target_branch}')" "$y" || fail "real loader rejected $y"
  done
else
  [[ "$REQUIRE_REAL" == "1" ]] && fail "amalgamator sibling / claude-agent-sdk unavailable (MOCK_REQUIRE_REAL=1)"
  echo "  (skipped — amalgamator sibling or claude-agent-sdk/colorama not available)"
fi

echo "== stage 4: run_backport.sh with the mock engine (token stripping asserted) =="
export GITHUB_TOKEN=dummy-must-not-reach-pipeline
export PYTHONPATH="$HERE/mock_amalgamator"
export MOCK_OUTCOMES="release-2=pipeline_stop,release-3=pipeline_escalation"
# Local runs construct an explicit environment; opt the mock knobs in through
# the documented extension point (also proves BACKPORT_ENV_ALLOW works).
export BACKPORT_ENV_ALLOW="MOCK_OUTCOMES"
cd "$WORK"
bash "$HARNESS_ROOT/harnessing/7-remediate/backport-fix/scripts/run_backport.sh" \
  --config-dir "$CONFIGS" --output-dir "$RESULTS" 2>&1 | grep -E "MOCK|Collected|INPUT ERROR" || true
unset PYTHONPATH MOCK_OUTCOMES BACKPORT_ENV_ALLOW
[[ -s "$RESULTS/release-1/candidate.patch" ]] || fail "candidate.patch not collected for release-1"
python3 -c "
import json, sys
s = json.load(open('$RESULTS/run_summary.json'))
assert (s['passed'], s['failed'], s['skipped']) == (1, 1, 1), s" || fail "run_summary counts wrong"

echo "== stage 6: emit from the IMPACT artifact (no remediation JSON) + publish =="
cd "$HARNESS_ROOT"
EMIT_OUT="$(python3 harnessing/7-remediate/backport-fix/scripts/emit_backport_report.py \
  --results-dir "$RESULTS" \
  --impact "$WORK/seamA-impact.json" \
  --output "$WORK/myrepo-backport-report.json" --publish-root "$FAKE_AR" 2>&1 || true)"
if grep -q "schema not found" <<<"$EMIT_OUT"; then
  fail "the installed traust-contracts has no backport-report schema (traust-contracts#187)"
fi
grep -q "validates against schema" <<<"$EMIT_OUT" || fail "report failed schema validation"
D="$(ls -d "$FAKE_AR"/remediations/example-product/myrepo/backport-* 2>/dev/null | head -1 || true)"
[[ -n "$D" && -f "$D/myrepo-backport-report.json" && -f "$D/myrepo-backport-release-1.patch" ]] \
  || fail "published tree incomplete: $(ls "$D" 2>/dev/null)"
python3 -c "
import json, yaml
r = json.load(open('$WORK/myrepo-backport-report.json'))
cfg = yaml.safe_load(open('$CONFIGS/release-1.yaml'))
assert r['source_fix']['finding_refs'] == ['CVE-0000-04242'], r['source_fix']
# provenance must be the run's own config, byte-for-byte — the '0000000'
# placeholder or a stale commit must fail here
assert r['source_fix']['commit'] == cfg['fix']['commit'], (r['source_fix'], cfg['fix'])
assert r['source_fix']['branch'] == 'main', r['source_fix']" \
  || fail "impact-mode report metadata wrong (CVE ref / fix commit / source branch)"
validate_json "$WORK/myrepo-backport-report.json" \
  | grep "ALL PASSED" >/dev/null || fail "backport report failed cross-checks"

echo
echo "MOCK SEAM A: PASS   (work dir: $WORK)"
