#!/usr/bin/env bash
# Legacy batch mode, kept: no traust-core door selects candidates in bulk by product yet; run_one.sh
# now takes work item ids (traust remediation open), so this CSV manifest no longer feeds it.
# Drive one full-portfolio remediation batch (CAMPAIGN-PLAN.md).
#
# Usage:
#   run_batch.sh <batch-number> [--dry-run] [--prune]
#
# Reads:
#   analysis-results/remediations/_manifest/campaign-plan.json   (batch → products)
#   analysis-results/remediations/_manifest/campaign-repos.json  (repo → {product, upstream, sha, rem_ids})
#
# Does (idempotent — safe to re-run):
#   1. Append new fork-map.csv rows for the batch's repos
#      (collision-suffix <repo>-<org> if the name is already mapped to a
#       different upstream).
#   2. Append candidate rows to remediation-manifest.csv.
#   3. Emit a workflow script with embedded REPO_ORDER / ASSIGNMENTS
#      (template: mce-remediation-campaign-*.js).
#   4. Print the Workflow({scriptPath}) invocation for the supervising
#      Claude session to launch (this script does NOT launch the workflow
#      itself — that step is interactive so the session can supervise).
#
# Post-completion (run by the supervising session on workflow notify):
#   - emit_product_index.py <p> for each product in the batch
#   - create+push <fork_org>/<prefix>-<p>-index (remediation.yaml)
#   - refresh <prefix>-control
#   - optionally: run_batch.sh <N> --prune  (remove .fork-staging/work/* +
#     bare clones for this batch's repos)

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Harness root: the directory holding VERSION, walked rather than counted,
# so nesting this skill under a stage directory (skill-usability plan 1.2)
# cannot silently repoint it.
HARNESS="${HERE}"
while [ ! -f "${HARNESS}/VERSION" ] && [ "${HARNESS}" != / ]; do
  HARNESS="$(dirname "${HARNESS}")"
done
[ -f "${HARNESS}/VERSION" ] || { echo "harness root not found above ${HERE}" >&2; exit 1; }
# shellcheck source=../../_lib/traust_paths.sh
source "${HARNESS}/harnessing/_lib/traust_paths.sh"
traust_load_paths
traust_load_remediation   # exports HARNESS_FORK_ORG + REMEDIATION_PREFIX for the heredocs
MANIFEST_DIR="$AR/remediations/_manifest"
SCRIPTS_DIR="$HOME/.claude/projects/$(echo "$WS" | tr / -)"
# best-effort locate the MCE template (the one with embedded constants)
TEMPLATE="$(ls "$SCRIPTS_DIR"/*/workflows/scripts/mce-remediation-campaign-*.js 2>/dev/null | head -1)"

BATCH="${1:?usage: run_batch.sh <batch-number> [--dry-run] [--prune]}"
DRY=false; PRUNE=false
for a in "${@:2}"; do
  case "$a" in
    --dry-run) DRY=true;;
    --prune)   PRUNE=true;;
  esac
done

if $PRUNE; then
  echo "[run_batch] pruning .fork-staging for batch $BATCH repos"
  python3 - "$MANIFEST_DIR" "$BATCH" "$WS" <<'PY'
import json, sys, shutil, pathlib
md, batch, ws = sys.argv[1], int(sys.argv[2]), pathlib.Path(sys.argv[3])
plan = json.load(open(f'{md}/campaign-plan.json'))
repos = json.load(open(f'{md}/campaign-repos.json'))
prods = next(b['products'] for b in plan['batches'] if b['batch']==batch)
freed = 0
for r,d in repos.items():
    if d['product'] not in prods: continue
    for p in (ws/'.fork-staging'/'work'/r, ws/'.fork-staging'/f'{r}.git'):
        if p.exists():
            try:
                for sub in p.rglob('*'):
                    try: sub.chmod(0o755)
                    except: pass
                shutil.rmtree(p); freed += 1
            except Exception as e:
                print(f"  warn: {p}: {e}")
print(f"  removed {freed} staging dirs")
PY
  exit 0
fi

echo "[run_batch] batch=$BATCH dry_run=$DRY"
[[ -f "$MANIFEST_DIR/campaign-plan.json" ]] || { echo "ERROR: campaign-plan.json missing — run the planning step first" >&2; exit 1; }
[[ -n "$TEMPLATE" ]] || { echo "ERROR: cannot locate workflow template (mce-remediation-campaign-*.js)" >&2; exit 1; }

python3 - "$MANIFEST_DIR" "$BATCH" "$TEMPLATE" "$DRY" "$WS" "$AR" <<'PY'
import json, csv, os, re, sys, glob, pathlib
from collections import defaultdict, Counter

md, batch, template, dry, ws, ar = (sys.argv[1], int(sys.argv[2]), sys.argv[3],
                                     sys.argv[4]=='true', sys.argv[5], sys.argv[6])
ws = pathlib.Path(ws); ar = pathlib.Path(ar)

def manifest_rel(p):
    p = pathlib.Path(p)
    try:
        return str(p.relative_to(ws))
    except ValueError:
        try:
            return 'analysis-results/' + str(p.relative_to(ar))
        except ValueError:
            return str(p)
ORG = os.environ["HARNESS_FORK_ORG"]                       # from remediation.yaml via traust_load_remediation
PREFIX = os.environ.get("REMEDIATION_PREFIX", "traust")
sev_rank = {"critical":0,"high":1,"medium":2,"low":3}

plan  = json.load(open(f'{md}/campaign-plan.json'))
repos = json.load(open(f'{md}/campaign-repos.json'))
try:
    prods = next(b['products'] for b in plan['batches'] if b['batch']==batch)
except StopIteration:
    print(f"ERROR: no batch {batch} in campaign-plan.json", file=sys.stderr); sys.exit(1)

# current state
mrows = list(csv.DictReader(open(f'{md}/remediation-manifest.csv')))
COLS = list(mrows[0].keys())
done_ids = {r['rem_id'] for r in mrows}
fm = list(csv.DictReader(open(f'{md}/fork-map.csv')))
fm_by_name = {}
for r in fm:
    fm_by_name.setdefault(r['fork_url'].rstrip('/').split('/')[-1], r['upstream_url'])

def slug(s): return re.sub(r'[^a-z0-9]+','-',(s or '').lower()).strip('-')[:40]

def fork_name(repo, upstream):
    """Resolve a fork repo-name, suffixing -<org> on collision with a
    different upstream already in fork-map."""
    if repo not in fm_by_name or fm_by_name[repo] == upstream:
        return repo
    org = upstream.rstrip('/').split('/')[-2].lower()
    return f"{repo}-{re.sub(r'[^a-z0-9-]','',org)}"

# --- triage lookup so we can populate title/sev/cwe/file/line per rem_id ---
triage = {}
for tp in glob.glob(f'{ar}/findings/*/*/[!.]*-triage.json'):
    try: d = json.load(open(tp))
    except: continue
    ctx = d.get('triage_context',{}).get('repo','')
    if '@' not in ctx: continue
    repo = ctx.split('@')[0].split('/')[-1]
    for f in d.get('findings',[]):
        if f.get('verdict')!='true_positive': continue
        rid = f"{repo}.{f['id']}"
        if rid not in triage:
            triage[rid] = {
                'title': re.sub(r'\s+',' ',f.get('title',''))[:300],
                'severity': str(f.get('severity','')).lower(),
                'confidence': str(f.get('confidence','')),
                'cwes': ';'.join(f.get('cwes',[])) if isinstance(f.get('cwes'),list) else str(f.get('cwes','')),
                'file': f.get('file',''), 'line': str(f.get('line','')),
                'audit_finding_id': (f.get('source','').split('#')[-1] or ''),
                'remediation_hint': re.sub(r'\s+',' ',str(f.get('remediation','')))[:300],
                'triage_path': manifest_rel(tp),
                'audit_path': manifest_rel(pathlib.Path(tp).with_name(
                    pathlib.Path(tp).name.replace('-triage.json', '-security-audit.json'))),
            }

# --- build new rows ---
new_fm = []; new_mrows = []; assignments = defaultdict(list); repo_order_keys = []
for repo, d in repos.items():
    if d['product'] not in prods: continue
    upstream = d['upstream_url']; sha = d['audited_commit']; product = d['product']
    fname = fork_name(repo, upstream)
    fork_url = f"https://github.com/{ORG}/{fname}"
    if fname not in fm_by_name:
        new_fm.append({'upstream_url':upstream,'fork_url':fork_url,'host':'github',
                       'visibility':'private','base_ref':'__audited__',
                       'fix_branch_prefix':os.environ.get('FIX_BRANCH_PREFIX','fix'),'notes':f'batch {batch} — {product}'})
        fm_by_name[fname] = upstream
    sev_min = 9
    for rid in d['rem_ids']:
        if rid in done_ids: continue
        t = triage.get(rid, {})
        sev = t.get('severity','medium')
        sev_min = min(sev_min, sev_rank.get(sev,9))
        row = {c:'' for c in COLS}
        row.update({'rem_id':rid,'logical_product':product,'repo_name':repo,
            'upstream_url':upstream,'audited_commit':sha,'fork_url':fork_url,
            'fix_branch':f"{PREFIX}/{rid.split('.')[-1]}/{slug(t.get('title',''))}",
            'finding_id':rid.split('.')[-1],'audit_finding_id':t.get('audit_finding_id',''),
            'title':t.get('title',''),'severity':sev,'confidence':t.get('confidence',''),
            'cwes':t.get('cwes',''),'file':t.get('file',''),'line':t.get('line',''),
            'remediation_hint':t.get('remediation_hint',''),
            'validation_verdict':'not_validated','status':'candidate',
            'triage_path':t.get('triage_path',''),'audit_path':t.get('audit_path',''),
            'report_path':f'analysis-results/remediations/{product}/{repo}/{rid}-remediation.json'})
        new_mrows.append(row)
        assignments[repo].append(rid)
    if assignments[repo]:
        repo_order_keys.append((sev_min, -len(assignments[repo]), repo))

repo_order = [r for _,_,r in sorted(repo_order_keys)]
assignments = {r: assignments[r] for r in repo_order}

by_sev = Counter(r['severity'] for r in new_mrows)
print(f"[run_batch] batch {batch}: {len(new_mrows)} findings · {len(repo_order)} repos · {len(new_fm)} new fork-map rows · products={len(prods)}")
print(f"            severity: {dict(by_sev)}")

if dry:
    print("[run_batch] --dry-run: not writing fork-map/manifest/workflow")
    sys.exit(0)

# --- pre-create private mirrors (serial, ~50/min) so the parallel workers
#     never burst-POST and trip GitHub's secondary content-creation limit ---
import urllib.request, urllib.error, time, os, sys as _sys
_sys.stdout.reconfigure(line_buffering=True)  # flush prints when piped
TOKEN = os.environ.get('GITHUB_TOKEN','')
def gh(method, path, body=None):
    req = urllib.request.Request(f'https://api.github.com{path}', method=method,
        headers={'Authorization': f'Bearer {TOKEN}', 'Accept': 'application/vnd.github+json'})
    if body: req.data = json.dumps(body).encode()
    try:
        with urllib.request.urlopen(req, timeout=15) as r: return r.status
    except urllib.error.HTTPError as e: return e.code
    except Exception: return 0  # network/timeout — caller skips
created = 0
for r in new_fm:
    name = r['fork_url'].rstrip('/').split('/')[-1]
    if gh('GET', f'/repos/{ORG}/{name}') == 200: continue
    code = gh('POST', f'/orgs/{ORG}/repos',
        {'name': name, 'private': True, 'visibility': 'private', 'has_issues': False, 'has_wiki': False,
         'description': f'Private mirror of {r["upstream_url"]} for automated security remediation (traust).'})
    if code == 201: created += 1
    elif code == 403:
        print(f"  ⚠ secondary rate limit on {name}; backing off 90s"); time.sleep(90)
        if gh('POST', f'/orgs/{ORG}/repos', {'name': name, 'private': True, 'visibility': 'private'}) == 201: created += 1
    time.sleep(1.2)
if created: print(f"[run_batch] pre-created {created} private mirrors in {ORG}")

# --- append fork-map + manifest ---
with open(f'{md}/fork-map.csv','a',newline='') as f:
    csv.DictWriter(f, fieldnames=fm[0].keys()).writerows(new_fm)
new_mrows.sort(key=lambda r:(sev_rank.get(r['severity'],9), -float(r['confidence'] or 0), r['rem_id']))
with open(f'{md}/remediation-manifest.csv','a',newline='') as f:
    csv.DictWriter(f, fieldnames=COLS).writerows(new_mrows)

# --- generate workflow script from template ---
tpl = open(template).read()
out = re.sub(r"name: '[^']*-remediation-campaign'", f"name: 'batch-{batch:02d}-remediation-campaign'", tpl)
out = re.sub(r"description: 'Patch all [^']*'",
             f"description: 'Remediation batch {batch:02d} — patch {len(new_mrows)} findings across {len(repo_order)} repos ({', '.join(prods[:3])}{'…' if len(prods)>3 else ''}) on private mirrors'", out)
out = re.sub(r"const REPO_ORDER = \[.*?\];", "const REPO_ORDER = "+json.dumps(repo_order)+";", out, flags=re.S)
out = re.sub(r"const ASSIGNMENTS = \{.*?\};", "const ASSIGNMENTS = "+json.dumps(assignments)+";", out, flags=re.S)
out = re.sub(r"in the \w+ campaign", f"in remediation batch {batch:02d}", out)

import pathlib
sdir = pathlib.Path(template).parent
dst = sdir / f"batch-{batch:02d}-remediation-campaign.js"
dst.write_text(out)
print(f"[run_batch] workflow script: {dst}")
print(f"\nTo launch (in the supervising Claude session):")
print(f"  Workflow({{scriptPath: \"{dst}\"}})")
print(f"\nProducts in this batch (for post-completion emit_product_index.py):")
for p in prods: print(f"  {p}")
PY
