#!/usr/bin/env bash
# Legacy batch mode, kept: no traust-core door selects candidates in bulk by product yet; run_one.sh
# now takes work item ids (traust remediation open), so this CSV manifest no longer feeds it.
# Post-process a completed remediation batch:
#   - emit_product_index.py for each product in the batch
#   - create + push <fork_org>/<prefix>-<product>-index (remediation.yaml)
#     (idempotent — updates if the repo already exists)
#   - refresh <prefix>-control
#   - optionally prune .fork-staging for the batch
#
# Usage:
#   finish_batch.sh <batch-number> [--prune]
#
# Env: GITHUB_TOKEN required.

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
MD="$AR/remediations/_manifest"
traust_load_remediation            # FORK_ORG + REMEDIATION_PREFIX from remediation.yaml / env
ORG="$FORK_ORG"
PREFIX="$REMEDIATION_PREFIX"
: "${GITHUB_TOKEN:?GITHUB_TOKEN must be set}"

BATCH="${1:?usage: finish_batch.sh <batch-number> [--prune]}"
# $BATCH is interpolated nowhere: numeric-guarded and passed via argv
# (assessment 2026-07-31 H2 — `python3 -c "…==$1"` converted the scoped
# grant into arbitrary execution; run_batch.sh:78 was already correct).
[[ "$BATCH" =~ ^[0-9]{1,3}$ ]] || { echo "ERROR: batch must be numeric, got '$BATCH'" >&2; exit 1; }
PRUNE=false; [[ "${2:-}" == "--prune" ]] && PRUNE=true

PRODS=$(python3 -c "
import json, sys
p = json.load(open(sys.argv[1]))
print('\n'.join(next(b['products'] for b in p['batches']
                     if b['batch'] == int(sys.argv[2]))))
" "$MD/campaign-plan.json" "$BATCH")
[[ -z "$PRODS" ]] && { echo "ERROR: batch $BATCH not in campaign-plan.json" >&2; exit 1; }

GH_CRED='!f() { test "$1" = get && printf "username=x-access-token\npassword=%s\n" "${GITHUB_TOKEN:?}"; }; f'

echo "[finish_batch] batch=$BATCH products: $(echo "$PRODS" | tr '\n' ' ')"

# --- per-product index repos -----------------------------------------------
for p in $PRODS; do
  slug="$(echo "$p" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9-]/-/g')"
  IDX="$WS/.fork-staging/${PREFIX}-${slug}-index"
  rm -rf "$IDX"
  if ! python3 "$HERE/emit_product_index.py" "$p" --out "$IDX" 2>/dev/null; then
    echo "  [skip] $p — no manifest rows (0 patched)"
    continue
  fi
  REPO="${PREFIX}-${slug}-index"
  # token via --config on stdin, never argv (ps-visible; audit E2,
  # plan P2.15); JSON via json.dumps (audit F8)
  gh_auth() { printf 'header = "Authorization: Bearer %s"\n' "$GITHUB_TOKEN"; }
  # create if missing — tolerate secondary rate-limit (retry once after backoff, then skip)
  if ! gh_auth | curl -fsS --config - "https://api.github.com/repos/$ORG/$REPO" >/dev/null 2>&1; then
    BODY="$(python3 -c 'import json,sys; print(json.dumps({
        "name": sys.argv[1], "private": True, "visibility": "private",
        "has_issues": True, "has_wiki": False,
        "description": "Automated remediation index for %s (traust Stage-9). Embargoed." % sys.argv[2]}))' "$REPO" "$p")"
    code=$(gh_auth | curl -s -o /dev/null -w '%{http_code}' -X POST --config - -H "Accept: application/vnd.github+json" -d "$BODY" "https://api.github.com/orgs/$ORG/repos")
    if [[ "$code" == "403" ]]; then
      echo "  [rate-limit] $REPO — backing off 90s"; sleep 90
      code=$(gh_auth | curl -s -o /dev/null -w '%{http_code}' -X POST --config - -H "Accept: application/vnd.github+json" -d "$BODY" "https://api.github.com/orgs/$ORG/repos")
    fi
    if [[ "$code" == "201" ]]; then echo "  [create] $ORG/$REPO"
    else echo "  [skip-create] $ORG/$REPO (HTTP $code) — will retry on next finish_batch run"; rm -rf "$IDX"; continue; fi
  fi
  sleep 1.5
  ( cd "$IDX"
    git init -q -b main
    git config --local 'credential.https://github.com.helper' ''
    git config --local --add 'credential.https://github.com.helper' "$GH_CRED"
    git add -A
    git commit -q -m "${PREFIX}: $p remediation index (batch $BATCH)"
    git remote add origin "https://github.com/$ORG/$REPO.git" 2>/dev/null || true
    git push -f origin main 2>&1 | sed -E 's/(ghp_|gho_|ghu_|ghs_|ghr_)[A-Za-z0-9]*|github_pat_[A-Za-z0-9_]*/<REDACTED>/g' | tail -1
  )
  echo "  [push]   https://github.com/$ORG/$REPO"
done

# --- refresh the control repo ----------------------------------------------
echo "[finish_batch] refreshing ${PREFIX}-control"
python3 - "$WS" "$AR" "$ORG" "$PREFIX" <<'PY'
import csv, json, sys, glob
from collections import defaultdict, Counter
ws, ar, org, prefix = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
CTRL = f'{ws}/.fork-staging/{prefix}-control'
rows = list(csv.DictReader(open(f'{ar}/remediations/_manifest/remediation-manifest.csv')))
done = [r for r in rows if r['status'] in ('checks_passed','revalidated_fixed')]
abandoned = [r for r in rows if r['status']=='abandoned']
pending = [r for r in rows if r['status'] not in ('checks_passed','revalidated_fixed','abandoned')]
by_repo = defaultdict(list)
for r in done: by_repo[(r['logical_product'],r['repo_name'],r['upstream_url'],r['fork_url'],r['audited_commit'])].append(r)
sev_rank = {"critical":0,"high":1,"medium":2,"low":3}
sorted_repos = sorted(by_repo.items(), key=lambda kv:(kv[0][0],-len(kv[1])))
by_prod = Counter(r['logical_product'] for r in done); by_sev = Counter(r['severity'] for r in done)

# discover all <prefix>-*-index repos already pushed (best-effort: from .fork-staging)
idx_repos = sorted({d.split('/')[-1] for d in glob.glob(f'{ws}/.fork-staging/{prefix}-*-index')})
idx_table = "\n".join(f"| {r.replace(f'{prefix}-','').replace('-index','')} | [`{r}`](https://github.com/{org}/{r}) |" for r in idx_repos)

open(f'{CTRL}/README.md','w').write(f"""# Stage-9 — Remediation Control Repository

**Embargoed.** This repository indexes every automated security-finding patch produced by the traust Stage-9 remediation harness.

All patches live on `{prefix}/<finding-id>/<slug>` branches in **private mirrors** under `github.com/{org}/*`. Each branch is cut from the audited upstream commit and carries exactly one finding's fix.

## Snapshot

| | |
|---|---|
| Patched findings | **{len(done)}** |
| Repositories | **{len(by_repo)}** |
| Abandoned (FP / already-fixed / architectural) | {len(abandoned)} |
| In flight | {len(pending)} |
| `checks_failed` | {sum(1 for r in rows if r['status']=='checks_failed')} |
| By product | {' · '.join(f'{k}: {v}' for k,v in sorted(by_prod.items()))} |
| By severity | {' · '.join(f'{k}: {v}' for k,v in sorted(by_sev.items(), key=lambda x: sev_rank.get(x[0],9)))} |

## Per-product index repos

| Product | Index repo |
|---|---|
{idx_table}

## Files

| File | Purpose |
|---|---|
| [`INDEX.md`](INDEX.md) | Full per-repository index: upstream, mirror, every fix branch with title/severity/CWE/compare-link |
| [`findings.csv`](findings.csv) | Flat one-row-per-finding CSV |
| [`repositories.csv`](repositories.csv) | One row per repo: mirror URL, finding counts by severity |
| [`abandoned.csv`](abandoned.csv) | Findings ruled FP / already-fixed / architectural on Phase-2 inspection |

## Embargo

Do not open PRs against, comment on, or otherwise reference these findings on the **public upstream** repositories until a disclosure decision is made. Branch and commit names use only the internal `rem_id`.
""")

out=[f"# Per-Repository Remediation Index\n\n**{len(done)} patched findings across {len(by_repo)} repositories.**\n\n## Repository summary\n\n| # | Product | Repo | Mirror | Patched | H/M/L |\n|---|---|---|---|---|---|\n"]
for i,(key,findings) in enumerate(sorted_repos,1):
    logical,repo,upstream,fork,sha=key; sevs=Counter(r['severity'] for r in findings)
    out.append(f"| {i} | {logical} | [{repo}]({upstream}) | [mirror]({fork}) | {len(findings)} | {sevs.get('high',0)}/{sevs.get('medium',0)}/{sevs.get('low',0)} |\n")
out.append("\n---\n\n## Detail\n")
for key,findings in sorted_repos:
    logical,repo,upstream,fork,sha=key
    out.append(f"\n### `{repo}` · {logical}\n\n- **Upstream**: <{upstream}> @ `{sha[:12]}`\n- **Private mirror**: <{fork}>\n")
    out.append("\n| rem_id | sev | CWE | title | branch | compare |\n|---|---|---|---|---|---|\n")
    for r in sorted(findings,key=lambda f:(sev_rank.get(f['severity'],9),f['rem_id'])):
        title=(r['title'] or '').replace('|','\\|')[:90]; compare=f"{fork}/compare/{sha[:12]}...{r['fix_branch']}"
        out.append(f"| `{r['rem_id']}` | {r['severity']} | {r['cwes']} | {title} | [`{r['fix_branch'].split('/',2)[-1][:40]}`]({fork}/tree/{r['fix_branch']}) | [diff]({compare}) |\n")
open(f'{CTRL}/INDEX.md','w').write(''.join(out))
with open(f'{CTRL}/findings.csv','w',newline='') as f:
    w=csv.writer(f); w.writerow(['product','repo','rem_id','severity','cwes','title','upstream_url','audited_commit','mirror_url','fix_branch','fix_commit','compare_url','status'])
    for key,findings in sorted_repos:
        logical,repo,upstream,fork,sha=key
        for r in sorted(findings,key=lambda f:(sev_rank.get(f['severity'],9),f['rem_id'])):
            w.writerow([logical,repo,r['rem_id'],r['severity'],r['cwes'],r['title'],upstream,sha,fork,r['fix_branch'],r['fix_commit'],f"{fork}/compare/{sha[:12]}...{r['fix_branch']}",r['status']])
with open(f'{CTRL}/repositories.csv','w',newline='') as f:
    w=csv.writer(f); w.writerow(['product','repo','upstream_url','mirror_url','audited_commit','patched_findings','high','medium','low'])
    for key,findings in sorted_repos:
        logical,repo,upstream,fork,sha=key; sevs=Counter(r['severity'] for r in findings)
        w.writerow([logical,repo,upstream,fork,sha,len(findings),sevs.get('high',0),sevs.get('medium',0),sevs.get('low',0)])
with open(f'{CTRL}/abandoned.csv','w',newline='') as f:
    w=csv.writer(f); w.writerow(['product','repo','rem_id','severity','title','triage_path'])
    for r in sorted(abandoned,key=lambda x:x['rem_id']): w.writerow([r['logical_product'],r['repo_name'],r['rem_id'],r['severity'],r['title'],r['triage_path']])
print(f"  control: {len(done)} patched · {len(by_repo)} repos · {len(abandoned)} abandoned · {len(pending)} in-flight · {len(idx_repos)} index repos")
PY
( cd "$WS/.fork-staging/${PREFIX}-control"
  git add -A
  if ! git diff --cached --quiet; then
    git commit -q -m "${PREFIX}: batch $BATCH post-process"
    git push origin main 2>&1 | sed -E 's/(ghp_|gho_|ghu_|ghs_|ghr_)[A-Za-z0-9]*|github_pat_[A-Za-z0-9_]*/<REDACTED>/g' | tail -1
  else
    echo "  (no changes)"
  fi
)

# --- prune -----------------------------------------------------------------
if $PRUNE; then
  bash "$HERE/run_batch.sh" "$BATCH" --prune
  # Bound go-build cache growth across the campaign — at 3-wide it accretes
  # ~3 GB/min and reached 840 GB before the B11 OOM. Clearing per-batch is
  # cheap (next batch's repos are disjoint anyway) and keeps disk bounded.
  CACHE_SZ=$(du -sm "${GOCACHE:-$HOME/.cache/go-build}" 2>/dev/null | cut -f1 || echo 0)
  if [[ "$CACHE_SZ" -gt 51200 ]]; then
    echo "[finish_batch] go-build cache at ${CACHE_SZ} MiB — clearing"
    go clean -cache 2>/dev/null || rm -rf "${GOCACHE:-$HOME/.cache/go-build}"/*
  fi
fi

echo "[finish_batch] done"
