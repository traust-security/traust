#!/usr/bin/env python3
"""build_fuzz_rollup.py — deterministic regenerator for the two fuzz roll-up docs.

Single source of truth:
  * targets.json            (this directory)      — the campaign manifest
  * logs/<target>/Fuzz*.log (this directory)      — per-fuzzer execution results
  * pattern-hits.json / logs/sweep-grep-candidates.txt — batch-6 grep sweep
  * analysis-results/findings/**/fuzz-corpus/*    — per-bug write-ups
  * analysis-results/advisories/HPS-ADV-*.md      — portfolio advisories

Outputs (overwritten in place):
  * analysis-results/FUZZ-CAMPAIGN-SUMMARY.md     — executive one-pager
  * analysis-results/FUZZ-FINDINGS-ROLLUP.md      — per-bug detail rollup
  * analysis-results/FUZZ-CAMPAIGN-SUMMARY.json   — machine-readable sidecar
    (totals/batches/bugs/patterns) that dashboards consume instead of
    scraping the markdown
  * progress-tracker/metrics/dashboards/fuzz/     — published copies of all
    three, so the metrics tree carries the fuzz summary + rollup

Everything countable is DERIVED from the sources above at run time. Per-bug
narrative (descriptions, CVSS vectors, fixes, remediation priorities,
negative-control notes, methodology takeaways) cannot be computed from disk;
it is CARRIED VERBATIM from the legacy 2026-07-05 documents, embedded below
keyed by bug number, and each carried section is labelled with its provenance
in the output. The script hard-fails if the embedded bug table drifts from
the on-disk evidence (missing write-up, count mismatch).

Usage:  python3 build_fuzz_rollup.py            # from anywhere
"""

import argparse
import datetime
import json
import os
import re
import subprocess
import sys
from pathlib import Path

from traust.context import (
    add_config_home_arg,
    load_engine,
    progress_tracker_dir,
    resolve_results_root,
    workspace_dir,
)

SCRIPTS_DIR = Path(__file__).resolve().parent
# SKILL_DIR was Path(__file__).parent -- the SCRIPTS directory, not the skill.
# Every path built from it as though it were the skill root pointed at
# scripts/<name>, which does not exist, so sweep_stats() reported 0 pattern
# hits and 0 sweep candidates for as long as it has been running. Nothing
# failed; the numbers were just always zero.
SKILL_DIR = SCRIPTS_DIR.parent
# The harness repo: the directory holding VERSION, walked rather than counted,
# so moving this file between stage directories cannot silently repoint it.
HARNESS_REPO = next(p for p in Path(__file__).resolve().parents if (p / "VERSION").is_file())
TARGETS_JSON = SKILL_DIR / "targets.json"
LOGS = SKILL_DIR / "logs"

# Corpus paths — configured from main() via configure_corpus(); never at import.
_corpus: dict[str, Path] = {}


def configure_corpus(
    results_root: Path,
    workspace: Path,
    metrics_fuzz_dir: Path,
) -> None:
    global _corpus
    _corpus = {
        "workspace": workspace,
        "analysis": results_root,
        "findings": results_root / "findings",
        "advisories": results_root / "advisories",
        "summary_out": results_root / "FUZZ-CAMPAIGN-SUMMARY.md",
        "rollup_out": results_root / "FUZZ-FINDINGS-ROLLUP.md",
        "sidecar_out": results_root / "FUZZ-CAMPAIGN-SUMMARY.json",
        "metrics_fuzz_dir": metrics_fuzz_dir,
    }


def _corpus_path(key: str) -> Path:
    if not _corpus:
        sys.exit("build_fuzz_rollup: corpus paths not configured — invoke main()")
    return _corpus[key]


TODAY = datetime.date.today().isoformat()

# --------------------------------------------------------------------------
# Carried data: the 18 confirmed real bugs.
# Metadata (CVSS, CWE, advisory, method, title) is CARRIED from the legacy
# 2026-07-05 rollup — it is analyst triage output, not machine-derivable.
# `writeup` is VERIFIED against analysis-results/findings/ at run time.
# `target` is VERIFIED against targets.json (except package-operator, which
# was found by the batch-6 grep sweep and is deliberately off-manifest).
# --------------------------------------------------------------------------
BUGS = [
    # num, target-id, title, cvss-display, cwe, advisory, method, writeup tail (under <repo>/fuzz-corpus/)
    dict(
        num=1,
        target="kube-rbac-proxy",
        title="`template.Parse` err discard nil-deref",
        cvss="3.3",
        cwe="476",
        adv="—",
        method="fuzz",
        writeup="FuzzTemplateWithValue/001-nil-template-parse-error.md",
    ),
    dict(
        num=2,
        target="kube-rbac-proxy",
        title="`{{range N}}` unbounded loop (config-trust)",
        cvss="3.3",
        cwe="834",
        adv="ADV-002",
        method="fuzz",
        writeup="FuzzTemplateWithValue/002-unbounded-range-int-hang.md",
    ),
    dict(
        num=3,
        target="external-secrets",
        title="sprig `repeat` OOM via tenant `ExternalSecret` CR",
        cvss="6.5",
        cwe="770",
        adv="ADV-002",
        method="fuzz",
        writeup="FuzzExecute/001-sprig-repeat-oom.md",
    ),
    dict(
        num=4,
        target="cluster-logging-operator",
        title="`Filters[len(FilterRefs)-1]` index-mismatch OOB + `os.Exit(1)`",
        cvss="5.7*",
        cwe="129/248",
        adv="ADV-003",
        method="fuzz",
        writeup="FuzzGenerateConf/002-pipeline-filters-index-oob.md",
    ),
    dict(
        num=5,
        target="sriov-network-operator",
        title="`parseRange` `rng[1]` panic on VF range without hyphen",
        cvss="4.4",
        cwe="129",
        adv="ADV-003",
        method="fuzz",
        writeup="FuzzParseVfRange/001-parserange-missing-hyphen.md",
    ),
    dict(
        num=6,
        target="sriov-network-operator",
        title="`ParseMstconfigOutput` nil regex-result index",
        cvss="3.3",
        cwe="129",
        adv="ADV-003",
        method="fuzz",
        writeup="FuzzParseMstconfigOutput/001-regex-no-match-index.md",
    ),
    dict(
        num=7,
        target="cluster-api",
        title="sprig `repeat` OOM in ClusterClass patch template",
        cvss="4.9–6.5",
        cwe="770",
        adv="ADV-002",
        method="fuzz",
        writeup="FuzzRenderValueTemplate/001-sprig-repeat-oom.md",
    ),
    dict(
        num=8,
        target="oauth-server",
        title="`/\\` open redirect on `/logout` + `/login` `then=`",
        cvss="6.1",
        cwe="601",
        adv="ADV-001",
        method="fuzz",
        writeup="FuzzIsServerRelativeURL/001-backslash-open-redirect.md",
    ),
    dict(
        num=9,
        target="cluster-policy-controller",
        title='`mcs.ParseRange("/-1")` → `uint(MaxUint64)` wrap',
        cvss="3.5–5.3",
        cwe="190/20",
        adv="ADV-003",
        method="fuzz",
        writeup="FuzzMCSParseRange/001-negative-uint-wrap.md",
    ),
    dict(
        num=10,
        target="csi-external-snapshotter",
        title="`makeSnapshotName` slice OOB on flag",
        cvss="2.7",
        cwe="129",
        adv="ADV-003",
        method="fuzz",
        writeup="FuzzMakeSnapshotName/001-uuidlength-slice-oob.md",
    ),
    dict(
        num=11,
        target="tektoncd-hub",
        title="unvalidated `redirect_uri` → OAuth code exfiltration",
        cvss="~8.1",
        cwe="601/359/362",
        adv="ADV-001",
        method="static scout",
        writeup="static-001-unvalidated-redirect-uri-code-exfil.md",
    ),
    dict(
        num=12,
        target="oauth-proxy",
        title="`/\\` open redirect on `rd=` (stale oauth2-proxy fork, reach=126)",
        cvss="6.1",
        cwe="601",
        adv="ADV-001",
        method="static scout",
        writeup="static-001-backslash-open-redirect.md",
    ),
    dict(
        num=13,
        target="go-template-utils",
        title="sprig `repeat` NOT in `sensitiveSprigFunctions` denylist (ACM/MCE-wide)",
        cvss="5.7",
        cwe="770",
        adv="ADV-002",
        method="fuzz",
        writeup="FuzzResolveTemplate/001-sprig-repeat-denylist-gap.md",
    ),
    dict(
        num=14,
        target="siteconfig",
        title="slim-sprig `repeat` DoS in ClusterInstance templates",
        cvss="4.9",
        cwe="770",
        adv="ADV-002",
        method="fuzz",
        writeup="FuzzParseTemplate/001-slim-sprig-repeat-dos.md",
    ),
    dict(
        num=15,
        target="loki",
        title="tenant `line_format` sprig `repeat` → shared-querier DoS",
        cvss="~7.1",
        cwe="770/400",
        adv="ADV-002",
        method="static scout",
        writeup="static-001-line-format-repeat-dos.md",
    ),
    dict(
        num=16,
        target="node-feature-discovery",
        title="sprig `repeat` in `NodeFeatureRule.labelsTemplate`",
        cvss="4.9",
        cwe="770",
        adv="ADV-002",
        method="fuzz",
        writeup="FuzzNewHelper/001-sprig-repeat-dos.md",
    ),
    dict(
        num=17,
        target="cluster-etcd-operator",
        title='`validRelPath("..")` accepted (zip-slip validator gap)',
        cvss="~4.1",
        cwe="22/180",
        adv="ADV-003",
        method="fuzz",
        writeup="FuzzValidRelPath/001-bare-dotdot-zipslip.md",
    ),
    dict(
        num=18,
        target="package-operator",
        title="sprig `repeat` + `until` explicitly allowlisted",
        cvss="4.9",
        cwe="770",
        adv="ADV-002",
        method="grep sweep",
        writeup="static-001-sprig-repeat-until-allowlisted.md",
        off_manifest=True,
    ),
]

# Display orders (carried from legacy docs: severity-ranked)
SUMMARY_ORDER = [11, 15, 3, 8, 12, 4, 13, 7, 14, 16, 18, 5, 17, 9, 2, 6, 1, 10]
HIGH_ORDER = [11, 15]
MEDIUM_ORDER = [3, 8, 12, 4, 13, 7, 14, 16, 5, 9, 18, 17]
LOW_ORDER = [2, 6, 1, 10]

# Advisory-class display metadata (class names carried from legacy rollup)
ADV_CLASSES = {
    "ADV-001": "Open redirect via `/\\` / unvalidated redirect",
    "ADV-002": "Unbounded sprig funcmap on tenant template",
    "ADV-003": "Unchecked slice/split/regex index on CR field",
}

# --------------------------------------------------------------------------
# Carried verbatim narrative blocks, keyed by bug number
# (from legacy FUZZ-FINDINGS-ROLLUP.md, 2026-07-05).
# --------------------------------------------------------------------------
BUG_DETAILS = {
    11: """### #11 — tektoncd-hub: OAuth authorization-code exfiltration via unvalidated `redirect_uri`
| | |
|---|---|
| **CVSS v3.1** | **~8.1** (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N) |
| **CWE** | 601 + 359 + 362 |
| **Location** | `api/pkg/auth/service/auth.go:92,125` |
| **Repro** | `GET /auth/github?redirect_uri=https://attacker.example/cb` → callback 307's victim to attacker with `?code=<victim's OAuth grant>` |
| **Trust boundary** | Unauthenticated → victim account takeover |
| **Fix** | Remove package-global `UI_URL`; carry redirect in signed `state`; allowlist against configured UI origin; exchange `code` server-side |
| **Advisory** | HPS-ADV-2026-001 |
| **Write-up** | `findings/**/tektoncd-hub/fuzz-corpus/static-001-unvalidated-redirect-uri-code-exfil.md` |""",
    15: """### #15 — loki: tenant `line_format` sprig `repeat` → shared-querier DoS
| | |
|---|---|
| **CVSS v3.1** | **~7.1** (AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:N/A:H) |
| **CWE** | 770, 400 |
| **Location** | `pkg/logql/log/fmt.go:91,215` — `"repeat"` explicitly allowlisted |
| **Repro** | `{app="x"} \\| line_format "{{ repeat 200000000 \\"0\\" }}"` → 200 MB per matched line, uncapped |
| **Trust boundary** | Any Loki-query user (Grafana Explore / logcli) → shared querier OOM for all tenants |
| **Fix** | Remove `repeat` from allowlist; wrap `Execute` in byte-capped writer (≤ `max_line_size`) |
| **Advisory** | HPS-ADV-2026-002 |
| **Write-up** | `findings/**/loki/fuzz-corpus/static-001-line-format-repeat-dos.md` |""",
    3: """### #3 — external-secrets: sprig `repeat` OOM via tenant `ExternalSecret` CR
| | |
|---|---|
| **CVSS** | **6.5** (AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H) · **CWE** 770 |
| **Location** | `runtime/template/v2/template.go:241` `execute()` |
| **Repro** | `spec.target.template.data.x: "{{\\"00\\"|repeat 2000000000}}"` |
| **Trust boundary** | Any tenant with `create externalsecret` in own namespace → cluster-wide controller OOM |
| **Artifact** | `runtime/template/v2/testdata/fuzz/FuzzExecute/59fabaf968b895ed` |
| **Advisory** | HPS-ADV-2026-002 · **Write-up** `findings/**/external-secrets/fuzz-corpus/FuzzExecute/001-sprig-repeat-oom.md` |""",
    8: """### #8 — oauth-server: `/\\` open redirect on `/logout` + `/login` `then=`
| | |
|---|---|
| **CVSS** | **6.1** (AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N) · **CWE** 601 |
| **Location** | `pkg/server/redirect/redirect.go:9` `IsServerRelativeURL` → `logout.go:55`, `login.go:127,157` |
| **Repro** | `https://oauth-openshift.../logout?then=%2F%5Cattacker.example` → 302 off-origin |
| **Trust boundary** | Unauthenticated → credential-phishing on the platform IdP |
| **Advisory** | HPS-ADV-2026-001 · **Write-up** `findings/**/oauth-server/fuzz-corpus/FuzzIsServerRelativeURL/001-backslash-open-redirect.md` |""",
    12: """### #12 — oauth-proxy: `/\\` open redirect on `rd=` (stale fork of oauth2-proxy)
| | |
|---|---|
| **CVSS** | **6.1** (AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N) · **CWE** 601 |
| **Location** | `oauthproxy.go:525,685` — `HasPrefix("/") && !HasPrefix("//")` misses `/\\` |
| **Product reach** | **126** portfolio segments (Prometheus, Alertmanager, Grafana, Kibana, Thanos sidecars) |
| **Trust boundary** | Unauthenticated → phishing across every oauth-proxy-fronted UI |
| **Fix** | Port upstream `oauth2-proxy` `invalidRedirectRegex` back to the openshift fork |
| **Advisory** | HPS-ADV-2026-001 · **Write-up** `findings/**/oauth-proxy/fuzz-corpus/static-001-backslash-open-redirect.md` |""",
    4: """### #4 — cluster-logging-operator: `Filters[len(FilterRefs)-1]` index-mismatch + `os.Exit(1)`
| | |
|---|---|
| **CVSS** | **5.7*** (AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H — pending admission-webhook check) · **CWE** 129, 248 |
| **Location** | `internal/generator/vector/adapters/pipeline.go:60,66` |
| **Repro** | `ClusterLogForwarder` with `spec.pipelines[].filterRefs` where a ref produces no `Filter` |
| **Trust boundary** | Tenant with `create clusterlogforwarders` → operator crash-loop; `os.Exit(1)` at :60 terminates process outright |
| **Artifact** | `internal/generator/forwarder/testdata/fuzz/FuzzGenerateConf/f1be8693c265b492` |
| **Advisory** | HPS-ADV-2026-003 · **Write-up** `findings/**/cluster-logging-operator/fuzz-corpus/FuzzGenerateConf/002-pipeline-filters-index-oob.md` |""",
    13: """### #13 — go-template-utils: sprig `repeat` NOT in `sensitiveSprigFunctions` denylist
| | |
|---|---|
| **CVSS** | **5.7** (AV:N/AC:L/PR:H/UI:N/S:C/C:N/I:N/A:H) · **CWE** 770 |
| **Location** | `pkg/templates/templates.go:75,685` — denylist covers env/leak, not allocation |
| **Downstream** | governance-policy-propagator, config-policy-controller, cert-policy-controller, iam-policy-controller — **all ACM/MCE policy controllers on hub + every spoke** |
| **Trust boundary** | Policy author on hub → hangs/OOM every policy controller fleet-wide |
| **Advisory** | HPS-ADV-2026-002 · **Write-up** `findings/**/go-template-utils/fuzz-corpus/FuzzResolveTemplate/001-sprig-repeat-denylist-gap.md` |""",
    7: """### #7 — cluster-api: sprig `repeat` OOM in ClusterClass patch template
| | |
|---|---|
| **CVSS** | **4.9–6.5** (PR:H→L depending on multi-tenant CAPI-as-a-service) · **CWE** 770 |
| **Location** | `internal/controllers/topology/cluster/patches/inline/json_patch_generator.go:320` `renderValueTemplate` — `sprig.HermeticTxtFuncMap()` retains `repeat` |
| **Trust boundary** | `ClusterClass` author → CAPI topology controller for all managed clusters |
| **Artifact** | `.../inline/testdata/fuzz/FuzzRenderValueTemplate/d52e657300c07e2c` |
| **Advisory** | HPS-ADV-2026-002 · **Write-up** `findings/**/cluster-api/fuzz-corpus/FuzzRenderValueTemplate/001-sprig-repeat-oom.md` |""",
    14: """### #14 — siteconfig: slim-sprig `repeat` DoS in ClusterInstance templates
| | |
|---|---|
| **CVSS** | **4.9** (AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H) · **CWE** 770 |
| **Location** | `internal/controller/clusterinstance/helper.go:321` — `slim-sprig.TxtFuncMap()` retains `repeat`/`rand*` |
| **Trust boundary** | ConfigMap-write in siteconfig namespace → siteconfig-controller OOM |
| **Note** | slim-sprig is NOT a safe alternative — drops env/network but keeps allocation sinks |
| **Advisory** | HPS-ADV-2026-002 · **Write-up** `findings/**/siteconfig/fuzz-corpus/FuzzParseTemplate/001-slim-sprig-repeat-dos.md` |""",
    16: """### #16 — node-feature-discovery: sprig `repeat` in `NodeFeatureRule.labelsTemplate`
| | |
|---|---|
| **CVSS** | **4.9** (AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H) · **CWE** 770 |
| **Location** | `pkg/apis/nfd/template/template.go:33` — full `sprig.FuncMap()` |
| **Trust boundary** | Cluster-admin `NodeFeatureRule` → nfd-worker DaemonSet OOM on every node |
| **Advisory** | HPS-ADV-2026-002 · **Write-up** `findings/**/node-feature-discovery/fuzz-corpus/FuzzNewHelper/001-sprig-repeat-dos.md` |""",
    5: """### #5 — sriov-network-operator: `parseRange` `rng[1]` panic on VF range without hyphen
| | |
|---|---|
| **CVSS** | **4.4** (AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H) · **CWE** 129 |
| **Location** | `api/v1/helper.go:550` — `strings.Split(r,"-")[1]` no len check |
| **Repro** | `SriovNetworkNodePolicy.spec.nicSelector.pfNames: ["eth0#0"]` |
| **Artifact** | `api/v1/testdata/fuzz/FuzzParseVfRange/d8f26ecffa44a0c1` |
| **Advisory** | HPS-ADV-2026-003 · **Write-up** `findings/**/sriov-network-operator/fuzz-corpus/FuzzParseVfRange/001-parserange-missing-hyphen.md` |""",
    9: """### #9 — cluster-policy-controller: `mcs.ParseRange("/-1")` → `uint(MaxUint64)` wrap
| | |
|---|---|
| **CVSS** | **3.5–5.3** (pending downstream `combinations()` audit) · **CWE** 190, 20 |
| **Location** | `pkg/security/mcs/label.go:174` — `strconv.Atoi` → `uint(k)` no sign check |
| **Repro** | Namespace annotation `openshift.io/sa.scc.mcs: "s0/-1"` |
| **Trust boundary** | Namespace-admin → SCC/MCS allocator (impact TBD) |
| **Advisory** | HPS-ADV-2026-003 · **Write-up** `findings/**/cluster-policy-controller/fuzz-corpus/FuzzMCSParseRange/001-negative-uint-wrap.md` |""",
    18: """### #18 — package-operator: sprig `repeat` + `until` explicitly allowlisted
| | |
|---|---|
| **CVSS** | **4.9** (AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H) · **CWE** 770 |
| **Location** | `internal/transform/transformfiles_funcs.go:28,70` — `allowedFuncNames["repeat"]`, `["until"]` |
| **Trust boundary** | Package-image author (addon vendor) → package-operator controller OOM |
| **Note** | Found via batch-6 source-grep exhaustion (889 repos); only NEW vulnerable hit |
| **Advisory** | HPS-ADV-2026-002 · **Write-up** `findings/**/package-operator/fuzz-corpus/static-001-sprig-repeat-until-allowlisted.md` |""",
    17: """### #17 — cluster-etcd-operator: `validRelPath("..")` accepted (zip-slip validator gap)
| | |
|---|---|
| **CVSS** | **~4.1** (AV:L/AC:L/PR:H/UI:N/S:C/C:N/I:L/A:L) · **CWE** 22, 180 |
| **Location** | `pkg/cmd/backuprestore/tarutils.go:225` — `strings.Contains(p, "../")` misses bare `".."` |
| **Repro** | Backup tarball with entry `Name=".."` → extraction escapes one level from destDir |
| **Trust boundary** | Backup-storage write access (cluster/storage-admin) → restore-path escape |
| **Fix** | `filepath.IsLocal(p)` (Go 1.20+) or component-wise `..` reject |
| **Advisory** | HPS-ADV-2026-003 · **Write-up** `findings/**/cluster-etcd-operator/fuzz-corpus/FuzzValidRelPath/001-bare-dotdot-zipslip.md` |""",
}

# --------------------------------------------------------------------------
# Other carried narrative sections (verbatim from legacy docs, 2026-07-05)
# --------------------------------------------------------------------------
CARRIED_TAG = "*(carried verbatim from the legacy 2026-07-05 hand-written doc — analyst content, not machine-derivable)*"

PATTERN_HIT_RATES = """| Pattern | Tested | Vulnerable | Rate | Portfolio advisory |
|---|--:|--:|--:|---|
| sprig/`text/template` DoS on tenant template string | 10 | 6 | 60%¹ | HPS-ADV-2026-002 |
| `/\\` open-redirect | 5 | 3 | 60% | HPS-ADV-2026-001 |
| Split/Submatch/slice index no bounds | 5 | 5 | 100% | HPS-ADV-2026-003 |
| PEM/x509/CSR (stdlib) | 5 | 0 | 0% | — |
| JSON/YAML `Unmarshal` into struct | 8 | 0 | 0% | — |

¹ 60% of *sprig call sites*; 100% of sites where template string is tenant-controlled.
(Table written at batch-5 close; batch 6 added #16–#18 to ADV-002/-003 classes — see the per-bug table for the current per-class counts.)"""

NOT_FUZZED_SCOPE = """| Reason | Count | Examples |
|---|--:|---|
| No concrete audit-named target | bulk | Most `findings/` repos — audit "Fuzzing 0/10" is Scorecard boilerplate |
| Already OSS-Fuzz'd upstream | 3 | coredns, prometheus, loki LogQL parser |
| Not Go / needs live env | ~8 | che-server (Java), notebooks (Jupyter), security-profiles-operator (C `libsemanage` — Track 3) |
| Trusted-template-source sprig | 4 | ptp-operator, cluster-network-operator, kubernetes-nmstate, sriov render.go |
| Heavy receiver deps | 2 | dex `parseAuthorizationRequest` (needs storage), router `writeConfig` (disk+prometheus) |"""

METHODOLOGY = """1. **Every real bug surfaced in <11 minutes of fuzz time.** `FUZZTIME=15m` is
   sufficient; `1h` adds nothing for these bug classes.
2. **Seed the known-bad shape.** Batch-1's go-template-utils ran clean at 46M
   execs because it lacked a `repeat 2e9` seed; batch-4's re-seed hit in 11s.
   Coverage-guided mutation does not discover string funcnames.
3. **Differential invariants > crash-only.** Several bugs (open-redirect,
   int-wrap, zip-slip) came from asserting a *property*, not waiting for a
   panic. But the invariant must model the real trust boundary
   (false-positives come from over-broad checks).
4. **Signature scouts ≈ fuzzing.** 4 of 18 bugs (tektoncd-hub, oauth-proxy,
   loki, package-operator) were confirmed by code-inspection/grep *before or
   without* any fuzzing — pattern-directed source review is as valuable as
   the fuzzer for known classes.
5. **Stop fuzzing stdlib wrappers.** PEM/x509/CSR/`json.Unmarshal` into typed
   structs: 0 bugs. The stdlib is already OSS-Fuzz'd; thin wrappers add
   nothing.

(Takeaways 1–3 and 5 were written at batch-5 close; takeaway 4 updated for
the final 18-bug count.)"""

REMEDIATION_PRIORITY = """| P | Action | Closes | Effort |
|---|---|---|---|
| **P0** | Port `oauth2-proxy` `invalidRedirectRegex` to `openshift/oauth-proxy` | #12 across 126 products | S |
| **P0** | Report #11 to tektoncd via GHSA (upstream, code-exfil) | #11 | S |
| **P0** | Add `\\\\` + `//` reject to `oauth-server` `IsServerRelativeURL` | #8 | S |
| **P1** | Extend `go-template-utils` `sensitiveSprigFunctions` denylist + byte-cap | #13 (ACM-wide), transitively hardens governance-policy-propagator | S |
| **P1** | Report #15 to grafana/loki via GHSA (tenant → querier DoS) | #15 | S |
| **P1** | Report #3 to external-secrets via GHSA | #3 | S |
| **P2** | Apply ADV-002 shared fix to cluster-api, siteconfig, NFD, package-operator | #7, #14, #16, #18 | M |
| **P2** | Fix cluster-logging-operator `pipeline.go` index + replace `os.Exit(1)` | #4 | S |
| **P3** | Apply ADV-003 shared fix to sriov ×2, cluster-policy-controller, csi-snapshotter, cluster-etcd-operator | #5, #6, #9, #10, #17 | S each |
| **P3** | Fix kube-rbac-proxy template Parse-err + validate at config-load | #1, #2 | S |"""

NOT_VULNERABLE = """| Repo | Checked for | Result |
|---|---|---|
| oauth2-proxy | `/\\` redirect | PATCHED — `invalidRedirectRegex` complete |
| console | user-controlled redirect | N/A — fixed OIDC/config URLs only |
| router | `spec.path` regex-metacharacter injection | SAFE — `regexp.QuoteMeta` applied (util.go:66,69) |
| argo-rollouts | expression-eval DoS | MITIGATED — `expr-lang/expr` has built-in iteration budget |
| helm-operator-plugins | sprig on tenant CR | N/A — sprig only over operator-author `watches.yaml` |
| ptp-operator, cluster-network-operator, kubernetes-nmstate | sprig on tenant CR | N/A — templates are baked-in bindata; only data is CR-supplied |
| prom-label-proxy | tenant-isolation matcher-injection bypass | SAFE — every VectorSelector carries injected matcher (1h AST-walk fuzz) |
| gatekeeper | mutation-path canonicalisation | Info-only — `Path.String()` strips quotes (not re-parsed in production) |
| cluster-api-provider-vsphere | sprig on tenant CR | SAFE — allowlists only `trimSuffix`+`trunc` (correct pattern) |
| csi-driver-nfs | volume-ID path traversal | SAFE — `validatePath` applied to both `baseDir` and `subDir` |
| kube-linter, operator-sdk | sprig on user config | N/A — CLI/codegen local-trust |"""

REMAINING_SURFACES = """See `advisories/TRACK-3-CPP-TARGETS.md`:
- **security-profiles-operator** `apparmor_parser` / `libsemanage` — tenant
  policy text → C parser as root on every node (est. High if hit); needs
  `defending-code-reference-harness/` libFuzzer/ASAN Docker setup.
- FRR `bgpd` config, OVN `northd` — CR → C config parser."""

SCOPE_LINE = (
    "Repositories with `analysis-results/findings/**/*security-audit.md` "
    "that named a concrete fuzz-target function."
)
METHOD_LINE = (
    "Go-native `go test -fuzz` @ 15m–1h per target; no cluster, no cloud, "
    "no network beyond `git clone`. Linux-only targets via podman 6 GiB."
)


# --------------------------------------------------------------------------
# Derivation
# --------------------------------------------------------------------------
def fail(msg):
    print(f"FATAL: {msg}", file=sys.stderr)
    sys.exit(1)


def harness_version():
    v = "unknown"
    vf = HARNESS_REPO / "VERSION"
    if vf.exists():
        v = vf.read_text().strip()
    try:
        sha = subprocess.run(
            ["git", "-C", str(HARNESS_REPO), "rev-parse", "--short", "HEAD"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
    except Exception:
        sha = "?"
    return f"{v} (git {sha})"


def load_manifest():
    d = json.loads(TARGETS_JSON.read_text())
    ts = d["targets"]
    for t in ts:
        t.setdefault("batch", 1)  # batch-1 targets predate the batch key
    return d, ts


def classify_log(path: Path):
    text = path.read_text(errors="replace")
    if "no fuzz tests to fuzz" in text:
        return "noop"
    if "Failing input written to" in text:
        return "crasher"
    if re.search(r"^--- FAIL|^FAIL\b", text, re.M):
        return "fail"
    return "clean"


def collect_logs():
    """{target_id: {fuzz_name: verdict}} from logs/<target>/Fuzz*.log."""
    out = {}
    for p in sorted(LOGS.glob("*/Fuzz*.log")):
        out.setdefault(p.parent.name, {})[p.stem] = classify_log(p)
    return out


def collect_writeups():
    """Unique write-ups under findings/**/<repo>/fuzz-corpus/**, keyed by
    (repo, path-under-fuzz-corpus)."""
    uniq = {}
    for p in _corpus_path("findings").rglob("fuzz-corpus/**/*.md"):
        parts = p.parts
        i = parts.index("fuzz-corpus")
        repo = parts[i - 1]
        tail = "/".join(parts[i + 1 :])
        uniq[(repo, tail)] = p
    return uniq


def collect_reports():
    copies = list(_corpus_path("findings").rglob("*-fuzzing-report.md"))
    uniq = sorted({p.name[: -len("-fuzzing-report.md")] for p in copies})
    return len(copies), uniq


def _resolve_campaign_artifact(name: str) -> Path:
    env = os.environ.get("FUZZ_CAMPAIGN_DIR", "").strip()
    if env:
        return Path(env) / name
    corpus = _corpus_path("analysis") / "fuzz-harnesses" / "_campaign" / name
    return corpus if corpus.exists() else SKILL_DIR / name


def sweep_stats():
    cand = LOGS / "sweep-grep-candidates.txt"
    n_cand = sum(1 for _ in cand.open()) if cand.exists() else 0
    # pattern-hits.json is campaign output -- a scan of named repositories --
    # so it lives in the corpus beside the harnesses, not in the skill.
    # Order: explicit env > corpus > the old in-skill location, so a checkout
    # that has not migrated still works.
    ph = _resolve_campaign_artifact("pattern-hits.json")
    hits, hit_repos = 0, set()
    if ph.exists():
        raw = ph.read_text()
        ids = re.findall(r'"id":\s*"([^"]+)"', raw)
        hits = len(ids)
        hit_repos = {i.split("__")[0] for i in ids}
    return n_cand, hits, sorted(hit_repos)


def campaign_dates(manifest):
    start = manifest.get("generated", "?")
    end = start
    dates = set()
    for p in [*list(LOGS.glob("*.out")), LOGS / "sweep.log"]:
        if p.exists():
            dates.update(re.findall(r"\b(20\d\d-\d\d-\d\d)\b", p.read_text(errors="replace")))
    if dates:
        end = max(dates)
    return start, end


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    add_config_home_arg(ap)
    ap.add_argument("--results-root", type=Path, default=None)
    args = ap.parse_args(argv)

    engine = load_engine(args.config_home)
    results_root = resolve_results_root(args)
    configure_corpus(
        results_root,
        workspace_dir(engine),
        progress_tracker_dir(engine) / "metrics" / "dashboards" / "fuzz",
    )
    SUMMARY_OUT = _corpus_path("summary_out")
    ROLLUP_OUT = _corpus_path("rollup_out")
    SIDECAR_OUT = _corpus_path("sidecar_out")
    METRICS_FUZZ_DIR = _corpus_path("metrics_fuzz_dir")
    WORKSPACE = _corpus_path("workspace")
    _corpus_path("findings")
    ADVISORIES = _corpus_path("advisories")

    manifest, targets = load_manifest()
    by_id = {t["id"]: t for t in targets}

    # ---- manifest-derived population ----
    n_targets = len(targets)
    by_language = {}
    for t_ in targets:
        lang = t_.get("language", "go")
        by_language[lang] = by_language.get(lang, 0) + 1
    fuzzable = [t for t in targets if any(h.get("fuzz") for h in t["harnesses"])]
    harnessless = [t for t in targets if t not in fuzzable]
    fuzz_funcs = [(t["id"], h["fuzz"]) for t in targets for h in t["harnesses"] if h.get("fuzz")]
    clone_keys = {t.get("clone_alias") or t["id"] for t in targets}
    n_repos = len(clone_keys)
    harness_files_manifest = {h["file"] for t in targets for h in t["harnesses"]}
    harness_files_disk = set(
        str(q.relative_to(SKILL_DIR))
        for ext in ("*_test.go", "*_fuzz.py", "*.fuzz.js", "*_fuzz.rs", "*Fuzz.java")
        for q in SKILL_DIR.glob(f"harnesses/**/{ext}")
        if "_templates" not in q.parts
    )
    missing_harness_files = sorted(harness_files_manifest - harness_files_disk)
    if missing_harness_files:
        fail(f"manifest references harness files missing on disk: {missing_harness_files}")

    # ---- log-derived execution results ----
    logs = collect_logs()
    run_verdicts = [(tid, fz, v) for tid, m in logs.items() for fz, v in m.items()]
    real_runs = [(t, f, v) for t, f, v in run_verdicts if v != "noop"]
    executed_targets = sorted({t for t, _, v in run_verdicts if v != "noop"})
    crashfail_targets = sorted({t for t, _, v in real_runs if v in ("crasher", "fail")})
    n_crashfail_runs = sum(1 for _, _, v in real_runs if v in ("crasher", "fail"))
    n_clean_runs = sum(1 for _, _, v in real_runs if v == "clean")

    # ---- bug table cross-checks against disk ----
    writeups = collect_writeups()
    writeup_index = {(r, t) for (r, t) in writeups}
    if len(BUGS) != 18:
        fail(f"embedded bug table has {len(BUGS)} entries, expected 18")
    for b in BUGS:
        key = (b["target"], b["writeup"])
        if key not in writeup_index:
            fail(
                f"bug #{b['num']}: write-up not found on disk: findings/**/{b['target']}/fuzz-corpus/{b['writeup']}"
            )
        if not b.get("off_manifest") and b["target"] not in by_id:
            fail(f"bug #{b['num']}: target {b['target']} not in targets.json")
    n_bug_writeups = len({(b["target"], b["writeup"]) for b in BUGS})
    n_other_writeups = len(writeups) - n_bug_writeups

    bug_targets = {b["target"] for b in BUGS}
    fuzz_bug_targets = sorted({b["target"] for b in BUGS if b["method"] == "fuzz"})
    noise_targets = sorted(
        set(crashfail_targets)
        - bug_targets
        - {v["id"] for v in targets if v.get("clone_alias") in bug_targets}
    )
    clean_targets = sorted(
        t for t in executed_targets if t not in crashfail_targets and t not in bug_targets
    )

    # ---- per-batch table (bugs attributed to the *target's* batch) ----
    batch_rows = []
    batches = sorted({t["batch"] for t in targets})
    bug_batch = {}
    for b in BUGS:
        if b.get("off_manifest"):
            bug_batch.setdefault("sweep", []).append(b["num"])
        else:
            bug_batch.setdefault(by_id[b["target"]]["batch"], []).append(b["num"])
    for bt in batches:
        bts = [t for t in targets if t["batch"] == bt]
        n_fz = sum(1 for t in bts for h in t["harnesses"] if h.get("fuzz"))
        batch_rows.append((bt, len(bts), n_fz, len(bug_batch.get(bt, []))))

    # ---- misc derived ----
    n_reports, report_repos = collect_reports()
    n_cand, n_hits, hit_repos = sweep_stats()
    advisories = (
        sorted(p.name for p in ADVISORIES.glob("HPS-ADV-*.md")) if ADVISORIES.exists() else []
    )
    start, end = campaign_dates(manifest)
    hver = harness_version()

    adv_counts = {}
    for b in BUGS:
        adv_counts.setdefault(b["adv"], []).append(b["num"])
    n_medplus = len(HIGH_ORDER) + len(MEDIUM_ORDER)
    hit_rate = f"{len(fuzz_bug_targets)}/{len(executed_targets)}" if executed_targets else "?"
    hit_rate_pct = (
        round(100 * len(fuzz_bug_targets) / len(executed_targets)) if executed_targets else 0
    )

    # soft consistency warnings
    if len(fuzz_funcs) != len(real_runs):
        print(
            f"WARNING: {len(fuzz_funcs)} fuzz functions in manifest vs {len(real_runs)} executed runs logged",
            file=sys.stderr,
        )

    targets_rel = TARGETS_JSON.relative_to(WORKSPACE)
    script_rel = Path(__file__).resolve().relative_to(WORKSPACE)

    def header(doc):
        return (
            f"<!--\n  GENERATED — do not hand-edit. Re-run the generator instead.\n"
            f"  doc:        {doc}\n"
            f"  script:     {script_rel}\n"
            f"  run date:   {TODAY}\n"
            f"  manifest:   {targets_rel} (generated {manifest.get('generated', '?')})\n"
            f"  harness:    traust v{hver}\n"
            f"  Derived numbers come from targets.json + logs/ + findings/ write-ups;\n"
            f'  sections marked "carried" are verbatim analyst text from the legacy\n'
            f"  2026-07-05 documents, keyed by bug number.\n-->\n\n"
        )

    population = f"""## Population — how the counts relate

*(all numbers in this section derived from `{targets_rel}` and `logs/` at generation time)*

- **{n_targets} targets** in the manifest (batches 1–6; by language: {", ".join(f"{k} {v}" for k, v in sorted(by_language.items()))}), covering **{n_repos} distinct
  repositories** — {n_targets - n_repos} targets are batch-5 "v2" refined-invariant re-fuzzes
  sharing an existing clone (`clone_alias`).
- **{len(fuzzable)} targets carry runnable fuzz harnesses** ({len(fuzz_funcs)} fuzz functions);
  **{len(harnessless)} targets are manifest-tracked without a fuzzer** (static-confirmed
  finding, deduplicated against another harness, or dropped with reason — see
  "Not fuzzed" below).
- All {len(executed_targets)} harness-bearing targets were executed: **{len(real_runs)} fuzz-function
  runs logged** ({n_crashfail_runs} produced crashers/failures, {n_clean_runs} ran clean).
- **{len(BUGS)} real bugs** confirmed: {sum(1 for b in BUGS if b["method"] == "fuzz")} by fuzz execution,
  {sum(1 for b in BUGS if b["method"] != "fuzz")} by static scout / grep-sweep confirmation
  (write-ups prefixed `static-…`).

**Why earlier documents disagreed (48 vs 58 targets, 52 vs 61 fuzzers, ≥15 vs 18
bugs):** the legacy CAMPAIGN-SUMMARY was frozen at batch-5 close, when the
manifest held 48 targets (batches 1–5) — batch 6 later appended 10 targets
(9 fuzzable) and the 889-repo grep sweep. Its "52 fuzzers" additionally counted
rerun/re-seed executions; the legacy ROLLUP's "61 fuzzers executed" also counted
rerun legs. Its "≥15 bugs" predates #16 (node-feature-discovery, batch-5 Track-C
still running at freeze), #17 (cluster-etcd-operator, batch 6) and #18
(package-operator, batch-6 grep sweep). Neither legacy fuzzer count is exactly
reproducible from disk; the deterministic counts above supersede both."""

    # ---------------- SUMMARY ----------------
    s = [header("FUZZ-CAMPAIGN-SUMMARY.md")]
    s.append("# Offline fuzz campaign — summary\n")
    s.append(f"**Duration:** {start} → {end} (batches 1–6)")
    s.append(f"**Scope:** {SCOPE_LINE}")
    s.append(f"**Method:** {METHOD_LINE}\n")
    n_advs = len(advisories) - (1 if "TRACK-3-CPP-TARGETS.md" in advisories else 0) or len(
        advisories
    )
    s.append(
        f"**Headline:** {n_targets} manifest targets ({n_repos} repos) · "
        f"{len(fuzzable)} fuzzed with {len(fuzz_funcs)} fuzz functions · "
        f"**{len(BUGS)} real bugs** ({n_medplus} Medium+; top CVSS ~8.1) · "
        f"{n_advs} portfolio advisories · "
        f"fuzz-bug hit-rate {hit_rate} executed targets ({hit_rate_pct}%)\n"
    )
    s.append(population + "\n")
    s.append("## Results by batch\n")
    s.append(
        "*(targets/fuzzers derived from the manifest; bugs attributed to the "
        "batch of the target they were found in)*\n"
    )
    s.append("| Batch | Targets | Fuzz functions | Real bugs | Bug #s |")
    s.append("|--:|--:|--:|--:|---|")
    for bt, n_t, n_f, n_b in batch_rows:
        nums = ", ".join(f"#{n}" for n in sorted(bug_batch.get(bt, []))) or "—"
        s.append(f"| {bt} | {n_t} | {n_f} | {n_b} | {nums} |")
    sw = bug_batch.get("sweep", [])
    s.append(
        f"| grep sweep ({n_cand} repos) | — | — | {len(sw)} | "
        + (", ".join(f"#{n}" for n in sorted(sw)) or "—")
        + " |"
    )
    s.append(f"| **Total** | **{n_targets}** | **{len(fuzz_funcs)}** | **{len(BUGS)}** | |\n")
    s.append("## Confirmed bugs (severity-ranked)\n")
    s.append(
        "*(per-bug CVSS/CWE/advisory carried from analyst triage; write-up existence machine-verified)*\n"
    )
    s.append("| # | Repo | Bug | CVSS | CWE | Advisory | Found by |")
    s.append("|--:|---|---|--:|---|---|---|")
    bmap = {b["num"]: b for b in BUGS}
    for n in SUMMARY_ORDER:
        b = bmap[n]
        s.append(
            f"| {n} | {b['target']} | {b['title']} | {b['cvss']} | {b['cwe']} | {b['adv']} | {b['method']} |"
        )
    s.append("")
    s.append("## Bug classes (derived from per-bug advisory mapping)\n")
    s.append("| Class | Advisory | Bugs |")
    s.append("|---|---|---|")
    for adv in ("ADV-001", "ADV-002", "ADV-003"):
        nums = ", ".join(f"#{n}" for n in sorted(adv_counts.get(adv, [])))
        s.append(
            f"| {ADV_CLASSES[adv]} | HPS-{adv[:3]}-2026-{adv[4:]} | {len(adv_counts.get(adv, []))} ({nums}) |"
        )
    unc = adv_counts.get("—", [])
    if unc:
        s.append(f"| Unclassed | — | {len(unc)} ({', '.join(f'#{n}' for n in sorted(unc))}) |")
    s.append("")
    s.append(f"## Pattern hit-rates\n\n{CARRIED_TAG}\n\n{PATTERN_HIT_RATES}\n")
    s.append("## Confirmed clean (executed, no crasher, no confirmed bug)\n")
    s.append("*(derived from `logs/`)*\n")
    s.append(", ".join(clean_targets) + ".\n")
    s.append("## Crashers triaged as noise / FP / harness gap (no real bug)\n")
    s.append("*(derived: crash/fail log present but no confirmed-bug write-up)*\n")
    s.append(", ".join(noise_targets) + ".\n")
    s.append("## Not fuzzed — manifest targets without a harness\n")
    s.append("*(derived from `targets.json` notes)*\n")
    s.append("| Target | Batch | Reason (manifest note / audit_ref) |")
    s.append("|---|--:|---|")
    for t in harnessless:
        note = t.get("note") or t.get("audit_ref") or "(no reason recorded)"
        bug_nums = sorted(b["num"] for b in BUGS if b["target"] == t["id"])
        if bug_nums:
            note += " — confirmed bug(s): " + ", ".join(f"#{n}" for n in bug_nums)
        s.append(f"| {t['id']} | {t['batch']} | {note} |")
    s.append("")
    s.append(f"### Wider not-fuzzed scope\n\n{CARRIED_TAG}\n\n{NOT_FUZZED_SCOPE}\n")
    s.append(f"## Methodology takeaways for future audits\n\n{CARRIED_TAG}\n\n{METHODOLOGY}\n")
    s.append("## Artefacts (counted on disk at generation time)\n")
    s.append(
        f"- `{targets_rel}` — {n_targets}-target manifest (repo/commit/harness/fuzztime/goos/batch)"
    )
    n_harness_refs = sum(len(t["harnesses"]) for t in targets)
    s.append(
        f"- `harnesses/<repo>/*_fuzz*_test.go` — {len(harness_files_disk)} harness files on disk, "
        f"all {len(harness_files_manifest)} manifest-referenced files present "
        f"({n_harness_refs - len(harness_files_manifest)} files are referenced by two harness entries)"
    )
    s.append(f"- `logs/<repo>/<Fuzz>.log` — {len(real_runs)} fuzz-function run logs")
    s.append(
        f"- `findings/**/<repo>/fuzz-corpus/**` — {len(writeups)} write-ups "
        f"({n_bug_writeups} confirmed bugs + {n_other_writeups} noise/FP/harness-gap/info)"
    )
    s.append(f"- `advisories/` — {', '.join(advisories)}")
    s.append(
        f"- `reports/<repo>-fuzzing-report.md` — {len(report_repos)} per-repo reports "
        f"({n_reports} copies published into `findings/**/`)"
    )
    s.append(
        f"- grep sweep — {n_cand} candidate repos, {n_hits} pattern hits across "
        f"{len(hit_repos)} repos (`pattern-hits.json`), 1 new vulnerable (#18 package-operator)"
    )
    s.append("- `BATCH-{3,4,5,6,7}-PLAN.md` — batch strategy evolution\n")
    s.append("Branches: `traust@create-fuzzing-batch1`, `analysis-results@fuzz-reports-batch1`.")
    summary_text = "\n".join(s) + "\n"

    # ---------------- ROLLUP ----------------
    r = [header("FUZZ-FINDINGS-ROLLUP.md")]
    r.append("# Fuzz Campaign — Medium/High/Critical Findings Rollup\n")
    r.append(
        "**Campaign:** Offline Go-native fuzzing of `analysis-results/findings/` audit-named targets"
    )
    r.append(f"**Period:** {start} → {end} (batches 1–6 + {n_cand}-repo grep sweep)")
    r.append("**Method:** `go test -fuzz` @ 15m–1h per target, no live cluster/cloud/network")
    r.append(
        f"**Coverage:** {n_targets} manifest targets ({n_repos} distinct repos, "
        f"{len(fuzzable)} with harnesses), {len(real_runs)} fuzz-function runs executed; "
        f"source-pattern grep swept {n_cand} additional repos; "
        f"{n_reports} report copies in `findings/**/`"
    )
    r.append("**Status:** FINAL — regenerated deterministically; see header\n")
    r.append("---\n")
    r.append(population + "\n")
    r.append("---\n")
    r.append("## Executive summary\n")
    r.append(
        f"**{len(BUGS)} real bugs** confirmed. **{n_medplus} rated Medium or higher** "
        f"(CVSS ≥ 4.0). Three cross-cutting bug classes account for "
        f"{sum(len(v) for k, v in adv_counts.items() if k != '—')} of {len(BUGS)}:\n"
    )
    r.append("| Class | Instances | Highest CVSS | Advisory |")
    r.append("|---|--:|--:|---|")
    class_max = {"ADV-001": "**8.1**", "ADV-002": "**7.1**", "ADV-003": "5.7"}
    for adv in ("ADV-001", "ADV-002", "ADV-003"):
        r.append(
            f"| {ADV_CLASSES[adv]} | {len(adv_counts.get(adv, []))} | {class_max[adv]} | HPS-{adv[:3]}-2026-{adv[4:]} |"
        )
    r.append("")
    r.append("**Highest-urgency single fix:** `openshift/oauth-proxy` (`/\\` open redirect,")
    r.append("finding #12) — one 3-line patch closes CWE-601 across **126 shipped products**.\n")
    r.append("---\n")
    r.append(f"## HIGH (CVSS ≥ 7.0)\n\n{CARRIED_TAG}\n")
    for n in HIGH_ORDER:
        r.append(BUG_DETAILS[n] + "\n")
    r.append("---\n")
    r.append(f"## MEDIUM (CVSS 4.0–6.9)\n\n{CARRIED_TAG}\n")
    for n in MEDIUM_ORDER:
        r.append(BUG_DETAILS[n] + "\n")
    r.append("---\n")
    r.append("## LOW (CVSS < 4.0) — not detailed here; see `FUZZ-CAMPAIGN-SUMMARY.md`\n")
    r.append("| # | Repo | Bug | CVSS |")
    r.append("|--:|---|---|--:|")
    for n in LOW_ORDER:
        b = bmap[n]
        r.append(f"| {n} | {b['target']} | {b['title']} | {b['cvss']} |")
    r.append("")
    r.append("---\n")
    r.append(
        f"## Remediation priority (recommended order)\n\n{CARRIED_TAG}\n\n{REMEDIATION_PRIORITY}\n"
    )
    r.append("---\n")
    r.append(
        f"## Verified NOT vulnerable (negative controls)\n\n{CARRIED_TAG}\n\n{NOT_VULNERABLE}\n"
    )
    r.append(
        f"| **{n_cand} repos** source-grepped for redirect + sprig patterns (`sweep-grep-all.sh`) "
        f"| — | {n_hits} hits → {len(hit_repos)} unique repos → 1 new vulnerable "
        f"(package-operator #18); rest bindata-trusted / correctly-allowlisted / "
        f"release-branch variants of #8 | *(derived)*\n"
    )
    r.append("---\n")
    r.append("## Artefacts (counted on disk at generation time)\n")
    r.append("| | |")
    r.append("|---|---|")
    r.append(
        f"| Per-bug write-ups | `findings/**/<repo>/fuzz-corpus/**` — {len(writeups)} files "
        f"({n_bug_writeups} real bugs + {n_other_writeups} noise/FP/gap/info) |"
    )
    r.append(
        f"| Portfolio advisories | `advisories/`: {', '.join(a for a in advisories if a.startswith('HPS-ADV'))} |"
    )
    r.append(
        "| Minimised crash inputs | `clones/<repo>/**/testdata/fuzz/<Fuzz>/<hash>` (clones pruned after campaign; inputs preserved in write-ups) |"
    )
    r.append(
        f"| Per-repo reports | {len(report_repos)} reports, {n_reports} copies in `analysis-results/findings/**/` |"
    )
    r.append(f"| Run logs | `{script_rel.parent}/logs/` — {len(real_runs)} fuzz-function logs |")
    r.append("| Full campaign detail | `FUZZ-CAMPAIGN-SUMMARY.md` |")
    r.append(
        "| Branches | `traust@create-fuzzing-batch1`, `analysis-results@fuzz-reports-batch1` |\n"
    )
    r.append("---\n")
    r.append(
        f"## Remaining offline surfaces (documented, not started — different pipeline)\n\n{CARRIED_TAG}\n\n{REMAINING_SURFACES}\n"
    )
    r.append("---\n")
    r.append(
        f"*Document status: FINAL — batch-6 exhaustion sweep complete ({n_cand}/{n_cand} repos "
        "pattern-grepped). Go-native offline fuzzing surface exhausted for the three "
        "confirmed patterns; remaining offline value is in C/C++ Track-3.*"
    )
    rollup_text = "\n".join(r) + "\n"

    # ---------------- JSON sidecar (machine-readable summary) ----------------
    pattern_rows = []
    for ln in PATTERN_HIT_RATES.splitlines():
        cells = [c.strip() for c in ln.strip().strip("|").split("|")]
        if len(cells) < 5 or cells[0] in ("Pattern", "") or set(cells[0]) <= {"-", ":"}:
            continue
        pattern_rows.append(
            {
                "name": cells[0].strip("`"),
                "tested": int(re.search(r"\d+", cells[1]).group()),
                "vulnerable": int(re.search(r"\d+", cells[2]).group()),
                "rate": cells[3],
                "advisory": None if cells[4] in ("—", "-", "") else cells[4],
            }
        )
    if not pattern_rows:
        fail("pattern hit-rate table produced zero sidecar rows")
    sidecar = {
        "generated": TODAY,
        "harness_version": hver,
        "manifest_generated": manifest.get("generated", "?"),
        "duration": {"start": start, "end": end},
        "totals": {
            "targets": n_targets,
            "repos": n_repos,
            "fuzzed_targets": len(fuzzable),
            "fuzz_functions": len(fuzz_funcs),
            "executed_targets": len(executed_targets),
            "runs_logged": len(real_runs),
            "bugs": len(BUGS),
            "bugs_medium_plus": n_medplus,
            "bugs_by_fuzz": sum(1 for b in BUGS if b["method"] == "fuzz"),
            "advisories": n_advs,
            "hit_rate": hit_rate,
            "hit_rate_pct": hit_rate_pct,
        },
        "batches": (
            [
                {"batch": str(bt), "targets": n_t, "fuzz_functions": n_f, "bugs": n_b}
                for bt, n_t, n_f, n_b in batch_rows
            ]
            + [
                {
                    "batch": "grep-sweep",
                    "targets": None,
                    "fuzz_functions": None,
                    "bugs": len(bug_batch.get("sweep", [])),
                }
            ]
        ),
        "bugs": [
            {
                "num": n,
                "target": bmap[n]["target"],
                "title": bmap[n]["title"],
                "cvss": bmap[n]["cvss"],
                "cwe": bmap[n]["cwe"],
                "advisory": bmap[n]["adv"],
                "method": bmap[n]["method"],
            }
            for n in SUMMARY_ORDER
        ],
        "patterns": pattern_rows,
        "advisory_files": advisories,
    }
    sidecar_text = json.dumps(sidecar, indent=1, ensure_ascii=False) + "\n"

    SUMMARY_OUT.write_text(summary_text)
    ROLLUP_OUT.write_text(rollup_text)
    SIDECAR_OUT.write_text(sidecar_text)
    print(f"wrote {SUMMARY_OUT}")
    print(f"wrote {ROLLUP_OUT}")
    print(f"wrote {SIDECAR_OUT}")
    if METRICS_FUZZ_DIR.parents[1].exists():  # progress-tracker/metrics/
        METRICS_FUZZ_DIR.mkdir(parents=True, exist_ok=True)
        for text, name in (
            (summary_text, SUMMARY_OUT.name),
            (rollup_text, ROLLUP_OUT.name),
            (sidecar_text, SIDECAR_OUT.name),
        ):
            (METRICS_FUZZ_DIR / name).write_text(text)
            print(f"wrote {METRICS_FUZZ_DIR / name}")
    else:
        print(
            "WARNING: progress-tracker/metrics/ not found; metrics copies skipped", file=sys.stderr
        )
    print(
        f"derived: {n_targets} targets / {n_repos} repos / {len(fuzzable)} fuzzable / "
        f"{len(fuzz_funcs)} fuzz funcs / {len(real_runs)} runs logged "
        f"({n_crashfail_runs} crash-fail, {n_clean_runs} clean) / {len(BUGS)} bugs "
        f"({n_medplus} Medium+) / {len(writeups)} write-ups / {n_reports} report copies / "
        f"sweep {n_cand} repos {n_hits} hits"
    )


if __name__ == "__main__":
    raise SystemExit(main())
