---
name: operator-priv-profile
description: Use when the user asks whether an operator runs with least privilege, what SCCs/securityContext/namespaces/roles an operator uses or requires, or for a fleet least-privilege inventory of OpenShift core and optional operators. Builds a deterministic per-operator privilege profile from manifests/CSVs (tier 1 — SCC requests, per-container securityContext, namespaces/install modes, complete RBAC enumeration), diffs shipped RBAC against the code's +kubebuilder:rbac markers (tier 2 — surplus grants = least-priv gap), and ships a gated runtime capture for the actually-assigned SCC and effective SA permissions (tier 3, executed only with explicit cluster authorization). Records canonical priv_profile assessments for each profiled commit through traust-core.
metadata:
  harness.tier: "primary"
---

# Operator Privilege Profile (least-privilege assessment)

> **Paths.** `analysis-results/…` and `progress-tracker/…` in this skill are the
> default workspace layout. They resolve through `locations:` in `traust.yaml` in
> `$TRAUST_CONFIG_HOME` (`docs/setup.md`, Storage locations); substitute your
> configured roots.


Answers "does this operator run with the least privileges it requires?"
in three fidelity tiers. The findings tree alone cannot answer this — it
records privilege *violations*, not inventories; this skill builds the
*has vs. needs* picture.

| Tier | Question | Source | Tool |
|---|---|---|---|
| 1 | What does the operator **ask for**? | manifests + CSV in the repo | `traust adapters priv-profile` |
| 2 | What does it **declare it needs**? | `+kubebuilder:rbac:` markers vs shipped roles | same (diff section) |
| 3 | What does it **actually run with**? | live cluster (pod `openshift.io/scc`, `oc auth can-i --list`) | `capture_runtime_privileges.py` |

## Tier 1+2 — static profile

```bash
traust repo checkout <url> --ref <commit-sha> --history 1
python3 -m traust.cli adapters priv-profile <local-path> --name <repo-name> \
    --out analysis-results/findings/<product>/<repo>/<repo-name>-priv-profile.json
```

The command prints the checkout's path (`<local-path>`); resolve a branch ref to
its head commit SHA first (the forge's MCP tools, or `git ls-remote <url> <ref>`).

Emits `<repo>-priv-profile.json` next to the repo's audit report:

- **SCC requests** — RBAC `use` verbs on `securitycontextconstraints`
  (with `resourceNames`) plus any shipped SCC objects. *No request
  recorded ⇒ OpenShift assigns `restricted-v2` by default* — say that,
  never imply "unknown".
- **securityContext** — pod- and container-level for every workload
  (Deployment/StatefulSet/DaemonSet + CSV-embedded deployments), plus
  host{Network,PID,IPC} and hostPath volumes.
- **Namespaces / install modes** — Namespace objects, workload
  namespaces, CSV `installModes`, OperatorGroup targetNamespaces.
- **Complete RBAC enumeration** — every Role/ClusterRole/CSV-permission
  rule with scope + source, and risk flags (wildcards, secrets access,
  RBAC write, escalate/bind/impersonate, pods/exec, nodes).
- **Tier-2 diff** — shipped rules with no `+kubebuilder:rbac` marker
  backing them (`shipped_not_declared`) are the least-privilege surplus
  candidates. Repos without markers get an honest "not derivable
  statically" note — do NOT infer need from silence.

Record each profile as a priv-profile assessment of the profiled commit
(`git -C <local-path> rev-parse HEAD`):

```bash
python3 -m traust.cli reporting record \
    analysis-results/findings/<product>/<repo>/<repo>-priv-profile.json \
    --kind priv_profile --repo-url <url> --sha <commit> --branch <branch>
```

Fleet rollup (after recording a set; each repository's latest recorded
profile, `--as-of <ISO time>` for an earlier point):

```bash
python3 -m traust.cli dashboard view privileges \
    --out progress-tracker/metrics/dashboards/operator-least-priv/
```

Emits four artifacts, one row per repository with one column per assessment
question (SCCs requested / securityContext posture / namespaces + install
modes / RBAC): `operator-least-privilege-rollup.md` (paste-into-doc table),
`.json` (full rows), `.csv` (spreadsheet export), and `.html` (KPI summary +
table). Exclude catalog aggregation trees (certified-operators,
community-operators, marketplace) from profiling — a catalog's thousands of
third-party bundles would read as one giant "operator" and distort the
ranking.

## Tier 3 — runtime capture (gated; execute only when scheduled)

```bash
python harnessing/3-audit/operator-priv-profile/scripts/capture_runtime_privileges.py \
    --namespace <ns> --name <repo-name> \
    --out-dir analysis-results/findings/<product>/<repo>/ \
    --i-am-authorized [--kubeconfig <path>]
```

Read-only (`get`/`auth can-i` only, audit trail embedded). **Fail-closed:
refuses without `--i-am-authorized`**, which asserts the cluster is
within the campaign's authorized scope (same discipline as
validate-findings). Captures per pod: the ACTUALLY-ASSIGNED SCC
annotation, container securityContexts as admitted, the namespace PSA
labels, and each ServiceAccount's effective permission list. The
deploy-operator / validate-operator-live lanes are the natural place to
run this right after install.

## Interpretation rules

1. **Requested ≠ assigned.** Tier 1 shows intent; only tier 3 shows the
   SCC actually applied. Keep the tiers labeled in every artifact.
2. **Surplus needs verification before filing.** `shipped_not_declared`
   rules may be exercised by non-kubebuilder code paths (plain client-go,
   helpers); confirm with a call-site search before calling it excess.
   Confirmed surplus feeds `/file-security-defect` or the audit report as
   an authorization finding.
3. **Helm/Go-templated manifests are skipped** by the parser — a profile
   from a chart-heavy repo is partial; say so rather than presenting it
   as complete.
4. Profiles are inventory documents, not findings: place them beside the
   audit reports in `analysis-results`; only the rollup goes to
   `progress-tracker/metrics/dashboards/` (rollups-only discipline — the
   convention is documented for every skill in `docs/artifacts.md`).

## Integrations

- **`/secure-code-audit`** runs the profiler as a conditional pre-scan on
  manifest-bearing repos (records `priv-profile` in `deterministic_steps`)
  — every audit/re-audit refreshes the fleet's profiles.
- **`/secure-container-audit`** profiles extracted operator **bundle
  images** (`/manifests` tree; tier-2 n/a — no Go source in images).
- **`/isolation-review`** consumes existing profiles as
  privilege-dimension evidence (never re-derives RBAC by hand where a
  profile exists).

## Failure modes

| Symptom | Cause | Fix |
|---|---|---|
| Empty profile from an operator repo | manifests are helm-templated or generated at build time | note partial coverage; profile the bundle/CSV repo instead |
| `surplus` = n/a fleet-wide | non-kubebuilder codebase | tier 3 or manual call-site review is the needs-baseline |
| Runtime capture refuses to run | missing `--i-am-authorized` | intentional — verify cluster authorization first |
