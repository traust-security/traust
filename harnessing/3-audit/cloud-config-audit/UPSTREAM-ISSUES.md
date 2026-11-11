# DRAFTS — filing upstream is a human decision

Draft issue text for Checkov engine gaps observed during the
81-target Phase-0 /cloud-config-audit sweep (2026-07, reports under
`analysis-results/cloud-config/`). **Nothing here is filed
automatically**: an agent never opens an upstream issue; a maintainer
reviews each draft, re-verifies the repro against the then-current
Checkov release, strips any internal references, and files by hand.
All observations are against the pinned engine, **Checkov 3.3.6**
(`CHECKOV_VERSION` in traust-core's `models/cloud_config.py`), running under the
skill's standard contract: **declared-configuration evidence only**
(no cloud API calls) and every runner invocation recorded in the
report's `metadata.deterministic_steps` — see SKILL.md.

The harness already compensates for every gap below (Containerfile
aliasing, mechanical coverage-gap register, SKILL.md engine-FP
suppression guidance) — filing upstream is about fixing the ecosystem,
not unblocking us.

---

## 1. dockerfile framework skips `Containerfile`-named files

- **Title:** dockerfile framework does not scan files named
  `Containerfile` / `Containerfile.*` (Podman/Buildah/Red Hat
  convention)
- **Affected version:** 3.3.6
- **Repro sketch:** `mkdir t && printf 'FROM scratch\nUSER root\n' >
  t/Containerfile && checkov -d t --framework dockerfile -o json` →
  zero checks evaluated, no error, no signal that the file was
  skipped. Rename the same file to `Dockerfile` → CKV_DOCKER checks
  evaluate. `Containerfile` is the documented default for
  Podman/Buildah builds.
- **Expected:** `Containerfile` and `Containerfile.*` matched by the
  dockerfile framework (or at minimum a skipped-file notice).
- **Our evidence:** rhoim-bootc-images `vllm-bootc/Containerfile`
  silently unassessed —
  `analysis-results/cloud-config/rhoim-bootc-images/`.
- **Our mitigation:** traust-engine's `CheckovProvider` materializes Dockerfile-named
  alias symlinks in a temp scan tree and maps fact paths back
  (`containerfile_alias_workaround`).

## 2. Silent zero-coverage for providers with no policies (rhoas, Cloudflare, IBM Cloud)

- **Title:** terraform framework evaluates zero checks for
  provider-only trees (rhoas / Cloudflare / IBM Cloud) with no
  coverage signal
- **Affected version:** 3.3.6
- **Repro sketch:** a `.tf` tree whose resources are exclusively from
  a provider Checkov has no policies for (e.g. `rhoas_*`,
  `cloudflare_*`, `ibm_*`) → `checkov -d . -o json` returns
  passed=0/failed=0 with exit 0; indistinguishable from a clean or
  empty tree. A "0 applicable policies for N parsed resources"
  summary line (or per-provider policy count) would make the
  non-coverage visible.
- **Our evidence:** `analysis-results/cloud-config/
  terraform-provider-rhoas/`, `er-cloudflare-account/`,
  `er-cloudflare-zone/`, `ibmc-workspace-vlans/`.
- **Our mitigation:** mechanical `IacInventory.gaps()` in
  traust-core's `models/cloud_config.py` emits a NOT-ASSESSED gap whenever `.tf` files exist
  but the terraform framework evaluated zero checks.

## 3. Weak Bicep parsing (large real-world parse-failure rate)

- **Title:** bicep framework fails to parse a large share of
  real-world Bicep files
- **Affected version:** 3.3.6
- **Repro sketch:** run `checkov -d . --framework bicep -o json` on a
  substantial production Bicep codebase (modules, user-defined types,
  loops, nested deployments); a large fraction of files land in
  `summary.parsing_errors`. On Azure/ARO-HCP we measured **82 of 188
  Bicep files (44%) failing to parse**, so most of the declared
  surface is silently unassessed.
- **Our evidence:** `analysis-results/cloud-config/ARO-HCP/` facts
  (`parsing_errors` count and gaps entries).
- **Our mitigation:** parse failures and zero-check bicep trees are
  loud `gaps[]` entries; transpile-based workarounds deliberately not
  adopted (dependency intake gate — see SKILL.md known limitations).

## 4. CKV_AWS_27 does not credit SQS-managed SSE (`SqsManagedSseEnabled`)

- **Title:** CKV_AWS_27 flags SQS queues encrypted with SSE-SQS
  (`sqs_managed_sse_enabled = true`) as unencrypted
- **Affected version:** 3.3.6
- **Repro sketch:** `resource "aws_sqs_queue" "q" {
  sqs_managed_sse_enabled = true }` → CKV_AWS_27 FAILED, though the
  queue is encrypted at rest (SSE-SQS has been the AWS default-capable
  mode since 2021); only `kms_master_key_id` is credited.
- **Expected:** either encryption mode passes the check (or a distinct
  check differentiates KMS vs SSE-SQS).
- **Our evidence:** recurring engine-FP class across the Phase-0
  sweep's AWS terraform targets (`analysis-results/cloud-config/`,
  er-aws-* series); suppressed per SKILL.md with per-queue attribute
  citations.

## 5. CKV2_GCP_18 only credits classic firewall rules, not network firewall policies

- **Title:** CKV2_GCP_18 does not recognize
  `google_compute_network_firewall_policy` (+ association) as
  firewall coverage for a network
- **Affected version:** 3.3.6
- **Repro sketch:** `google_compute_network` protected via
  `google_compute_network_firewall_policy` +
  `google_compute_network_firewall_policy_association` +
  `..._rule` (Google's recommended successor to classic rules) →
  CKV2_GCP_18 still FAILED; only classic `google_compute_firewall`
  resources satisfy the YAML graph query.
- **Our evidence:** engine-FP class from the Phase-0 sweep's GCP
  terraform targets (`analysis-results/cloud-config/`); suppressed per
  SKILL.md citing the policy association resources.

## 6. Non-Dockerfile `Dockerfile.<x>.<y>` files misparse as Dockerfiles

- **Title:** dockerfile framework misparses `Dockerfile.<x>.<y>`
  prefix-named files that are not Dockerfiles (pip constraints files
  etc.)
- **Affected version:** 3.3.6
- **Repro sketch:** a file named e.g. `Dockerfile.build.constraints`
  containing pip constraints (`package==1.2.3` lines) is picked up by
  the `Dockerfile.*` name match and either misparses or emits
  meaningless CKV_DOCKER facts against non-Dockerfile content. A
  cheap content sniff (first instruction must be a Dockerfile keyword
  such as FROM/ARG/# syntax) would avoid the class.
- **Our evidence:** engine-FP class from the Phase-0 sweep
  (`analysis-results/cloud-config/`); suppressed per SKILL.md citing
  the file's actual format.

## 7. CKV2_AWS_19 misses EIP association via ENI

- **Title:** CKV2_AWS_19 flags EIPs associated through a network
  interface (ENI) as unattached
- **Affected version:** 3.3.6
- **Repro sketch:** `aws_eip` + `aws_eip_association` using
  `network_interface_id` (or `aws_eip.network_interface`) instead of
  `instance` → CKV2_AWS_19 FAILED although the EIP is in use; the
  graph query only follows the instance-attachment edge.
- **Our evidence:** engine-FP class from the Phase-0 sweep's AWS
  terraform targets (`analysis-results/cloud-config/`); suppressed per
  SKILL.md citing the association resource.

## 8. No framework assesses OpenShift Template / Tekton PipelineRun objects

- **Title:** objects inside OpenShift Templates (`kind: Template`) and
  Tekton `.tekton/` PipelineRuns are not assessed by any framework
- **Affected version:** 3.3.6
- **Repro sketch:** a yaml with `kind: Template` whose `objects:` list
  contains a privileged `DeploymentConfig`/`Deployment` → kubernetes
  framework evaluates nothing inside `objects:` (parameterized
  manifests are not unwrapped); `.tekton/` PipelineRun files likewise
  match no framework. Both silently contribute zero checks.
- **Our evidence:** Phase-0 sweep targets carrying OpenShift Templates
  and Pipelines-as-Code `.tekton/` trees
  (`analysis-results/cloud-config/`).
- **Our mitigation:** mechanical NOT-ASSESSED gaps for both classes in
  traust-core's `IacInventory.gaps()` (template unwrapping deliberately not attempted).
