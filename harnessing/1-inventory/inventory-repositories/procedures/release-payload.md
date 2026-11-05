# Release Payload — Repository Inventory Procedure

This procedure extracts every container image shipped in an OpenShift/OKD-style
release payload image, maps each image back to its source repository,
categorises by functional area, produces a Markdown report and a CSV inventory
in a segment of kind `release-payload`, and registers the repositories, their
owner teams and the release (its version and commits) in traust-core.

`<segment>` below is the descriptor segment resolved by the parent skill;
`<inputs>` is `locations.inputs`.

---

## Prerequisites

The following tools MUST be available on `$PATH`. Check before proceeding:

- `oc` (OpenShift CLI) — for `oc adm release info`
- `skopeo` — for registry tag listing
- `python3` with `PyYAML` installed (`import yaml`)

Authentication: if the payload registry needs credentials, the environment
variable `REGISTRY_AUTH_JSON` must contain a Docker/Podman auth JSON (raw or
base64-encoded). Decode it into a private temp file:

```bash
AUTHDIR=$(mktemp -d)   # per-user 0700 dir, never a fixed /tmp name
AUTHFILE="$AUTHDIR/auth.json"
printf '%s' "$REGISTRY_AUTH_JSON" | base64 -d > "$AUTHFILE" 2>/dev/null \
  || printf '%s' "$REGISTRY_AUTH_JSON" > "$AUTHFILE"
```

Use `--authfile "$AUTHFILE"` (skopeo) or `-a "$AUTHFILE"` (oc) for all
registry operations, and remove `$AUTHDIR` when done. Public payloads need no
auth file.

---

## Step 1 — Identify the release image

The image reference comes from the segment's `payload_image` key in
`<inputs>/inventory.yaml`, with `{version}` substituted — for example
`quay.io/okd/scos-release:{version}` or a vendor's release repository. If the
key is absent and the user did not pass `--image`, ask.

If the user gives a minor version (e.g. "4.21"), find the latest z-stream:

```bash
oc adm release info <payload_image with version=4.21.0> -a "$AUTHFILE" 2>&1 | head -20
```

If that fails, increment the z-stream (4.21.1, 4.21.2, …) or list tags:

```bash
skopeo list-tags docker://<payload repository> --authfile "$AUTHFILE" \
  | python3 -c "import sys,json; [print(t) for t in json.load(sys.stdin)['Tags'] if t.startswith('<version>')]" \
  | sort -V | tail -5
```

## Step 2 — Extract image-to-repository mapping

```bash
oc adm release info <release-image> -a "$AUTHFILE" --commit-urls 2>&1 \
  | grep -E 'https?://' \
  | awk '{print $1, $2}' > "$AUTHDIR/payload-image-repo-map.txt"
```

This prints every payload image name alongside its source commit URL:

- Column 1: payload image name (e.g. `cluster-etcd-operator`)
- Column 2: full commit URL (e.g. `https://github.com/<org>/cluster-etcd-operator/commit/abc123`)

Strip `/commit/<sha>` (or `/-/commit/<sha>` on GitLab) from the URL to get the
repository. Extract the branch from the release info output (typically
`release-<version>`).

## Step 3 — Extract release metadata

Also capture from the `oc adm release info` output (without `--commit-urls`):

- Release name, version, digest, creation date
- Kubernetes version (from Component Versions)
- Machine OS version

## Step 4 — Categorise

Categorise each image/repo into functional groups. The groups below are the
standard payload anatomy; keep the names stable across versions so the graph's
category nodes stay comparable:

1. **ClusterOperators** — group images by the ClusterOperator they belong to
   (authentication, baremetal, cloud-controller-manager, cloud-credential,
   cluster-autoscaler, cluster-version, config-operator, console,
   control-plane-machine-set, csi-snapshot-controller, dns, etcd,
   image-registry, ingress, insights, kube-apiserver, kube-controller-manager,
   kube-scheduler, kube-storage-version-migrator, machine-api,
   machine-approver, machine-config, marketplace, monitoring, network,
   node-tuning, olm, openshift-apiserver, openshift-controller-manager,
   openshift-samples, service-ca, storage).
2. **Cluster API (CAPI) Providers** — `cluster-capi-operator`, `cluster-api`,
   `cluster-api-provider-*`
3. **Installer & Agent-Based Installer** — `installer`, `assisted-*`,
   `agent-installer-*`
4. **Core Platform Machinery** — `kubernetes` (hyperkube, kube-proxy, pod),
   `oc` (cli, deployer, tools), `origin` (tests), `cluster-bootstrap`,
   `cluster-policy-controller`, `builder`, `must-gather`, `driver-toolkit`
5. **Cloud Provider Identity & Encryption** — `*-pod-identity-webhook`,
   `*-encryption-provider`, `*-workload-identity*`, `*-karpenter-*`
6. **HyperShift** — `hypershift`
7. **Operating System** — `os` (the CoreOS-style node image)

Note repos that produce multiple images or are consumed by multiple
ClusterOperators (for example the `kubernetes` fork → hyperkube, kube-proxy,
pod; `csi-operator` → several CSI driver operators; `oc` → cli, cli-artifacts,
deployer, tools).

## Step 5 — Produce CSV output

Write to `<inputs>/<segment>/<segment>-<version>-payload-repos.csv`.

**Column schema:**
```
GitHub Repository,GitHub URL,Organization,Repo Name,Source Branch,Category,ClusterOperator(s),Payload Image(s),Image Count
```

(`GitHub Repository` / `GitHub URL` are the historical column names the graph
reads; they hold whatever forge the payload builds from.)

Rules:

- One row per unique repository (deduplicated)
- Multiple images from the same repo joined with `; `
- Multiple ClusterOperators for the same repo joined with `; `
- Sort rows by repository

Example:
```
example-org/cluster-etcd-operator,https://github.com/example-org/cluster-etcd-operator,example-org,cluster-etcd-operator,release-4.20,ClusterOperator,etcd,cluster-etcd-operator,1
```

## Step 6 — Produce Markdown report

Write to `<inputs>/<segment>/<segment>-<version>-payload-analysis.md`.

Structure:

1. **Title:** `# <label> <version> Release Payload — Repository Inventory`
   (`<label>` is the segment's `label` from the descriptor)
2. **Metadata table:**
   ```
   | Field | Value |
   |---|---|
   | **Release** | <label> <version> |
   | **Total Payload Images** | <count> |
   | **Unique Repositories** | <count> |
   | **Source Branch Pattern** | `release-<version>` |
   ```
3. **Category sections** — one `## <Category>` per group, each with a table:
   ```
   | Repository | Source Branch | Payload Image(s) | ClusterOperator(s) |
   |---|---|---|---|
   | [org/repo](https://github.com/org/repo) | `release-<ver>` | image-name | CO-name |
   ```
4. Sections sorted alphabetically by category name, repos sorted within each
   section.

## Step 7 — Register the repositories and their owners

`traust portfolio onboard --product <segment> --label <label> --repo <URL>…`
(every repository in the CSV), then follow the ownership resolution procedure
in the [parent skill](../SKILL.md#ownership-resolution).

Then record the release, the payload's commits as they are (before removing
`$AUTHDIR`):

```bash
traust portfolio import-release --product <segment> --version <version> \
  --branch <source branch> --commits "$AUTHDIR/payload-image-repo-map.txt"
```

Re-running it for the same payload changes nothing; a different commit set
for a version already recorded is refused (a release doesn't change), and so
is a commit whose repository isn't registered (nothing is written).

*Retired*: `<inputs>/<segment>/owners.csv` (see the parent skill's owners.csv
schema).

## Step 8 — Tracker columns

*Retired with `owners.csv`*: traust-core has no `Jira Project` /
`Jira Component` column.

---

## Troubleshooting

| Problem | Solution |
|---|---|
| `oc adm release info` returns empty | Verify the auth file is valid JSON with `python3 -m json.tool "$AUTHFILE"`, or drop `-a` for a public payload |
| Image not found | Check `skopeo list-tags` for available versions |
| Some images have no commit URL | These are typically base images — categorise as "Operating System" or "Base Image" |
