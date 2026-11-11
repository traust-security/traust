# OLM Operator Bundle — Repository Inventory Procedure

This procedure extracts every container image shipped in an OLM operator
bundle, maps each image back to its source repository, categorises by
functional area, produces a Markdown report and a CSV inventory in a segment
of kind `catalog`, and registers the repositories and their owner teams in
traust-core.

`<segment>` below is the descriptor segment resolved by the parent skill;
`<inputs>` is `locations.inputs`; `<product>` is the operator's package name.

---

## Prerequisites

The following tools MUST be available on `$PATH`. Check before proceeding:

- `skopeo` — for registry tag listing and image label inspection
- `podman` — for pulling and extracting operator bundles
- `python3` with `PyYAML` installed (`import yaml`)

Authentication: if the bundle registries need credentials, the environment
variable `REGISTRY_AUTH_JSON` must contain a Docker/Podman auth JSON (raw or
base64-encoded). Decode it into a private temp file:

```bash
AUTHDIR=$(mktemp -d)   # per-user 0700 dir, never a fixed /tmp name
AUTHFILE="$AUTHDIR/auth.json"
printf '%s' "$REGISTRY_AUTH_JSON" | base64 -d > "$AUTHFILE" 2>/dev/null \
  || printf '%s' "$REGISTRY_AUTH_JSON" > "$AUTHFILE"
```

Use `--authfile "$AUTHFILE"` for all registry operations and remove `$AUTHDIR`
when done. Public registries need no auth file.

---

## Step 1 — Locate the operator bundle image

The registries to search come from the segment's `registries` list in
`<inputs>/inventory.yaml`, tried in order; bundle images are conventionally
named `<registry>/<product>-operator-bundle:<tag>`. If the list is absent and
the user did not pass `--image`, ask for the bundle reference.

Find the latest tag:

```bash
skopeo list-tags docker://<registry>/<bundle-name> --authfile "$AUTHFILE" \
  | python3 -c "import sys,json; [print(t) for t in sorted(json.load(sys.stdin)['Tags'])]" \
  | tail -20
```

## Step 2 — Extract the bundle

```bash
BUNDLE_DIR="$AUTHDIR/<product>-bundle"
podman pull --authfile "$AUTHFILE" <bundle-image>:<tag>
CONTAINER=$(podman create <bundle-image>:<tag>)
podman cp "$CONTAINER":/ "$BUNDLE_DIR/"
podman rm "$CONTAINER"
```

## Step 3 — Parse the ClusterServiceVersion (CSV)

Find the CSV YAML with the Glob tool: `$BUNDLE_DIR/**/*.clusterserviceversion.yaml`.

Extract `relatedImages` from the CSV:
```python
import yaml

with open("<csv-path>") as f:
    csv_data = yaml.safe_load(f)
related = csv_data["spec"].get("relatedImages", [])
```

If `relatedImages` is empty, check the deployment spec for `RELATED_IMAGE_*`
or `OPERAND_IMAGE_*` environment variables:
```python
deploy = csv_data["spec"]["install"]["spec"]["deployments"]
for d in deploy:
    for c in d["spec"]["template"]["spec"]["containers"]:
        for e in c.get("env", []):
            if "IMAGE" in e.get("name", ""):
                print(e["name"], e["value"])
```

Also check for the operator's own container image in the deployment spec.

## Step 4 — Check for build-metadata extras

Some bundles ship an `extras/<version>.json` with direct `git-url` mappings
per image:
```bash
cat "$BUNDLE_DIR"/extras/*.json | python3 -m json.tool
```

Each entry has: `image-key`, `image-remote`, `image-name`, `image-digest`,
`git-url`, `git-revision`. If `git-url` values are present and not `"N/A"`,
use them directly — this is the most reliable source when it exists.

## Step 5 — Resolve source repositories

For images without a `git-url`, inspect the image's OCI source labels. If the
CSV references a registry you cannot pull from, retry the same
`<name>@<digest>` against each registry in the descriptor's `registries` list
(mirrors carry identical digests):

```python
import subprocess, json

img_name_digest = full_ref.rsplit("/", 1)[-1]  # foo@sha256:…
for registry in registries:  # descriptor order
    ref = f"{registry}/{img_name_digest}"
    result = subprocess.run(
        ["skopeo", "inspect", "--authfile", authfile, f"docker://{ref}"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    if result.returncode == 0:
        break
labels = json.loads(result.stdout).get("Labels", {})
source = labels.get(
    "org.opencontainers.image.source", labels.get("url", labels.get("vcs-url", "UNKNOWN"))
)
```

When labels carry a vendor catalog URL instead of a source URL, resolve with
the descriptor's optional `image_sources:` map (image name → repository URL)
or a deployment extension's mapping table; record the mapping's origin in the
report. Common generic cases:

- Images that are rebuilds of another product's components (CLI, RBAC proxy,
  config reloaders) → that product's repositories.
- Base and runtime images (`ubi-*`, `postgresql-*`, `redis-*`, `memcached`)
  → mark as **Base Image** with no repository.

If the bundle is not available in any accessible registry, fetch the CSV from
the operator's source repository instead:
```bash
python3 -m traust.cli portfolio file --repo https://github.com/<org>/<repo> --sha <commit> \
  bundle/manifests/<name>.clusterserviceversion.yaml   # .file in the JSON output
```
(`<commit>` is a full sha, e.g. the default branch's from `git ls-remote <url> HEAD`.)

## Step 6 — Categorise

Group images by functional area. Common patterns:

- **Operator** — the top-level operator that manages all sub-components
- **Console / UI** — web console plugins or standalone UIs
- **Observability** — monitoring, metrics, grafana, prometheus, thanos
- **Policy / GRC** — policy engines, controllers, admission webhooks
- **Cluster Lifecycle** — provisioning, import, discovery, placement
- **Networking** — cross-cluster connectivity, service discovery
- **Storage / Data Protection** — CSI drivers, volume replication
- **Shared Infrastructure** — kube-rbac-proxy, kube-state-metrics, exporters
- **Shared Platform Images** — images rebuilt from the underlying platform
- **Base Images** — vendor base/runtime images (no repository)

## Step 7 — Produce CSV output

Write to `<inputs>/<segment>/<product>/<version>/<product>-<version>-payload-repos.csv`.

**Column schema:**
```
GitHub Repository,GitHub URL,Organization,Repo Name,Branch,Category,Payload Image Key(s),Image Count
```

(`GitHub Repository` / `GitHub URL` are the historical column names the graph
reads; they hold whatever forge the operator builds from.)

Rules:

- One row per unique repository (deduplicated)
- Multiple images from the same repo joined with `; `
- Multiple categories for the same repo joined with `; `
- Base images: set `GitHub Repository` to `N/A (<base-image-path>)`, leave
  URL/Org/Name empty
- Sort rows by repository

## Step 8 — Produce Markdown report

Write to `<inputs>/<segment>/<product>/<version>/<product>-<version>-payload-analysis.md`.

Structure:

1. **Title:** `# <Product Name> <version> — Repository Inventory`
2. **Metadata table:**
   ```
   | Field | Value |
   |---|---|
   | **Product** | <product> |
   | **Version** | <version> |
   | **Bundle Image** | `<bundle-image>:<tag>` |
   | **Total Images** | <count> |
   | **Unique Repositories** | <count> |
   ```
3. **Category sections** — one `## <Category>` per group, each with a table:
   ```
   | Repository | Payload Image(s) | Role |
   |---|---|---|
   | [org/repo](https://github.com/org/repo) | image-key(s) | description |
   ```
4. **Summary statistics** — table of category → unique repos → image count

## Step 9 — Register the repositories and their owners

`traust portfolio onboard --product <product> [--label <name>] --repo <URL>…` (every repository
in the CSV; base images have none), then follow the ownership resolution
procedure in the [parent skill](../SKILL.md#ownership-resolution).

*Retired*: `<inputs>/<segment>/<product>/owners.csv` (see the parent skill's
owners.csv schema).

## Step 10 — Tracker columns

*Retired with `owners.csv`*: traust-core has no `Jira Project` /
`Jira Component` column.

---

## Troubleshooting

| Problem | Solution |
|---|---|
| `skopeo inspect` returns FAILED | Retry the same `name@digest` against the next registry in the descriptor list |
| Image labels only have catalog URLs | Use `image_sources:` / the extension's mapping table (Step 5) or the extras JSON |
| `relatedImages` is empty in the CSV | Check deployment env vars for `RELATED_IMAGE_*` or `OPERAND_IMAGE_*` patterns |
| Bundle image not found | Try the remaining registries, or fetch the CSV from the operator's source repository |
| `extras/*.json` has `"N/A"` for `git-url` | Fall back to skopeo image label inspection |
