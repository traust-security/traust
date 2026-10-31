# Setup reference

> New to the harness? The tiered requirements overview is
> [requirements.md](requirements.md) and the first-audit walkthrough is
> [getting-started.md](getting-started.md); this page is the complete
> reference for installation, configuration, storage, toolchain, and the
> contributor gates, in install order.

## 1. Start here: `install_traust`

```bash
scripts/install_traust            # choose TRAUST_CONFIG_HOME, copy traust.yaml,
                                  # persist the variable, optionally install the toolchain
scripts/install_traust --doctor   # run traust admin doctor against this shell's home
traust admin doctor               # every effective traust.yaml value and its source
```

The harness reads one config file, `traust.yaml`, from the directory
`TRAUST_CONFIG_HOME` names (default `~/.traust/config`; a deployment's
orchestrator points the variable at its private config checkout). Beside it sit
the model registry and any adopter-fact files you record (org parameters, ADR
registers, the benchmark answer key, the product map). `install_traust` copies
`config/traust.example.yaml` there as `traust.yaml`; you uncomment and fill in
what you use (database, identity, the ledger key — [signing.md](signing.md) —
budgets, locations). No `traust.yaml` at all is the zero-config local install:
SQLite and artifacts under `~/.traust`. Tool pins, safe-exec profiles and the
feeds registry ship with traust-core and are not configurable.

An old multi-file config home (`core.yaml`, `locations.yaml`, …) folds into one
file with `traust config migrate <old home>`: it writes `traust.yaml`, reports a
verdict for every file and prints the command to record each adopter fact.

`--doctor` is the troubleshooting entry point, and it is one code path: it runs
`traust admin doctor`, which reports core's preflight — the same check the
engine's start gate refuses on — so a gap (an unset location, a missing model
registry, an unmet pack requirement) is a FAIL that names its fix, never a
warning the run carries on past. Flags for CI: `--yes --config-home DIR
--toolchain PROFILE` (`--no-toolchain`, `--no-profile-write`, `--force` also
available). The full contract: [config/README.md](../config/README.md).

## 2. Prerequisites

- Python 3.11+ and [`uv`](https://github.com/astral-sh/uv) (or pip with the
  hash-pinned lockfile, below). The code-facts scans read target Python with
  the running interpreter, so an older one can't parse newer syntax and
  reports those files as a coverage gap; the runtime image runs on Python 3.14
- Git access to this repository and, for the multi-repository pipeline, the
  sibling data repositories (§3)
- Network access to the forge holding the repositories you audit
- A core-verified human identity for anyone who countersigns: `traust auth login`
  against the trusted issuers in `traust.yaml`'s `identity:` section, or
  `traust auth local --identity you@example.com` on a solo installation with
  `identity: {trust_local: true}` explicitly configured. Core verifies the
  signature, caller and any deployment directory policy on writes. Review
  commands may instead read an explicitly selected token from stdin, never argv
  or agent-visible logs. Retired `ledger auth` commands,
  `HARNESS_COUNTERSIGN_ALLOW_LOCAL` and `LAAS_*` do not configure this workflow.
  See [the command contract](cli-reference.md#direct-human-severity-recording).

Scanner tools are per capability, not global: nothing beyond the baseline is
needed until a skill calls for it. What each capability needs is the table in
[requirements.md](requirements.md); the pinned versions are the manifest
traust-core's shipped `external-tools.yaml`; licenses and citations are in
[external-dependencies.md](external-dependencies.md). Installing them is §4.

## 3. Clone the workspace and install

Standalone use needs only this repository. The multi-repository pipeline
expects a **workspace**: a parent directory holding the harness beside the
data repositories, which hold content, not code, and are referenced by
relative path ([storage.md](storage.md) for what goes where):

```bash
# FORGE is your git host and namespace, e.g. git@gitlab.example.com:my-team
FORGE=<your-forge-and-namespace>

mkdir harness-workspace && cd harness-workspace
git clone "$FORGE/traust.git"
git clone "$FORGE/analysis-results.git"        # findings store (name is the deployment's)
git clone "$FORGE/<inputs-inventory>.git"      # scope declarations, repo rosters
git clone "$FORGE/progress-tracker.git"        # metrics tree (name is the deployment's)

cd traust && uv sync
```

No `uv`? `pip install --require-hashes -r requirements.lock`.

`uv sync` installs `traust-core` at the commit selected in `pyproject.toml` and
resolved in `uv.lock`. Contracts and ledger come through core's pins, rather than
direct imports into the harness. The continuous-ops service, `traust-engine`, is
installed separately (the runtime image includes it); locally,
`uv tool install "traust-engine @ git+https://github.com/traust-security/traust-engine@<sha>"`.

Local domain operations call core's services through the app composition root.
`traust.yaml` in `TRAUST_CONFIG_HOME` selects core's database, identity and optional
ledger policy; a REST deployment is not required for the local CLI.
For PostgreSQL, use `uv sync --extra postgres`; SQLite needs no driver extra.
Core's platform configuration is documented in its
[development README](https://github.com/traust-security/traust-core/blob/development/README.md).

What each component owns, which repo to change, and how source conflicts and
commit updates work: [components.md](components.md). `uv sync --locked`
refuses an installed package that does not match its selected dependency;
`uv sync` restores the manifest/lockfile selection.

## 4. Scanner toolchain

The harness ships an opinionated, version-pinned toolchain. You name a
**profile** and it handles install, database population and provenance
stamping. Profiles are the `consumers` values in traust-core's shipped `external-tools.yaml`
(one per skill that needs external tools, plus `ledger-signing`); the CLI lists
them when given an unknown name.

```bash
./scripts/install-toolchain.sh secure-code-audit          # binaries + DBs for one profile
./scripts/install-toolchain.sh --all                      # every profile
python3 -m traust.cli admin toolchain setup --profile secure-code-audit   # same, via the CLI
python3 -m traust.cli admin toolchain doctor --profile secure-code-audit  # verify
```

Binaries download straight from each project's own upstream release at the
version pinned in the manifest — the same pins the toolchain container image
consumes, so workstation and job image match — and are verified against the
upstream checksum where the project publishes one. No third-party package
manager or index sits in between. Binaries land in `~/.local/bin` (override
with `HARNESS_BIN_DIR`); `--dry-run` previews. macOS and Linux. `doctor` exits
0 when every tool for the profile is installed at the pinned version with its
databases populated, 1 with a per-tool diagnostic otherwise; `/drift-watch`
(`traust dashboard view freshness`) shows the same readiness on demand.

Step by step, if you need to install by hand:

| Tool | Upstream release | Checksum verified |
|------|------------------|-------------------|
| `opengrep` | github.com/opengrep/opengrep | no (upstream publishes none) |
| `gitleaks` | github.com/gitleaks/gitleaks | yes |
| `syft` | github.com/anchore/syft | yes |
| `grype` | github.com/anchore/grype | yes |
| `osv-scanner` | github.com/google/osv-scanner — **air-gapped OSV scanning only, and not installed by the script or the image**: you install it at the pin in traust-core's shipped `external-tools.yaml` (see below). The default dependency pre-scan uses the OSV API | no (upstream publishes none) |
| `cosign` | github.com/sigstore/cosign | yes |
| `govulncheck` | `go install golang.org/x/vuln/cmd/govulncheck@<pin>` (needs a Go toolchain) | Go module checksum DB |

Take the pin from the manifest and fetch that tag's asset for your OS/arch.
Tools with no standalone upstream binary come from a package manager:

| Tool | Install method |
|------|---------------|
| `joern` | `brew install joern` or the [joern release](https://github.com/joernio/joern/releases) (Java 11+) |
| `skopeo` | `brew install skopeo` (macOS), `dnf install skopeo` (Fedora/RHEL) |
| `yara` | `brew install yara`, or build from the [yara release](https://github.com/VirusTotal/yara/releases) |
| `pip-audit` | `pipx install pip-audit` |
| `checkov` | `pipx install checkov==<pin>` — the pin is `CHECKOV_VERSION` in traust-core's `models/cloud_config.py`; `traust cloud-config run` hard-fails on a mismatch |

Vulnerability databases (grype, govulncheck) are populated by `setup`; to
refresh them, or to bundle them for an air-gapped host:

```bash
python3 -m traust.cli admin toolchain fetch-dbs --profile secure-container-audit
python3 -m traust.cli admin toolchain fetch-dbs --profile secure-container-audit --offline-bundle dbs.tar.gz
```

### OSV: the API by default, osv-scanner when air-gapped

The dependency pre-scan (`traust adapters osv`) reads the checkout's
lockfiles and manifests and queries the **OSV API**. That is the default
and needs nothing installed or kept current. The setting is `feeds.osv_access`
in `$TRAUST_CONFIG_HOME/traust.yaml`:

```yaml
feeds:
  osv_access: api        # default; or air-gapped
```

If the API cannot be used at all, the scan fails fast: `status: failed`,
an `ERROR:` line, exit 2, and no dependency results. A scan where only some
lookups failed is `degraded` (exit 3). Neither is ever "no advisories".

#### Manifests without a lockfile: deps.dev resolution

A `package.json`, `requirements*.txt`, `pom.xml` or `Cargo.toml` with no
lockfile beside it declares only direct dependencies. The pre-scan resolves
the rest through the **deps.dev API**, which is on by default:
- each direct dependency's resolved graph is added to the OSV lookup
  (`version_basis: resolved`, with `resolved_via`);
- a declaration with no version resolves at deps.dev's default version
  (`version_basis: resolved-default`).

For PyPI and Maven, a version the project declares itself overrides a
resolved one. Each dependency is resolved on its own, as of today, so the
result approximates an install; it isn't a lockfile. Whatever can't be
resolved stays in `unresolved_manifests` with a reason
(`transitive_coverage: partial`). npm, PyPI, Maven and Cargo only; Go needs
none (`go.mod` lists every module).

**Terms and attribution.** Use of the API is subject to the
[Google APIs Terms of Service](https://developers.google.com/terms), which
bind the operator who runs it. The resolved graphs are deps.dev-generated
data licensed CC BY 4.0, and every scan carries the attribution in
`metadata.resolution.attribution`. Details are in
[external-dependencies.md](external-dependencies.md).

The `deps_dev` source is in the feeds registry traust-core ships, which is not
adopter config, so resolution is always on; it isn't used air-gapped, where
manifests without a lockfile stay coverage gaps.

#### Air-gapped OSV scanning

For deployments with no route to the OSV API, set `feeds.osv_access: air-gapped`.
The pre-scan then runs **osv-scanner offline** (`--offline`) against a local
OSV database. **You provide both the binary and the database**: the harness
does not install them, and continuous operations do not keep them current.

1. Install osv-scanner on the scanning host (or into your extension of the
   toolchain image) at the version pinned in traust-core's shipped `external-tools.yaml`:
   the tested version, the floor the freshness view's `tool:osv-scanner`
   row checks. `install-toolchain.sh` and the image do not install it.
2. On a connected host, download the database:
   `osv-scanner scan source --offline-vulnerabilities --download-offline-databases <any dir>`.
3. Copy the cache directory to the scanning host and point
   `OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY` at it. Repeat the copy to refresh:
   results are only as current as your last copy.

A missing binary or database is `status: failed`, exit 2 (osv-scanner
itself exits 127 with an empty, clean-looking result in that case; the
adapter reads that as a failure). Coverage differs from the API: offline
osv-scanner reports no Go standard-library advisories (measured on a real
Go checkout, 2026-10-20: 73 of the API's 122 candidates, the gap all `stdlib` but 3), so
run govulncheck, which carries its own database, for Go. The other OSV
consumers query the API and do not run air-gapped: the fleet sweep
(`dependency-watch`) writes a `failed` worklist and exits 2, and advisory
fetches (`traust impact find` / `symbols` / `document`, the CVE-replay
monitor) report their lookups as failed.

### Container images (CI, platform worker, air gap)

For CI pipelines, platform worker pods, or air-gapped environments, use the
container images instead of the install script. External tooling and the
traust Python stack are **two separate images**, so a pin advance (weekly at
most) never forces a rebuild of the Python layer, and vice versa:

| Image | Contains | Tag |
|---|---|---|
| `traust-toolchain` | Pinned scanner binaries only (traust-core's shipped `external-tools.yaml`): opengrep, gitleaks, syft, grype, cosign, govulncheck, skopeo, yara, pip-audit (in its own isolated Python environment). No traust Python stack, no vulnerability databases. | `toolchain-<pin-set hash>` (`scripts/containerfile-build-args.py --pin-hash`) |
| `traust-runtime` | `FROM traust-toolchain` by digest, plus traust-core/traust at the Git SHAs pinned in `pyproject.toml`/`uv.lock` and traust-engine as a separate tool install (`TRAUST_ENGINE_SHA` in `Containerfile.runtime`), and the harness skill data (`harnessing/`, `config/`, `docs/`). | the commit, plus the toolchain hash it was built on (labels `traust.commit`, `traust.toolchain-hash`) |

**No vulnerability database ships in either image.** For offline scans, mount
databases kept current by the deployment, for example under
`/feeds/tool-dbs/<tool>/`. Set `GRYPE_DB_CACHE_DIR=/feeds/tool-dbs/grype` and
`GRYPE_DB_AUTO_UPDATE=false` for grype; direct govulncheck invocations take
`-db file:///feeds/tool-dbs/govulncheck`. The core-based scanner registration
does not automatically wire `locations.feeds_cache` or `FEEDS_CACHE_DIR` into
these tools. The caller must configure the database and verify it is usable
before scanning: grype fails on an empty database, but govulncheck can silently
report zero findings against an empty local database. osv-scanner
is installed in neither image: an air-gapped deployment
extends `traust-toolchain` with osv-scanner and its offline database
([Air-gapped OSV scanning](#air-gapped-osv-scanning)).

The runtime build fetches Python packages at the commit SHAs in
`pyproject.toml`/`uv.lock`; sibling repositories are not required. Scanner
versions and the pin-set hash come from traust-core's shipped `external-tools.yaml`.

```bash
./scripts/build-toolchain-image.sh                      # both images, tagged by pin hash / commit
./scripts/build-toolchain-image.sh --tools-only          # traust-toolchain only, e.g. to publish a pin advance
./scripts/build-toolchain-image.sh --tag <registry>/traust-runtime:<tag>
./scripts/build-toolchain-image.sh --tools-tag <registry>/traust-toolchain:<tag>

podman run --rm -v "$PWD":/workspace:Z traust-runtime:latest \
  admin toolchain doctor --profile secure-code-audit
```

`traust-runtime` is the **runtime base** a platform worker extends or mounts
from; it is separate from the data-only `Containerfile`, which ships skills
and templates as a mountable OCI artifact. Deployment configuration is
mounted at `TRAUST_CONFIG_HOME` (the image sets `/harness/deploy-config`),
never baked in.

An all-in-one image (both layers combined) is fine for local, non-air-gapped
use only — `traust-runtime`'s label says exactly that
(`summary: "Traust runtime on toolchain <hash>"`). The air-gap answer is
mirroring both images separately and copying the feeds cache across on a
cadence, so a pin advance and a code change can each ship on their own
schedule.

## 5. Storage locations

Where each kind of data lives is in [storage.md](storage.md). Runtime paths
resolve from `locations:` in `$TRAUST_CONFIG_HOME/traust.yaml` — the section in
`config/traust.example.yaml`; fill in the fields you use. There are no environment overrides for workspace, analysis-results,
progress-tracker, or feeds-cache.

How the lanes that execute a target repository's build/test code run is a
deployment setting, not an environment variable: `execution.sandbox` in
`$TRAUST_CONFIG_HOME/traust.yaml`, defaulting to `none`
(direct execution, scrubbed environment, disposable copy). Set it to
`podman` for a nested rootless container instead — see
[external-dependencies.md](external-dependencies.md) for the full contract.

Example for a mono-checkout:

```yaml
# $TRAUST_CONFIG_HOME/traust.yaml
locations:
  workspace: /path/to/workspace
  inputs: /path/to/workspace/inputs            # repository inventories (CSV)
  analysis_results: /path/to/workspace/analysis-results
  progress_tracker: /path/to/workspace/progress-tracker
  feeds_cache: /path/to/workspace/progress-tracker/feeds
```

### Bring your own inventory

`locations.inputs` points at the **repository inventory**: the list of
repositories the harness audits, graphs, and reports on. The harness ships no
inventory and no discovery for one — how you enumerate your repositories
(a forge API, a release manifest, a CMDB export) is yours. It only requires a
directory layout and a CSV shape, both deliberately small:

```
<inputs>/
  <segment>/                 # any name — a business unit, a product line, "adhoc"
    <group>/                 # one directory per org, team or engagement
      <anything>-repos.csv   # one row per repository
      owners.csv             # optional: who owns each repository
```

`*-repos.csv` needs one column the graph can read a repository URL from,
`URL` (or `GitHub URL`); the rest is optional context the dashboards carry
through:

```
Repository,URL,Host,Organization/Group,Repo Name,App/Sub-Service,Resource Type
example-org/api-server,https://github.com/example-org/api-server,GitHub,example-org,api-server,platform,service
```

`owners.csv` maps repositories to owning teams; `Repository` and `Owner Team`
are the columns the graph uses (`Manager` is carried through when present).
That layout is the `groups` kind, and it is what every segment is unless
an **inventory descriptor** at `<inputs>/inventory.yaml` says otherwise. The
descriptor declares what each segment *is*, so nothing in the harness keys on
a segment's name:

```yaml
segments:
  platform:  {kind: release-payload, label: Platform}   # <segment>-<version>-payload-repos.csv per release
  operators: {kind: catalog,         label: Operators}  # <segment>/<product>/<version>/*-payload-repos.csv
  services:  {kind: services,        label: Services}   # groups layout; rows may carry App/Sub-Service
```

Kinds are `groups` (default), `release-payload`, `catalog` and `services`;
their layouts are documented in the `traust.inventory` module docstring.
Declaration order is the segment priority the executive summary uses when a
repo ships in more than one segment. Start with one `groups` segment and one
group and add the descriptor only when you have a release payload or an
operator catalog to inventory (`/inventory-repositories` writes those).

Three ways to populate it:

- **`/add-inputs`** registers a repository or a whole GitHub/GitLab org in
  traust-core under a product (`traust portfolio onboard`) and imports owning
  teams from `org_teams:` (`traust portfolio import-owners`). It no longer
  writes this CSV tree; readers of the tree move to traust-core with their ports.
- **Export from your own source of truth** into the CSV shape above; a
  spreadsheet export is enough.
- **Keep the inventory in its own repository**, as this project does, so that
  ownership changes are reviewed and portfolio sync can tell when it moves.

Then register the *output* tree the audits write to with `/corpus-intake`.
Unset, `locations.inputs` defaults to
`<workspace>/inputs`.

### Remote results and graph

*Retired:* the engine's remote materialiser (`traust-engine[s3]`,
`HARNESS_REMOTE_CACHE`, `HARNESS_S3_*`, `HARNESS_STORAGE_OPTIONS`) went with the
portfolio graph it served. traust reads through traust-core, and object storage
is traust-core's `ObjectStore` (`traust.yaml` → `artifacts`). Was:

Findings do not have to be local. Set
`traust.yaml` → `locations.analysis_results` to a
bare path, a `file://` URI, or an object-store URI, which is how a scheduled
orchestrator run reaches them.

| Variable / field | Purpose |
|---|---|
| `traust.yaml` → `locations.analysis_results` | findings-side artifacts (SBOMs, extracted images, graphs) |
| `HARNESS_REMOTE_CACHE` | where remote artifacts materialise (default `~/.cache/traust-engine/remote`) |

A bare path or `file://` imports no backend and copies no file, so a
workstation acquires no dependency for a deployment feature. Remote needs an
extra:

```bash
pip install 'traust-engine[s3]'     # gs:// or az://: [remote] plus gcsfs or adlfs
# in traust.yaml, under locations:
#   analysis_results: s3://<bucket>/results
```

Remote artifacts are **fetched once per job, not streamed**: the graph is a
large SQLite file and one query issues thousands of small indexed reads, which
object stores cannot serve, so it is materialised to the cache and queried
locally. The cache keys on the store's ETag; an unchanged artifact costs one
metadata call.

**S3-compatible stores** (MinIO, Ceph RGW, OpenShift Data Foundation) speak the
S3 API at a private endpoint. Without an override, `s3://` resolves to AWS and
the failure looks like bad credentials rather than a wrong endpoint:

```bash
export HARNESS_S3_ENDPOINT_URL=https://minio.apps.example.com:9000
export HARNESS_S3_PATH_STYLE=true        # no wildcard DNS for virtual-host style
export HARNESS_S3_CA_BUNDLE=/etc/pki/tls/certs/cluster-ca.crt   # private CA
export HARNESS_S3_REGION=us-east-1       # some stores require any non-empty region
```

There is deliberately **no TLS-verification-off switch** — supply a CA bundle.
`HARNESS_STORAGE_OPTIONS` takes a JSON object merged over the derived options
for any backend kwarg not covered above.

**Encryption at rest is the bucket's job, and it is required.** The findings
store holds security findings, some under embargo. The harness does not set
encryption on each object it writes, so the bucket must enforce it:

- turn on default encryption with a managed key (SSE-KMS on AWS; the
  equivalent server-side encryption on MinIO, Ceph RGW or ODF; a
  customer-managed key on GCS or Azure)
- add a bucket policy that denies unencrypted `PutObject` requests, so a
  misconfigured client fails loudly instead of writing plaintext
- restrict the key's use to the harness's identity and the people who triage
  its findings

A local path needs the same protection from the disk it sits on.

### Security-feed cache

Cached vulnerability data (EPSS, CISA KEV, vendor CVE and VEX feeds) is a
mirror of third-party licensed data: a different provenance class from the
findings you author, with opposite retention and redistribution properties, so
it lives outside the findings tree and is never committed. `traust feeds fetch`
snapshots it into traust-core's store (`traust.yaml`):

```bash
python3 -m traust.cli feeds fetch --feed all
```

`traust.yaml` → `locations.feeds_cache` (**no default**) now holds only the
product-definitions registry (`traust feeds fetch-products`), when the
deployment configures one:

```yaml
# traust.yaml
locations:
  feeds_cache: /path/to/progress-tracker/feeds
```

## 6. Environment variables

```bash
cp .env.example .env
```

Only the variables for the skills you run are required. [`.env.example`](../.env.example)
lists them all with descriptions. Model routing is policy data, not an
environment variable: before batch work, read [model-routing.md](model-routing.md)
for how roles resolve to models (never hardcode IDs — gate A12) and how a batch
declares its spend.

## 7. Run the tests

```bash
.venv/bin/python -m pytest tests/
```

pytest is the only runner (a unittest discover run silently skips the
pytest-native share of the suite). When the environment has no operational
config, the suite points `TRAUST_CONFIG_HOME` at a checked-in template copy
and skips the live smokes. A clean run shows zero errors.

Ledger writes need a verified identity. The suite provisions an isolated local
identity by itself: no OIDC login is needed, and your
`~/.config/traust-ledger` is never read. See
[CONTRIBUTING.md → Ledger auth in tests](../CONTRIBUTING.md#ledger-auth-in-tests).

## 8. Validate and render a report

```bash
python3 -m traust.cli reporting validate path/to/report.json            # schema auto-detected from the filename
python3 -m traust.cli reporting validate path/to/report.json --schema schemas/v1/validation.schema.json
python3 -m traust.cli reporting validate path/to/report.json --strict   # additional warnings
python3 -m traust.cli reporting render   path/to/report.json            # writes report.md alongside
```

The path may be a directory of `.json` reports. Without `--schema`, the schema
is detected from the filename (`*-triage.json`, `*-vuln-findings.json`, and so
on); anything unrecognised validates against the security-audit schema.

## 9. Contributor gates

The repository ships its hooks; enable them once per clone:

```bash
git config core.hooksPath .githooks
```

| Hook | Runs | Blocks |
|---|---|---|
| pre-commit | python3 -m traust.cli check skill-alignment and python3 -m traust.cli check skill-security --quiet | a cross-skill contract or security-posture regression; a missing python3 or a deleted checker also blocks (fail closed) |
| pre-push | python3 -m traust.cli check docs-consistency and python3 -m traust.cli check content-licenses | docs that drifted from the tree (counts, dead paths, stale generated pages) or re-imported restrictively licensed content |

Bypass once, in an emergency, with `--no-verify`. The same gates run
server-side in CI against merge requests, from pinned target-branch copies a
merge request cannot edit away. The pre-commit hook also prints a read-only
hint when a newly committed skill is not linked from `~/.claude/skills/`
(`bin/link_skills.sh`); it never writes into `$HOME`.
