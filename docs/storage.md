# Storage — where each kind of data lives

The harness keeps five kinds of data, each with its own home. The split is
deliberate: what must be tamper-evident stays under version control, what is
bulky or regenerable may live elsewhere, and what describes one deployment
never enters a repository that ships.

The harness expects a **workspace**: a parent directory holding the harness
checkout beside two data repositories — a **findings store** (scan and
assessment results plus the ledgers) and a **metrics tree** (roll-ups and
dashboards). In a typical mono-checkout they are named `analysis-results` and
`progress-tracker`; a deployment may call them anything. Set the paths in
`$TRAUST_CONFIG_HOME/locations.yaml` (copy from
`config/locations.example.yaml`).

| Data | Where it lives | Configured by | Notes |
|---|---|---|---|
| **Disposition ledgers** (`*-findings-layer.json`) | the findings store, under version control | `locations.yaml` → `analysis_results` (local path) | The record of truth. Append-only, Merkle-stamped, signed. The integrity chain is built on immutable files and their history, so ledgers stay in a repository. |
| **Scan and assessment results** (baselines, triage, validation, verification, threat models, per-target inventories) | the findings store: a local checkout **or** object storage | `locations.yaml` → `analysis_results` (path, `file://`, `s3://`, `gs://`, `az://`); `HARNESS_STORAGE_OPTIONS` (JSON) for private S3-compatible endpoints | Each ledger records the sha256 of the report it annotates and of every sibling artifact, inside its signature, so a copy is verifiable wherever it is stored. Remote artifacts materialise into `HARNESS_REMOTE_CACHE` (default `~/.cache/traust-engine/remote`). |
| **Roll-ups, dashboards, metrics ledgers** | the metrics tree | `locations.yaml` → `progress_tracker` | Aggregates only, never per-target detail (the rollups-only discipline in [artifacts.md](artifacts.md)). |
| **Projections and caches** — `findings.db`, the portfolio graph, the security-feed cache, remote materialisations | beside the findings store, or remote | `locations.yaml` → `portfolio_graph` (defaults to `<analysis_results>/graph/portfolio-graph.db`); `locations.yaml` → `feeds_cache` (**no default** — unset, feed fetch fails closed); `HARNESS_REMOTE_CACHE` | Regenerable. Deleting any of them loses nothing; the drift checker reports when one is stale. `findings.db` is never a write target. |
| **Operational configuration** (corpus registry, product map, budget policy, safe-exec profiles, allowlists, weights, vocabulary, signing public key) | the deployment's private config directory | `TRAUST_CONFIG_HOME` (default `~/.traust/config`) | Never in a shipping repository; this repo holds templates only. See [config/README.md](../config/README.md). The signing **private** key lives in the deployment's secret store, referenced by `LAAS_SIGNING_KEY_PATH`. |

Two rules follow from the table:

- **The ledger and the report it annotates may live apart.** The layer joins to
  its report by content hash, not by path, so moving reports to object storage
  changes where bytes are fetched from and nothing about what a verifier can
  check. A ledger never leaves version control.
- **Location is configuration, not code.** Every path above is read from
  `$TRAUST_CONFIG_HOME/locations.yaml` via `traust_engine.locations`; there are
  no environment overrides for workspace, analysis-results, progress-tracker,
  or feeds-cache. A skill that hard-codes a location fails the alignment gate.
  Where a field is unset the code returns nothing rather than guessing, so a
  misconfigured job fails instead of writing a stray tree.

Remote storage options (S3-compatible endpoints, cache directory): [setup.md](setup.md).
