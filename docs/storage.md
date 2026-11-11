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
`locations:` in `$TRAUST_CONFIG_HOME/traust.yaml` (template:
`config/traust.example.yaml`).

| Data | Where it lives | Configured by | Notes |
|---|---|---|---|
| **Disposition ledgers** (`*-findings-layer.json`) | the findings store, under version control — **or** the Ledger database | `traust.yaml` → `locations.analysis_results` (local path); `traust.yaml` → `database.url` (the record store) | The record of truth. Append-only, Merkle-stamped, signed. The ledger's dsn (`ledger.yaml`) is retired: ledger layers are contract tables in the record store. Signing and token verification are `traust.yaml`'s `ledger:` and `identity:` sections. |
| **Scan and assessment results** (baselines, triage, validation, verification, threat models, per-target inventories) | the findings store: a local checkout **or** object storage | `traust.yaml` → `locations.analysis_results` (path, `file://`, `s3://`, `gs://`, `az://`); `HARNESS_STORAGE_OPTIONS` (JSON) for private S3-compatible endpoints (*retired* with the engine's remote materialiser; object storage is traust-core's `ObjectStore`) | Each ledger records the sha256 of the report it annotates and of every sibling artifact, inside its signature, so a copy is verifiable wherever it is stored. Remote artifacts materialise into `HARNESS_REMOTE_CACHE` (*retired*, as above). |
| **Roll-ups, dashboards, metrics ledgers** | the metrics tree | `traust.yaml` → `locations.progress_tracker` | Aggregates only, never per-target detail (the rollups-only discipline in [artifacts.md](artifacts.md)). |
| **Projections and caches** — `findings.db`, the product-definitions cache, remote materialisations | beside the findings store, or remote | `traust.yaml` → `locations.feeds_cache` (**no default** — unset, `feeds fetch-products` fails closed; the security feeds are traust-core snapshots); `HARNESS_REMOTE_CACHE` (*retired*) | Regenerable. Deleting any of them loses nothing. `findings.db` is never a write target. |
| **Operational configuration** (`traust.yaml`: database, identity, ledger keys, budgets, locations; the model registry, product map, vocabulary) | the deployment's private config directory | `TRAUST_CONFIG_HOME` (default `~/.traust/config`) | Never in a shipping repository; this repo holds templates only. See [config/README.md](../config/README.md). The signing **private** key lives in the deployment's secret store, referenced by `traust.yaml` → `ledger.key_path`. |

Two rules follow from the table:

- **The ledger and the report it annotates may live apart.** The layer joins to
  its report by content hash, not by path, so moving reports to object storage
  changes where bytes are fetched from and nothing about what a verifier can
  check. A ledger never leaves version control.
- **Location is configuration, not code.** Every path above is read from
  `locations:` in `$TRAUST_CONFIG_HOME/traust.yaml` via traust-core's `Locations`; there are
  no environment overrides for workspace, analysis-results, progress-tracker,
  or feeds-cache. A skill that hard-codes a location fails the alignment gate.
  Where a field is unset the code returns nothing rather than guessing, so a
  misconfigured job fails instead of writing a stray tree.

Remote storage options (S3-compatible endpoints, cache directory): [setup.md](setup.md).
