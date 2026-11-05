# `config/` — one config file: copy, fill in, run `traust admin doctor`

```bash
scripts/install_traust            # copies traust.example.yaml to $TRAUST_CONFIG_HOME/traust.yaml
                                  # (plus the shipped model-registry.yaml)
$EDITOR "$TRAUST_CONFIG_HOME/traust.yaml"   # uncomment and fill in what you use
traust admin doctor               # every effective value and its source: file, env or default
```

An adopter sets **one file, `traust.yaml`**, in the directory named by
`TRAUST_CONFIG_HOME` (default `~/.traust/config`): the database, identity, the ledger
key, budgets, forge hosts, locations, and four small adopter fields (`feeds.osv_access`,
`execution.sandbox`, `remediation`, `campaign`). Secrets come from the environment: the
`*_env` keys name the variable. No `traust.yaml` at all is the zero-config local install
(SQLite and artifacts under `~/.traust`). The schema is traust-contracts' `traust`
(`config/v1/traust.schema.json`); unknown keys are refused. A deployment such as SCI sets
the same file as Helm values and its secrets from a secrets manager.

Local artifact bytes default to `<home>/artifacts`; set `artifacts.path` for a different
local directory. For shared artifact storage, install `traust[s3]` and set `artifacts.s3.bucket` in
`traust.yaml` (see `traust.example.yaml`); `prefix`, `region` and `endpoint_url` are
optional deployment settings. Omit `access_key_env`/`secret_key_env` to use the SDK
credential chain (including workload identity), or set **both** to names of environment
variables from a secrets manager. S3-compatible endpoints include MinIO and Ceph.
The role needs Get/Put on its keys and prefix-scoped ListBucket; access errors are not
cache misses. `artifacts.path` and `artifacts.s3` are mutually exclusive. Switching an
existing deployment from local files requires copying its artifact bytes to the same
keys before changing the config; the configuration switch does not migrate them.
`locations.analysis_results` is a legacy results location, not this artifact store.

## What ships here

| File | What it is |
|---|---|
| `traust.example.yaml` | the template for `traust.yaml`: every section, documented, commented out except the defaults. As copied it is the zero-config install |
| `model-registry.yaml` | model tier classes, routing roles and prices; read from the config home, where `install_traust` copies it ([procedure](../docs/model-classes.md#configuring-your-own-models)) |
| `rule-pack-allowlist.example.yaml` | the calibrated supplemental rule allowlist; enable it with `overrides.rule_pack_allowlist` (shipped default: no supplements) |

## Adopter facts: record them

Facts about your organization are not config files: keep the source files in your own
repository and record them into traust-core, where each recording is the next version and the
newest one is used.

| Fact | Record it with | Example |
|---|---|---|
| org parameters | `traust compliance policy org-parameters <file>` | [docs/examples/org-parameters.example.yaml](../docs/examples/org-parameters.example.yaml) |
| ADR registers | `traust compliance policy adr-registry <file>` | [docs/examples/adr-registry.example.yaml](../docs/examples/adr-registry.example.yaml) |
| recall-benchmark answer key | `traust sweep benchmark-targets <file>` | [docs/examples/benchmark-targets.example.yaml](../docs/examples/benchmark-targets.example.yaml) |
| the reviewed package/repo → product map | `traust registry product-map <file>` | [docs/examples/product-definitions-map.example.yaml](../docs/examples/product-definitions-map.example.yaml) |
| a changed SLA policy | `traust dashboard sla-policy <file>` | the security pack's default, [packs/security/sla-policy.yaml](../packs/security/sla-policy.yaml) ([docs/sla-policy.md](../docs/sla-policy.md)) |

The public-export inputs (the scrub's organization vocabulary) are not runtime config either:
see [tools/public-export/](../tools/public-export/README.md).

Which repositories are the estate's PQC chokepoints is the deployment's own list, never this
tree's, and it isn't a config-home file either: it's an adopter fact, to be recorded into core
once core has a home for it. Until then the caller names them per run with
`traust pqc worklist|sweep --chokepoint <URL fragment>` (repeatable; the deployment's
orchestrator passes its list). Without one, every repository ranks in the crypto-CWE and tail
tiers, and the command says so on stderr.

## What ships with traust-core instead (not configurable)

Tool pins (`external-tools.yaml`), the base safe-exec profiles (`safe-exec-profiles.yaml`)
and the feeds registry (`feeds.yaml`) are the project's opinions: they ship as traust-core
package data (`traust_core.v1.context.config.SHIPPED_*`) and `traust.context.load()`
registers them. The only override is `overrides.rule_pack_allowlist`. Build scripts that
need the pins (`scripts/containerfile-build-args.py`, `scripts/install-toolchain.sh`) read
the installed package's copy.

## From an old config home

Before `traust.yaml` a config home held up to 25 files. `traust config migrate <old home>`
writes one `traust.yaml` from `core.yaml`, `locations.yaml` (inline as `locations:`),
`ledger.yaml` and `ledger-signing-key.pub` (`ledger:`), `budget-policy.yaml` (`budgets`),
`execution-boundaries.yaml` (`execution.sandbox`), `remediation.yaml`, `campaign.yaml`,
`rule-pack-allowlist.yaml` (`overrides.rule_pack_allowlist`) and an old `feeds.yaml`'s osv
`access: air-gapped` (`feeds.osv_access`). It reports every file: carried, dropped (an old
`external-tools.yaml`, `safe-exec-profiles.yaml` or `feeds.yaml` is never carried, and it
says when one differs from the shipped copy), an adopter fact with the command to record
it, kept, or moved elsewhere. `corpus-config.yaml`, `storage.yaml` and
`hardening-risk-weights.json` are retired (no readers).

## Hygiene gate

`python3 -m traust.cli check docs-consistency` fails when this directory contains anything
other than the files listed under *What ships here* and this README, or when any file here
carries estate-specific markers.
