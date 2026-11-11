# Components — the repositories this harness is built from

The harness is **not one repository**. Its ecosystem includes six code components
plus three data repositories. This page maps current ownership and dependencies,
the migration toward shared core services, how commits are pinned, and **which
repo to change for a given fix**.

If you only want to install and run, [setup.md](setup.md) is enough.
Read this before changing a schema, an enum, the fingerprint recipe, or
anything under `traust_engine`, `traust_ledger`, or `traust_core`.

---

## 1. The stack

| Component | Lang | Responsibility |
|---|---|---|
| `traust` | Python | Security skills (`harnessing/`), prompts, slash commands, agent-facing CLIs (`src/traust/`), workflow policy, docs, and gates |
| [traust-core](https://github.com/traust-security/traust-core) | Python | In-process domain hub under `traust_core.v1`: models, repositories/persistence, finding identity and decisions, authenticated identity, services, configuration/context, artifact publishing and provider interfaces; individual doors and skill ports have differing implementation status |
| `traust-engine` | Python | Executors and deterministic tooling: scanner adapters, portfolio processing, reporting/rendering, validation, compliance, metrics and toolchain integration; not a second owner of domain state |
| `traust-ledger` | Python | Proof/integrity library: canonical event bytes, Merkle roots, stamping, signing and verification; core owns finding identity, decisions and persistence |
| `traust-contracts` | Python/data | Canonical artifact/config schemas, controlled vocabularies, shared bindings, and database DDL |
| `traust-sdk` | Go | Typed access to contracts, storage, ledger integration, and skill execution for non-Python consumers |

### Current dependencies

The harness declares direct dependencies on **`traust-core` and
`traust-engine`**. Engine also depends on core. Core selects the contracts and
ledger revisions used by these consumers: contracts supplies canonical shapes,
vocabularies and DDL; ledger supplies proof/integrity primitives.

The installed manifests and lockfiles define runtime behavior. A sibling checkout
alone does not change the selected revision or make an unfinished service door
available.

**`traust-sdk` is not a dependency of the harness.** It is a sibling consumer:
its generator pins contracts, and its APIs integrate with storage, the ledger,
and skill execution. Nothing in this repository imports it.

### Core migration boundary

Contracts defines canonical data shapes and database structure. **Core is the
domain owner**, not a future optional layer: finding identity, decision admission,
authenticated principals and persistence belong there. Engine provides executors;
security workflow policy remains in `traust`.

The app's composition root is `src/traust/context.py`. It loads core's
`Context` once, in process, through `load(config_home)`, with every provider
registered (the engine's executors load on first use); domain work goes through
`load(config_home).services()`. A Python caller does not
need a REST service or a legacy ledger client/login to record a decision.

Ownership does **not** imply every door or skill port is implemented. Countersign
now supports pending cards, review requests, single/bulk apply and direct human
validity/severity/resolution judgements; triage's core record port also exists.
Validation/verification ingestion and cumulative/projection skill ports remain
separate work, with no legacy fallback. See the [CLI reference](cli-reference.md#direct-human-severity-recording)
and core's [implementation status](https://github.com/traust-security/traust-core)
before wiring a caller. Do not create a second domain implementation or claim
that a stub is an available integration. The core REST route for non-Python
consumers remains planned; it is not required by the in-process Python app.

### Data repositories (not components)

`setup.md` also uses the word "sibling" for these, in a different sense — its
clone list is four entries because it counts `traust` itself. They
hold content, not code, are not pip dependencies, and are referenced by relative
path, not imported:

| Repo | Holds |
|---|---|
| `analysis-results` | Audit reports, disposition ledgers, triage, threat models — the corpus |
| `<inputs-inventory>` (name is the deployment's) | Scope declarations, repo rosters, service inventories |
| `progress-tracker` | Plans, dashboards, metrics, gap assessments |

---

## 2. Which repo do I change?

The most common mistake is editing the wrong layer — usually adding a schema
field to the harness, where it has no effect, because the validator loads
schemas from the **installed contracts package** (`traust_contracts`),
not from this repo.

| I want to… | Repo | Note |
|---|---|---|
| Add or edit a skill, prompt, slash command, or security workflow policy | `traust` | Keep shared domain behavior out of pack policy |
| Change shared platform models, persistence, authenticated identity or decision admission | `traust-core` | Use core services through the app composition root; check the specific door's implementation status |
| Add a field to an artifact schema | `traust-contracts` | Update affected producers and consumers before advancing their pins (§4) |
| Add an enum value | `traust-contracts` | Update canonical definitions and bindings using that repo's checks |
| Change the database structure | `traust-contracts` | Coordinate core repositories and existing SQL consumers with the selected DDL revision |
| Change the finding fingerprint or version attribution | `traust-core` (`services/findings/identity.py`) | One `IdentityPolicy` implementation; update `ALGO_VERSION` and its regression coverage (§5) |
| Change Merkle/stamping/signing behavior | `traust-ledger` (`integrity/`) | Proof primitives only; core owns persisted decisions and ledger-service orchestration |
| Add or fix a scanner executor/adapter | `traust-engine` (`adapters/`) | Adapter results must satisfy the installed contracts schema; domain admission stays in core |
| Change dashboard/corpus domain queries or derived-state policy | `traust-core` | Assessment/finding/insight services own the domain; engine owns remaining execution/rendering, and retired builders are not fallback APIs |
| Change what a Go consumer sees | `traust-sdk` | Also update contracts when the data shape changes; do not assume the planned core REST route exists |

---

## 3. Version pinning

The harness selects **core and engine** git commits with `rev` in
`[tool.uv.sources]`; `dependencies` names those packages and `uv.lock` records
the resolved graph. Engine selects core in its own manifest. Core, in turn,
selects contracts and the ledger proof library; the harness and engine do
not independently pin contracts or ledger.

Pins belong only in the owning manifests, not copied SHAs or dependency
snippets in documentation:

- [Harness manifest](../pyproject.toml): direct core and engine dependencies.
- [Engine manifest](https://github.com/traust-security/traust-engine/blob/development/pyproject.toml): its core dependency.
- [Core manifest](https://github.com/traust-security/traust-core/blob/development/pyproject.toml): contracts and ledger dependencies.

The harness and its selected engine **must resolve the same core revision**.
A sibling checkout or a newer tag does not change that installed selection.

### Source conflicts and compatibility

Inconsistent Git URLs or revision specifications for the same dependency can
make `uv lock` report **"conflicting URLs"**. In particular, advancing the
harness's core pin while its selected engine still pins a different core
revision causes a resolver conflict. Update engine's core selection and then
the harness's engine/core selections together so they agree; do not bypass
the conflict with independent contracts/ledger pins in the app.

A successful resolution is not proof of runtime compatibility. Schema layouts,
DDL, and APIs can change between commits; exercise affected consumers before
advancing pins. Adopting core requires working caller migrations, not merely
adding a package or changing the contracts revision.

`uv sync --locked` refuses installed dependency drift; `uv sync` restores the
dependency set selected by this project's manifest and lockfile. Read the
current sources in `pyproject.toml` and resolved commits in `uv.lock`; a sibling
checkout or its latest tag is not the installed version.

---

## 4. Release order

Update providers before their consumers, following the actual dependency graph
rather than a fixed release chain:

- Contracts or proof-library change: update the owning contracts/ledger
  repository first, then core's selected dependency and affected services.
- Core change: update engine's core selection as needed, then select that
  engine and the same core revision in the harness. Contracts and ledger
  arrive through core, not separate harness pins.
- Go path: regenerate SDK bindings and storage code against its selected
  contracts commit when those contracts change.

For an affected Python component:

1. Implement and test the change in the owning repository.
2. Merge it, then update each affected consumer's manifest to the tested commit.
3. Run `uv lock` and `uv sync`, exercise the affected runtime path, and run that
   consumer's checks before merging its pin update.
4. Continue outward until every affected consumer has been updated.

Follow each repository's own release instructions; no tagged release is
required merely to select a merged dependency commit. This dependency workflow
does not change the harness's `VERSION`/semantic-version convention or the Go
SDK's per-language release tags. Core's evolving `traust_core.v1` namespace is
an API boundary, not a package release number or a promise that all services
are implemented.

Do not change dependency pins in a documentation-only edit. A service cutover
must also migrate callers, configuration and persistence where needed; the
planned REST API is not a substitute for the implemented in-process integration.

---

## 5. What crosses the boundary

Contracts defines the shared data. The selected revision determines the
physical schema and DDL layout; paths from another revision are not an API.

| Contract | Defined in | Consumed by |
|---|---|---|
| **Artifact and config schemas** | Installed `traust-contracts` schema resources | Existing Python validators, core's contracts reader, and generated SDK types/validators |
| **Enums** | Contracts' canonical enum registry and bindings | Python components and generated SDK enums |
| **Database DDL** | Contracts' authored SQL for its selected data model | Core repositories and existing SQL consumers compatible with that revision |

Update canonical definitions and regenerate or update bindings according to the
contracts repository's checks. Core supplies access and behavior; neither core
nor the harness should create a second source of truth for schemas or DDL.

### Finding identity is deliberately *not* a cross-boundary contract

**The current finding-identity recipe is owned by core.** Reuse
`traust_core.v1.services.findings.identity.IdentityPolicy`; do not implement a
second recipe in the app, engine, ledger, Go SDK or a producer. The implementation
lives in `traust_core/v1/services/findings/identity.py` and includes version
attribution for historical stamps. A deliberate recipe change updates
`ALGO_VERSION` and core's regression coverage rather than silently restamping
existing findings.

Historical ledger fixture vectors and prose describe the earlier owner; they
are not an independent current identity contract. Contracts owns shared shapes
and vocabularies, not a second fingerprint implementation. Core finding intake
and decisions own admission and persistence. The countersign workbench
requires an existing core finding **UUID**: a fingerprint or legacy scan-scoped
ID is not a substitute. A current implementation of the recipe does not imply
that identity-move, rebaseline or every finding-intake skill port is complete.

---

## See also

- [setup.md](setup.md) — cloning the workspace and `uv sync`
- [traust-core](https://github.com/traust-security/traust-core) — platform API, implementation status, and core-specific development instructions
- [architecture.md](architecture.md) — code internals within a component
- [disposition-ledger.md](disposition-ledger.md) — what `traust-ledger` is protecting
- [signing.md](signing.md) — ledger signing
