# Changelog

All notable changes to Traust are documented here.

## [0.34.0]

- **Manifests without a lockfile are resolved through deps.dev, on by
  default** (owner decisions 2026-10-20 option c and 2026-10-21). Pins
  traust-engine 0.36.0 (683552d, which includes 0.35.1).
  - `traust adapters osv --repo` resolves the transitive tree of every
    `package.json`, `requirements*.txt`, `pom.xml` and `Cargo.toml`
    without a lockfile, and resolves declarations with no version at
    deps.dev's default. The added candidates carry `version_basis:
    resolved` / `resolved-default` and `resolved_via`. What can't be
    resolved stays in `unresolved_manifests` with a reason.
  - **Opt out** with `access: disabled` on the new `deps_dev` source in
    `feeds.yaml` (also a new `ACCESS_MODES` value). A config home without
    the source prints a NOTE and doesn't resolve.
  - **Terms and attribution documented** in `config/feeds.yaml`,
    `docs/external-dependencies.md` (the Google APIs Terms of Service
    obligations on the operator, CC BY 4.0 for the resolved data, and the
    attribution text) and `docs/setup.md`. Every scan carries the
    attribution in `metadata.resolution.attribution`.
  - `/secure-code-audit` and `/vuln-scan`: resolved candidates are an
    approximation and are never promoted on their own.

## [0.33.0]

- **Container audits: grype reads syft JSON, and OSV adds language-package
  advisories** (owner decisions 2026-10-20, option b plus fixes A and B).
  Pins traust-engine 0.35.0 (f9259ad).
  - **Fixed: grype ran on CycloneDX**, which drops syft's record of which
    OS package installed each file. grype then matched upstream advisories
    against language packages an RPM installed, which carry Red Hat
    backports. On `ubi9/python-311` that added 31 likely false positives
    (13 High). `/secure-container-audit` Phase 2 now writes syft JSON and
    CycloneDX in one syft run; Phase 3 runs grype on the syft JSON. The
    CycloneDX file still feeds the portfolio graph.
  - **`traust adapters osv --sbom <syft.json> [--grype <grype.json>]`**
    looks up the image's language packages that no OS package installed,
    through the OSV API (osv-scanner offline when air-gapped). It tags
    `also_in_grype` and reports `grype_dedupe` counts, with the same
    `complete` / `degraded` (exit 3) / `failed` (exit 2) statuses.
    CycloneDX input is refused (exit 2).
  - **grype's own matches on OS-installed language packages are listed**
    (`grype_os_installed`, with the owning packages). Even from syft JSON,
    grype reported 26 of them on `ubi9/python-311` (1 critical, 12 high,
    mostly npm packages the nodejs RPM ships). The skill records them as
    `installed by <owner>` and never promotes one on the upstream advisory
    alone.
  - `/secure-container-audit` Phase 3: grype stays primary. Only
    `also_in_grype: false` candidates become new `dependency_audit`
    entries; failures are a coverage gap under `osv-scanner`. A language
    package an RPM installed is judged by the RPM's RHSA state.

## [0.32.1]

- **The dependency pre-scan's report key is `osv-scanner` again.** 0.31.0
  renamed it to `osv` in `/secure-code-audit` and `/vuln-scan` (the
  `deterministic_steps` key and the `coverage_gaps` tool), out of step with
  the report schema's description, `docs/report-structure.md` and every
  earlier report. The key names the step, not the path: it stays
  `osv-scanner` whether the OSV API or, air-gapped, the binary ran. No
  report on record used `osv`.

## [0.32.0]

- **osv-scanner leaves the default install** (scanner-currency step 6,
  owner decisions 2026-10-20). OSV is queried through its API; air-gapped
  deployments provide osv-scanner and its offline database themselves.
  Pins traust-engine 0.34.0, which no longer fetches or tracks that
  database.
  - `install-toolchain.sh`: osv-scanner is in no profile and is no longer
    downloaded; `setup` no longer populates its database.
  - `Containerfile.toolchain` and `containerfile-build-args.py`: no
    osv-scanner binary, build arg or database. An air-gapped deployment
    extends the image.
  - **The pin stays, as the tested version for air-gapped adopters**:
    `config/external-tools.yaml` marks the row `provided_by: adopter` with
    `consumers: []`, and advances `expected` 2.4.0 → 2.7.0 (the latest
    release; the air-gapped smoke in 0.31.0 ran 2.7.0). When osv-scanner
    is absent, the `external-tools:osv-scanner` drift row compares the pin
    itself with upstream (`fresh` / `stale`) instead of reporting
    `pending`; when it is installed, the usual checks apply.
  - Docs: `docs/setup.md` (install table, container image, air-gapped
    steps) and `PROCESS.md`.

## [0.31.0]

- **OSV through the API; osv-scanner is no longer needed for dependency
  scans** (owner decision 2026-10-20, agreed with Shaun). Pins traust-engine
  0.33.0, whose `osv` adapter reads lockfiles and manifests and queries the
  OSV API through one shared client.
  - **`traust adapters osv`** uses the API by default. Output is
    `<repo>-osv.json`, artifact `osv-dependency-candidates`, with lookup
    provenance in `metadata`.
    - Exit 3 when the scan is `degraded`, meaning some lookups went
      unanswered or some manifests didn't parse.
    - **Exit 2 and `status: failed`** when OSV can't be used at all: one
      probe lookup fails before the scan (no retrying every batch), or no
      package is answered. An `ERROR:` line names the endpoint and the
      reason; the artifact is still written, with a `failure` block and no
      candidates.
    - A note when `transitive_coverage` is `partial` (manifests with no
      lockfile, or a pinned requirements file that wasn't compiled).
- **Air-gapped OSV scanning is a configuration option; the API is the
  default.** New `access` setting on the `osv` source in `feeds.yaml`:
  `api` (default) or `air-gapped`. Air-gapped, `traust adapters osv` runs
  osv-scanner offline against a local OSV database. The adopter provides
  the binary and the database; the harness installs neither and does not
  keep them current. A missing binary or database is `failed`, exit 2. The
  fleet sweep needs the API and writes a `failed` worklist (exit 2) in that
  mode. Documented in `config/feeds.yaml`, `docs/setup.md` ("Air-gapped OSV
  scanning"), `docs/external-dependencies.md`, `docs/requirements.md`,
  `docs/getting-started.md` and `config/README.md`. `--source` overrides
  the setting for one run.
  - **`fleet_sweep`** runs on the shared client. Before, three failed calls
    became "no vulnerabilities", page tokens were ignored, and failed detail
    fetches were dropped. Unanswered pairs are now counted and listed
    (`pairs_unanswered`, `unanswered_pairs`), and a degraded sweep exits 3.
    A sweep where OSV can't be used at all (failed probe, nothing
    answered, or `access: air-gapped`) is `failed` and exits 2.
  - **`resolve-advisory-symbols`** runs on the shared client. A failed alias
    fetch no longer turns into a false "no fix commit".
- **No inference in place of data** (scanner-currency workstream 10, shipped
  ahead per redesign D8).
  - `/secure-code-audit`'s dependency review: a skipped or degraded scanner
    is a coverage gap and no dependency conclusion either way. A manual
    review enumerates packages but never names CVEs from memory.
  - `/impact-analysis`: vulnerable ranges and fixed versions come from a
    fetched advisory, never from recall.
  - `/secure-container-audit`, `/secure-rpm-audit`, `/dependency-watch`
    and `/vuln-scan` carry the same rules.
  - The skills' tool permissions now match the commands they run, including
    `syft` and `grype` for `/secure-code-audit`.

## [0.30.0]

- **Nothing reads `progress-tracker/configs/` any more** (owner decision,
  2026-10-17). Deployment config lives in the config home
  (`TRAUST_CONFIG_HOME`), with a template here in `config/`.
  - **New templates:** `sla-policy`, `org-parameters`, `adr-registry`,
    `reachability-watch` and `benchmark-targets` (`*.example.yaml`), each
    schema-valid and estate-neutral. `install_traust` does not copy them
    into a new config home, because their placeholder values would be
    reported as if someone had declared them.
  - **`/drift-watch`** reads `adr-registry.yaml`, `sla-policy.yaml`,
    `org-parameters.yaml` and `reachability-watch.yaml` from the config
    home, and the framework provenance and catalogs from traust-engine.
    Before this, the path was built three different ways in one file.
  - **`/compliance-check`** takes the control-to-check mapping from
    traust-engine (`--registry` still overrides), org parameters from the
    config home, and the scope registry from the engine's
    `compliance.scope_registry()`.
  - **`traust ops index-adrs`** defaults to the config home's
    `adr-registry.yaml`.
  - **`/recall-benchmark`** documents the answer key at
    `$TRAUST_CONFIG_HOME/benchmark-targets.yaml` and the fixture sources at
    `$TRAUST_CONFIG_HOME/recall-benchmark/{canaries,seeded}/`.
  - **`/sla-view`** uses the config home's `sla-policy.yaml`; with none
    there, it fails and names the template.
- **Synthetic compliance fixtures moved into `tests/fixtures/compliance/`**
  (the per-check good and bad snapshots, and the efficacy seeded target). The
  compliance tests used to skip whenever progress-tracker wasn't checked out;
  they now always run. `traust ops score-compliance-efficacy` defaults to the
  in-repo seeded target.
- **The calibration test ran zero times.** `test_compliance_phase4.py`
  looked for `iac-inventory-calibration.json`, but the snapshot is
  `iac-inventory-app-interface-mirror.json`, and its module-level skip also
  hid every other test in the file. It now looks in the operator config
  home under `compliance/calibration/`, and only the two idempotence tests
  skip when the snapshot is absent.
- **Recall-benchmark fixture pins are reproducible again.** `build_canaries.py`
  committed with the builder's git config, so a builder that signs commits
  got a new SHA every run (the signature carries a timestamp). The fixture
  commit is now never signed.
- **Pins** traust-engine 0.31.0.

## [0.29.0]

- **Deprioritized threats carry review-surface tags.** traust-contracts
  0.60.0 lets a section 5 row carry `review_surfaces`, and traust-engine
  0.30.0 renders and lints it.
  - `/threat-model` bootstrap tags the section 5 row it writes when a check
    on a tagged surface turns up nothing, so the model records that the
    surface was checked and the threat set aside.
  - `/secure-code-audit`'s threat-model coverage diff counts those tags
    with the entry-point and threat tags: each must end the audit as
    `finding`, `negative` or `not_assessed`.
- **The vuln-findings schema enforces the full-scan rule.** A record that
  answers any review surface `out_of_scope` must carry
  `metadata.additional.coverage_diff`. The engine validator already
  checked this; now the schema does too, for every consumer.
- **Pins** traust-contracts 0.60.0, traust-ledger 0.11.3 and traust-engine
  0.30.0.

## [0.28.1]

- **The docs gate no longer checks the old GitLab group page.**
  `check docs-consistency` used to read `../gitlab-profile/README.md` when
  it sat next to the harness checkout, and failed when that page's
  version or skill count disagreed with this repo. Traust lives on GitHub
  now, so a stale GitLab page could fail the harness's tests and force a
  GitLab change for a GitHub release. The check, its tests and the
  `check-harness-docs` sections that described it are removed.

## [0.28.0]

- **Pins traust-engine 0.29.0.** The rendered threat-model Markdown now
  shows `review_surfaces`: sections 3 and 4 gain a trailing column when
  any row is tagged. The linter checks the tags against the enum, and the
  corpus parser reads them back.
- **threat-model bootstrap emits JSON, then renders.** Stage 5 used to
  assemble `_model.md` by hand and gate on `reporting lint`. It now
  composes `<repo>-threat-model.json` per SKILL.md Step 2 and runs
  `rate-threats`, then `validate`, then `render`, so a bootstrap model
  follows the same JSON-first path as every other model. The provenance
  block no longer carries `owner`.
- **`traust admin checkpoint reset` leaves an empty state dir.** It used
  to delete the dir, so a step that wrote into it before the first
  `save` (a pre-scan seed, for example) failed on a missing directory.
- **vuln-scan and verify-remediation record tools where the schema has
  room.** Vuln-findings metadata has no `tools` field, so vuln-scan
  records whether the k8s-hardening step ran in
  `metadata.additional.deterministic_steps`. verify-remediation puts
  scanner versions in `metadata.additional.tools`.

## [0.27.2]

- **Pins traust-engine 0.28.0** (rule pack v1.9).
  - The LIKE-wildcard rule catches a bound f-string parameter such as
    `(f"{owner}/{folder}/%",)`.
  - SSRF taint follows `request.get_json()` and friends, and stops at a
    database fetch.
  - The new `traust-python-ssrf-stored-url` flags an outbound call to a URL
    read from a database row or model field.
  - A default `traust adapters opengrep` run now finds both planted defects
    the `team-notes` recall fixture's audit run missed.

## [0.27.1]

- **The config-matrix redacts credentials in every tier, not just Python
  settings.** A secure-code-audit run on the `team-notes` recall fixture
  found the pre-scan copying a hardcoded `TOKEN_SIGNING_KEY` verbatim into
  its artifact.
  - Redaction moved into the shared triple builder, so Helm, Kustomize,
    Compose, Kubernetes env and env-chain defaults are covered too. The
    env-chain tier's sink expression, which quotes the source line, is
    redacted as well.
  - Names that count as credentials:
    - any secret-class name, now also including `signing_key`,
      `encryption_key`, `hmac_key` and `salt`
    - any name whose last segment ends in key, token, salt, secret or
      password at a word boundary (`SIGNING_KEY`, `apiToken`,
      `session-secret`), but not `public_key`, `primary_key`,
      `sort_key` and similar
    - templated values (`${X}`, `{{ … }}`) are not literals and stay as
      they are
  - A redacted default is reported as `<hardcoded literal, N chars>`, marked
    `literal_redacted`, and judged as a weak default.
  - Verification toggles with words between the parts now count, for
    example `VERIFY_WEBHOOK_SIGNATURES`.
  - On five real estate repos, no triple was lost and none was
    reclassified. 15 credential defaults were newly redacted, from env
    fallbacks, Compose and Kubernetes env. None of the redacted values
    appears anywhere in the new output.

## [0.27.0]

- **`/recall-benchmark` supports seeded fixtures.** `build_canaries.py` now
  accepts a `seed.yaml` answer key beside the existing `canary.yaml`: a
  synthetic app with one expected finding per planted defect and no
  `injection` block, registered as a `bt-seeded-<name>` target. Seeded
  fixtures live in `progress-tracker/configs/benchmark-seeded/`, apart from
  the canaries, so adding one leaves the canaries' entries untouched.
  - The builder refuses a source with both answer keys, or with an answer
    key anywhere inside `tree/` (it used to check only `tree/canary.yaml`).
  - Seeded fixtures are always development split: their author has read the
    answer key.
  - The manifest is now written with `allow_unicode`, so a rebuild no longer
    re-escapes every non-ASCII character in existing entries.
  - Materializing skips `__pycache__/` and `*.pyc`, so a target's SHA depends
    only on committed content, not on who last ran Python over the source.
  - The skill documents seeded fixtures: one defect per file (matching is by
    path and CWE), and nothing in `tree/` may hint at the answers.

## [0.26.0]

- **The config-matrix pre-scan expands Python settings** (new
  `python-settings` tier in `expand_config_matrix.py`).
  - **What it reads:** literals in settings modules (`settings*.py`,
    `config*.py`, `conf.py`, `configuration*.py`) and in settings classes
    (names ending `Settings`, `Config` or `Configuration`, or extending
    pydantic's `BaseSettings`). Files are parsed with `ast`, never imported
    or run. Test files, `conftest.py` and test directories are skipped.
  - **Sinks:** each triple's sink lists the setting's readers
    (`settings.X`, `config.X`, `app.config["X"]`, `config.get("X")`,
    `getattr(settings, "X")`), so the judge can rate a flag by its worst
    reader.
  - **Classification:** by the setting's name, so module-path values such
    as `rbac.urls` no longer read as auth. A value marks only a DSN or a
    bind-all address (`0.0.0.0`). Test toggles (`TESTING`), CSRF and
    signature-verification switches are now judged. A debug toggle is weak
    when it's on.
  - **Hardcoded credentials:** a secret-shaped name, or a URL with an
    embedded password, is a judged `weak_default`. It is reported as
    `<hardcoded literal, N chars>` or with the password masked, marked
    `literal_redacted`, and never copied into the artifact.
  - **Unparsed modules:** a settings module that doesn't parse is a
    `coverage_gap`.
  - The new class words (`testing`, `csrf`, `skip_auth`,
    `verify_signature`) also apply to the other tiers. On five real Python
    repos, the existing tiers' triples were unchanged.
- `/secure-code-audit`'s config-matrix section documents the tier. An
  `unresolved` sink means no reader in this tree, not an unused setting,
  because frameworks read most of them.

## [0.25.0]

- **`/threat-model` bootstrap maps the review surfaces.**
  - The Surface-mapper's grep table gains five rows: credential verification
    and minting, ownership resolution, security config flags, outbound fetch
    and shared content stores. Route and guard coverage, the sixth surface,
    stays under Network.
  - Entry points those rows produce are tagged with `review_surfaces`.
  - Stage 4's gap-fill walks each tagged surface's check from
    `review-surfaces.md`, alongside STRIDE and the infra/IAM walk. Each
    plausible answer becomes a section 4 row tagged with the surfaces it
    exercises; a check that finds nothing goes in section 5 with the reason.
  - Each new row names the tag it produces. `scope-enforcement` goes on
    Network entry points behind a role, scope or permission check. Outbound
    fetch means a server-side request whose destination someone other than
    the operator can influence. A threat's tags are a subset of the union of
    its entry points' tags. The Surface-mapper Returns shape and the
    checkpoint templates carry `review_surfaces`.
- **`/secure-code-audit` reads the threat model's review-surface tags from
  its JSON** (`<repo>-threat-model.json`, which only the JSON carries). Each
  surface the model tags must end `finding` or `negative`, or `not_assessed`
  with its gap, never `not_applicable`.
- **The `/vuln-scan` review brief checks the review surfaces.**
  - "WHAT TO LOOK FOR" gains a REVIEW SURFACES group, one line per surface.
    A shipped default that switches a control off is reportable even though
    flags are operator-set; the brief's exclusion for operator-controlled
    flags covers flags as an attack vector, not unsafe defaults.
  - The depth heuristics add (d): apply each touched surface's check.
  - The brief template now carries the depth heuristics (a)–(d) itself.
  - Each reported finding names its `<review_surface>`: the surface where
    the defect sits, whatever its CWE.
  - Each review subagent returns a `<surface>` block per surface it
    examined, using only the six ids.
  - Step 4 builds `review_surface_coverage` from the subagents' output:
    - `finding` lists every finding naming the surface.
    - `negative` combines what each subagent examined, and only when no
      finding names the surface.
    - `not_applicable` requires every subagent that looked to agree.
    - A surface nobody examined is `not_assessed` on a full scan and
      `out_of_scope` on a diff scan, never `negative`.
  - In `--diff` mode, a cluster that touches a verifier, a flag or its
    readers, an outbound call, an owner lookup, a route guard or a
    content-assembly path gets the matching surface check.
- `/vuln-scan`'s diff-packet builder no longer quotes a deployment's pilot
  cost figure in its docstring.

## [0.24.0]

- **Per-model cache rates and per-request long-prompt pricing.** Pins
  traust-contracts 0.59.0, traust-ledger and traust-engine 0.27.0.
  - **Cache rates:** `config/model-registry.yaml` sets
    `cache_read_multiplier` 0.05 for Opus 5.5 and Sonnet 5.5, and 0.025 for
    Mythos 5.1 and Fable 5.1, per the published rate card. Every other model
    keeps the standard 0.1.
  - **Haiku 5.5 long prompts:** `claude-haiku-5-5` gets a `long_prompt` tier.
    A request whose prompt (input, cache reads and cache writes) is over 100k
    tokens is priced at $0.50/$2.50.
  - **Financial report:** `build_financial_report`'s transcript collector
    splits long-prompt requests out per request (`collect_spend.add_usage`),
    and both of its pricing paths pass the split through.
  - **Effect:** this workspace's October 2026 Claude Code spend, priced from
    the registry, drops from $1,094.52 to $791.65 (−27.7%), all of it from
    Opus 5.5 cache reads.
- **`out_of_scope` only on diff scans.** The pinned engine rejects an
  `out_of_scope` review-surface entry on a vuln-findings report without
  `metadata.additional.coverage_diff`.
## [0.23.1]

- **`render-narrate` escalates to Sonnet 5.5.** `claude-sonnet-5-5` now comes
  before `claude-sonnet-5` in its approved list, so a `sonnet-class`
  escalation resolves to Sonnet 5.5, as `fact-judge` already does. Its floor
  model (Haiku 5.5) is unchanged.

## [0.23.0]

- **`fact-judge` prefers Sonnet 5.5** (`claude-sonnet-5-5` first, then
  `claude-sonnet-5`). The price is the same, and cache reads cost half as much.
- **`render-narrate` prefers Haiku 5.5** (`claude-haiku-5-5` first, then
  `claude-haiku-4-5-20251001`), at a tenth of Haiku 4.5's price. Prompts over
  100k tokens bill at $0.50/$2.50, which the registry's one price per model
  doesn't record, so spend on long prompts is understated.
- **Fable 5.1 is a candidate on every `mythos-class` role**
  (`candidates: [claude-fable-5-1]`). It awaits evals against Mythos 5.1 and
  changes no routing until it's approved.

## [0.22.0]

- **Model registry updated to the current Anthropic lineup** (published rate
  card, checked 2026-10-16).
  - **Mythos 5.1 replaces Mythos 5** in every role that approved it: all
    eight `mythos-class` roles, plus the mythos escalation entries in
    `fact-judge`, `fuzz-author` and `vuln-scan`. Mythos 5.1 is a
    limited-availability model, so a deployment without access to it can no
    longer resolve those roles.
  - **Opus 5.5 is the preferred Opus**, then Opus 5, then Opus 4.8, in every
    role that approved Opus 4.8. `fuzz-author` and `vuln-scan` now resolve to
    Opus 5.5. `fact-judge` and `render-narrate` resolve at their own floors
    and reach Opus only when escalated.
  - **New rate-card entries:** `claude-mythos-5-1` and `claude-fable-5-1`
    ($10/$50), `claude-opus-5-5` ($4/$20), `claude-sonnet-5-5` ($2/$10) and
    `claude-haiku-5-5` ($0.10/$0.50 for prompts up to 100k tokens). Older
    entries stay so past runs keep a price.
  - **`claude-sonnet-5` corrected from $3/$15 to $2/$10.** Its launch price
    became the standard price. Spend priced from the registry for Sonnet 5
    was overstated by half, and drops by a third once recomputed.
  - The `claude-opus-4-6` note no longer calls its price empirical; it is on
    the published card.

## [0.21.1]

- **New `vuln-scan` model role** (floor `opus-class`, approved
  `claude-opus-4-8` and `claude-mythos-5`, no ledger validity). `/vuln-scan`
  resolved its model through the registry but named no role, so it ran
  unrouted on whatever model the session had. It now runs on, and records
  spend against, `registry models resolve vuln-scan`. The role is separate
  from `deep-audit`, so scan cost tunes on its own. `docs/model-classes.md`
  and `docs/standalone-usage.md` move `vuln-scan` to `opus-class`.
- **Repo-root paths after the stage-directory move.** `/vuln-scan`,
  `/triage`, `/countersign`, `/threat-model` and `/patch` defined `<harness>`
  as `<skill-base>/../..`, which since the move to
  `harnessing/<N>-<stage>/<skill>` points at `harnessing/`, not the repo root.
  Script paths built on it (for example `/triage`'s
  `<harness>/harnessing/4-triage/triage/scripts/...`) did not exist. Now
  `<skill-base>/../../..`.
- `/vuln-scan` diff mode names `scripts/resolve_baseline.py` and
  `scripts/build_diff_packet.py` at their real paths.

## [0.21.0]

- **Review-surface coverage beyond the audit.** traust-contracts 0.57.0 and
  traust-engine 0.26.0 (pinned here) declare and check the record on the
  scans that follow an audit.
  - `/vuln-scan` and `/verify-remediation` record `review_surface_coverage`
    for the code they reviewed. A `--diff` or regression-scan scope answers
    untouched surfaces `out_of_scope`. These reports have no
    `negative_results`, so every status except `finding` carries a note.
  - `/secure-rpm-audit` records the record too, weighting dist-git patches
    and spec-shipped defaults.
  - `/threat-model` tags threats and entry points with `review_surfaces`.
  - `traust reporting validate` requires the record on vuln-findings,
    verification and rpm-profile reports from this release (0.21.0) on.
- **`build_cumulative` merges scan coverage into `*-findings-current.json`.**
  It finds scan reports through the `source.ref` of the
  `vuln_scan_report` / `verification_report` events it replays, and as the
  repo's own `<repo>-vuln-findings.json` / `<repo>-remediation-verification.json`
  (a scan with no new findings writes no events). Only scans dated on or
  after the audit apply, oldest first.
  - A `finding` adds its IDs; a routed regression maps to its `routed_id`.
  - A `negative` replaces earlier answers, but never a `finding` entry whose
    findings are still open. Its note becomes a `negative_results` entry.
  - A scan's `out_of_scope`, `not_applicable` and `not_assessed` change
    nothing.
  - An audit with no record (before traust 0.20.0) starts at `not_assessed`
    with matching `coverage_gaps`, once a scan record applies.
  - `metadata.additional.cumulative.review_surface_sources` names the scan
    that last answered each surface.
  - With no scan record, the output is unchanged.
  - `countersign` passes the audit path through, so its rebuilds merge too.
- The method companion `review-surfaces.md` documents `out_of_scope`, the
  scan records, the merge and the threat-model tags; `/track-findings` and
  `docs/report-structure.md` link it.
- `/vuln-scan`'s diff-mode dispatch note no longer carries a deployment's
  pilot cost figures; dispatch stays an operator decision with no fixed cost
  gate.

## [0.20.2]

- **Pins traust-engine 0.25.2** (`87a94fc`). `traust reporting validate`
  directory sweeps skip hidden directories (`.triage-state/`,
  `.threat-model-state/` and similar). The fingerprint, repository and strict
  checks run only on a report-shaped document: before this, a skill working
  file aborted the sweep for its whole directory with a traceback.

## [0.20.1]

- **Pins traust-contracts 0.57.0** (`4e900e7`), with traust-ledger and
  traust-engine re-pinned to match.
  - Verification and vuln-scan reports may now carry a declared
    `review_surface_coverage` record, and `review_surface_status` gains
    `out_of_scope`. Threat models may tag threats and entry points with
    `review_surfaces`. `traust reporting validate` checks their shapes. The
    fields stay optional until the skills produce them.
  - Storage is at revision 4 (`verification.review_surface_coverage`,
    `threat.review_surfaces`), so existing storage databases need
    `Store.migrate()`.
- **Pins traust-engine 0.25.1.** `traust reporting validate` now detects
  `*-remediation-verification.json`, `*-refuted-register.json` and
  `*-priv-profile.json` by filename. Until now each of them failed against
  the audit-report schema.
- `docs/storage-v1-ddl-model.md` is regenerated from the pinned contracts DDL.

## [0.20.0]

- **`/secure-code-audit` records review-surface coverage as data.** Every
  code-profile report carries `review_surface_coverage` (traust-contracts
  0.56.0), one entry per review surface: `finding` with `finding_ids`,
  `negative` with a `negative_results` entry whose `area` starts with the
  surface ID, `not_applicable` with a note, or `not_assessed` with a note
  and a `coverage_gaps` entry. A new pre-validation step has the auditor
  check the record. traust-engine 0.25.0 makes it required for code-profile
  audits from this release, and checks every entry against the rest of the
  report. A surface judged but left unrecorded now fails validation instead
  of reading as covered.
- **The surface checks live in the skill.** `docs/review-surfaces.md` moves
  to `harnessing/3-audit/secure-code-audit/review-surfaces.md`, so
  methodology stays out of the adopter-facing `docs/`. The new "Recording
  coverage" section replaces the minimum-coverage and coverage-gap sections.
  `docs/report-structure.md` documents the field.
- Pins traust-engine 0.25.0 (`bc14d6a`, traust-engine#27). Its version gates
  now pick the numbering from the audit date, so they hold across the
  2026-09-10 version reset.

## [0.19.1]

- **Pins traust-contracts 0.56.0** (`cb8bba8`), with traust-ledger and
  traust-engine re-pinned to match. Reports may now carry the declared
  `review_surface_coverage` record. `traust reporting validate` checks its
  shape (all six review surfaces, valid statuses, `finding_ids` / `note`
  where required). The field stays optional until `/secure-code-audit`
  produces it. Storage is at revision 3 (`report.review_surface_coverage`):
  existing storage databases need `Store.migrate()`.
- `docs/storage-v1-ddl-model.md` is regenerated from the pinned contracts
  DDL. It had fallen behind earlier storage releases (43 → 49 tables).

## [0.19.0]

- **New `docs/review-surfaces.md`: six code surfaces every review checks.**
  These are `credential-acceptance`, `ownership-resolution`,
  `security-flags`, `outbound-fetch`, `stored-content-integrity` and
  `scope-enforcement`, each with the check it requires, its `category` and
  CWEs, and what a scoped negative result looks like. It is the single
  definition; skills reference it.
- **`/secure-code-audit`:**
  - Review-depth heuristic 5 checks the six surfaces on every audit.
  - With no threat model, they are the minimum coverage: each applicable
    surface ends with a finding or a scoped negative result.
  - A scoped or partial audit records surfaces it skipped in
    `metadata.additional.coverage_gaps` (`tool: "review-surfaces"`).
  - A search-based negative result quotes the exact pattern searched.
  - PEACH data segmentation adds the stored-content integrity check.
- Scanner suppression comments in the target (`gitleaks:allow`,
  `nosemgrep`/`nosem`, `# nosec`) are named as repository content, never
  exemptions, in the adversarial-content doctrine and the skill. The
  pre-scans already disable them and flag the candidates.

## [0.18.1]

- **Pins traust-engine 0.24.0:** `traust adapters opengrep` no longer
  honours the scanned target's own `nosemgrep` / `nosem` comments. A fact
  on such a line is reported with `nosem_marked: true` instead of being
  dropped, the same treatment `traust adapters gitleaks` gives
  `gitleaks:allow` (`inline_allow`).

## [0.18.0]

- **One copy of each rule pack, loaded with no configuration.** The opengrep
  rule pack and the gitleaks config live only in traust-engine
  (`traust_engine/data/secure-code-audit/`), which is what every default run
  already loaded. The harness copies under
  `harnessing/3-audit/secure-code-audit/` are deleted. Rule pack v1.8
  (from 0.17.0) only reached default runs once traust-engine 0.23.0 carried
  it, so this release pins traust-engine 0.23.0 (`80bf320`).
- New docs gate `single rule pack`: fails on a rule-pack directory in this
  repo, or on a skill, doc or config that points at the removed copies.
- New `tests/test_default_rule_packs.py`: with the adopter-style fixture
  config (no rule-pack location set), `traust adapters opengrep` reports a
  v1.8 rule and `traust adapters gitleaks` reports a Traust detector. Not
  marked `integration`, so the pre-push hook runs them wherever the scanners
  are installed.
- `/secure-code-audit`, `/mine-ledger` and the docs point at the bundled
  packs. Rule promotion from `/mine-ledger` drafts is a traust-engine PR,
  followed by the traust engine-pin bump.

## [0.17.1]

- **Pins traust-contracts 0.55.0, traust-ledger and traust-engine 0.22.1.**
  - traust-contracts 0.55.0 types the run records under report
    `metadata.additional` (traust-contracts#42). A report that writes one of
    them in another shape, such as `null` inside `model_routing`, now fails
    `traust reporting validate`. It also brings storage revision 2 from
    0.54.0.
  - traust-engine 0.22.1: `traust registry models stamp` leaves out
    `floor` for a role missing from the registry instead of writing
    `null`; the gitleaks adapter (0.22.0) no longer honours the scanned
    target's own `gitleaks:allow` comments and flags those candidates
    `inline_allow`.

## [0.17.0]

- **Rule pack v1.8: authentication, ownership and crypto-hygiene
  rules.** Seven new or widened opengrep rules for defect classes that
  review missed and no rule surfaced (see the pack README for each rule's
  shape and exclusions):
  - `traust-python-injection-like-wildcard-unescaped` and
    `traust-go-injection-like-wildcard-unescaped` (CWE-155): a LIKE/ILIKE
    pattern built from a run-time value with `%`/`_` left live, through an
    ORM pattern operator, raw SQL text, or a wildcard-concatenated bound
    argument. Escape helpers and ESCAPE clauses sanitize; DDL
    `(LIKE table …)` is excluded.
  - `traust-python-authentication-jwt-signature-unverified` (new
    `python/authentication.yaml`) and
    `traust-go-authentication-jwt-signature-unverified` (CWE-347): token
    decoding with signature verification off, including the conditional
    shape (options mutated under a test/debug flag), `verify=False`, the
    `none` algorithm, Go key functions that return no key, and
    `ParseUnverified`.
  - `traust-python-input-validation-pickle-loads-taint` now also sinks on
    `Unpickler(...).load()` (including subclasses), `dill`, `jsonpickle`
    and `shelve`. The new
    `traust-python-input-validation-restricted-unpickler-inventory` (INFO)
    lists every `Unpickler` subclass overriding `find_class`, so a negative
    result cannot report deserialization absent where one exists.
  - `traust-python-cryptography-secret-compare-not-constant-time` and
    `traust-go-cryptography-secret-compare-not-constant-time` (CWE-208,
    LOW confidence): `==`/`!=`/`bytes.Equal` on secret-named operands,
    excluding literal, nil, error-sentinel, enum-constant and
    metadata-named comparisons.
- The rules are authored in the harness pack
  (`harnessing/3-audit/secure-code-audit/opengrep-rules/`). A run uses them
  when `locations.opengrep_rules` (or `--rule-pack`) points at that
  directory; the copy bundled in traust-engine is unchanged by this
  release.

## [0.16.0]

- **The route×guard pre-scan enumerates Flask.** `enumerate_route_guards.py`
  gains a `flask` family, parsed with `ast` (target code is never imported):
  `@<app|blueprint>.route` and verb decorators, `add_url_rule()` including
  MethodView/View `.as_view()` classes (one row per HTTP method the class
  defines), and Flask-RESTful / flask-restx `add_resource()` and
  `@<api|namespace>.route` resource classes. Guards come from handler and
  method decorators, class `decorators` / `method_decorators` (inherited
  through in-repo base classes) and `before_request` / `before_app_request`
  hooks that can reject a request. A blueprint hook covers that blueprint;
  an app hook covers the same app object and the blueprints its file
  registers, never every route in the tree. Explicit public / exempt
  decorators are unguard markers.
- Flask rows add a second asymmetry shape: a guard family (scope, admin,
  role, permission, csrf, token, authn) carried by most rows of one view
  class or blueprint but missing from a guarded sibling marks that sibling
  `judgement_required` with `guard_family_gaps`. Computed paths are kept
  as source text with `pattern_dynamic: true` (module-level string
  constants resolve to their literal), and rows under a test/example
  directory carry `test_path: true`.
- A tree that imports Flask but has no recognizable registration reports a
  `flask` coverage gap rather than reading as clean; Flask is no longer a
  coverage gap when it was enumerated. Files that also import FastAPI never
  contribute verb-decorator rows.
- `secure-code-audit` SKILL.md and `docs/language-support.md` list the new
  family.

## [0.15.1]

- **The docs gate accepts the `docs/README.md` index.** Since the README
  rewrite (#68), the root README links one reader's map, `docs/README.md`,
  instead of listing every guide, and the enumeration-coverage check failed
  for 24 pages. A `docs/` page now counts as reachable when the README or
  the index mentions it, and a new check fails if the README stops linking
  the index, so every page stays one hop from the README.
- `docs/cli-reference.md` lists `ledger pull`.

## [0.15.0]

- **The ledger is configured in `ledger.yaml`, not environment variables.**
  New templates `config/ledger.example.yaml` and `config/storage.example.yaml`
  (traust-contracts 0.53.0 shape: `dsn`, `signing`, `identity`). They are
  opt-in: `install_traust` lists them but never copies them, since an example
  DSN would switch the deployment to a database that does not exist.
- With `ledger.yaml` `dsn` set, the Ledger database is the authority for
  disposition layers and `*-findings-layer.json` becomes a read-only snapshot,
  so countersigns written outside the harness (e.g. in SCI) reach the next run.
  Every ledger writer — `emit-triage`, `emit-validation`, `emit-verification`,
  `route_regressions`, `route_impact_findings`, `build_cumulative`,
  `ledger pull`, `corpus finding-identity rebaseline`, the fuzz emitter and
  `baseline_claims` — takes `--ledger-layer` / `--product-repo` and binds the
  run's layer once (traust-engine 0.21.0 `engine.ledger.bind`); the emitters
  forward it to the `build_cumulative` they spawn, and `countersign` reads the
  layer through the ledger service. Without a `dsn`, file mode is unchanged.
  Read-only sweeps (`build_verify_sweep`, the fuzz cross-layer fingerprint
  lookup) read layer files, which are the snapshots in database mode.
- New `traust ledger pull <layer>` exports the bound layer as that snapshot
  before an LLM session.
- `build_cumulative` reads the layer through the ledger service, so its claim
  check and cumulative report see the database layer, not a stale file.
- **Breaking: signing and the employee directory come from `ledger.yaml`.**
  With traust-engine 0.21.0 no `LAAS_SIGNING_*` or `LEDGER_DIRECTORY_COMMAND`
  variable configures a harness run: set `signing` (method, key path,
  `required`) and `identity.directory_command` in the mounted `ledger.yaml`.
  `countersign` and `compliance_scope_intake` take their up-front directory
  check from the same configured directory. Docs (`signing.md`,
  `disposition-ledger.md`, `setup.md`, `architecture.md`, `requirements.md`,
  skills) describe the config keys instead of the variables; only the
  standalone `ledger` CLI still reads its own `LAAS_SIGNING_*`.
- New `ledger-db` extra (`traust-ledger[db]`) for the database backend.
- Pins traust-engine 0.21.0 (traust-security/traust-engine#21), traust-ledger
  0.11.1 and traust-contracts 0.53.0, all from `traust-security`.
- `docs/report-structure.md` lists every `remediation_effort` value.

## [0.14.0]

- **The scheduled threat-model check-up applies OWASP ratings.** A new
  `/threat-model review --auto --apply-ratings` mode (review.md R6) writes the
  OWASP Risk Rating Methodology ratings it proposes for unrated threats and
  leaves every other proposal report-only for a human. The quarterly and
  release-review lanes now dispatch it; `--auto` alone stays report-only.
  Release-branch models are still outside those lanes, by design.
- **`traust reporting render` won't erase threat-model prose.** It refuses to
  overwrite an existing `.md` when the new rendering would drop or empty a
  section the file has, which is what happens when the JSON lacks members
  the Markdown carries (the pre-schema backfill). Pass `--allow-section-loss`
  for an intended removal. Under `--apply-ratings` a refusal means "re-model
  needed" and nothing is written.

## [0.13.3]

- traust-engine 0.18.2. Rendering a threat model from its JSON is now
  lossless: the update history sits inside section 7 (so a rated model with
  history passes lint), optional asset columns are kept, and attack scenarios
  render as prose.
- traust-contracts 0.47.0 (every threat-model section defined) and
  traust-ledger 0.8.5.

## [0.13.2]

- traust-contracts v0.46.0 (OWASP risk ratings in the storage `threat`
  table), traust-ledger 0.8.4 and traust-engine 0.18.1. Nothing else changes.

## [0.13.1]

- **Released pins.** traust-engine `v0.18.0` and traust-ledger `v0.8.3`
  replace the fork commits 0.13.0 merged with. They are the same trees, so
  nothing else changes.

## [0.13.0]

- **Threats are rated with the OWASP Risk Rating Methodology.** This
  replaces the impact/likelihood labels and 1-2-4-8-16 weights inherited
  from the upstream skill, which weren't a published standard. Pins
  traust-contracts v0.45.0 (`risk_rating` on threats), traust-ledger 0.8.3
  and traust-engine 0.18.0; the engine and ledger are pinned to their open-PR
  commits until they're tagged.
  - `/threat-model`: the schema.md scoring guide restates the method in
    original wording, citing OWASP. The author scores the sixteen 0-9 factors
    with a reason for each one that evidence, a control or the owner moved.
    Bootstrap rates on the technical basis; interview rates on the business
    basis when the owner can answer. Section 4 gains
    `severity | likelihood | impact`, and a new section 11 lists the factors.
    bootstrap, interview, review, update and pr now speak the new vocabulary.
  - New `traust reporting rate-threats <model>.json` fills each rating's
    scores, levels and severity from its factors (`--check` reports without
    writing). `validate` rejects a rating that disagrees with its factors.
  - Existing models move over at their next update: any pass that writes a
    model rates every threat still carrying legacy labels (review R3b,
    update U1). Nothing is re-rated now.
  - `/threat-register` ranks by OWASP severity, then impact and likelihood
    score. It orders legacy threats by a labelled crosswalk (never reported
    as a rating) and orders products by open-severity counts rather than a
    weighted sum. It reports how many threats are rated. `score`,
    `score_sum`, `max_score` and `open_critical_plus` are replaced by
    `severity`, `severity_source`, `open_by_severity`, `max_severity` and
    `open_critical`. Quick wins now cover unmitigated threats of high or
    critical severity.
  - Crown-jewel tiers: a rated threat's impact component is its OWASP
    impact score / 9; legacy threats keep their points / 5.
  - `docs/external-dependencies.md` records the OWASP Risk Rating
    Methodology (CC-BY-SA-4.0, reimplemented in original wording), and
    `docs/risk-rating-methodology.md` covers threats.

## [0.12.0]

- **Pins: contracts 0.44.0, engine 0.17.0, ledger 0.8.2.** Ledger stays a
  declared dependency until the four direct `traust_ledger` call sites go
  through the engine's `LedgerService`. Ledger ≥0.7 verifies the caller's identity
  on every write, so running the harness needs a real identity: OIDC
  (`LEDGER_OIDC_ISSUER` / `LEDGER_OIDC_JWKS_URL`) or local auth
  (`LEDGER_LOCAL_IDENTITY`, or `ledger auth local`).
- **A rebaseline is now a ledger restatement.** `baseline_claims record
  --rebaseline <id>` needs `--ticket` and `--rationale`, and writes the new
  claim hash through `LedgerService.restate()`, which records the prior hash,
  the verified actor, the ticket and the rationale in the layer. When the
  report bytes changed too, `audit_report_sha256` is restated with it. Pinning
  a new finding's hash is unchanged. On ledger 0.8 the old path, an
  unrecorded overwrite, is refused. `track-findings` and
  `docs/disposition-ledger.md` describe the new flags; the ticket and
  rationale are the user's to supply.
- **The test suite sets up its own local ledger identity.** `tests/conftest.py`
  isolates `HOME`, clears inherited ledger tokens, sets
  `LEDGER_LOCAL_IDENTITY=test@traust.local`, and stops the run if auth doesn't
  resolve. Tests no longer pass placeholder tokens. The `requires_ledger`
  marker and its `LAAS_TOKEN` skip are gone, so the 17 ledger integration
  tests it hid now run; fixing them turned up the two fixes below. See
  CONTRIBUTING.md → "Ledger auth in tests".
- Fix: `emit_triage_ledger_events` reported every idempotent re-run as "N
  appended, 0 already present". An empty list of new event IDs was treated
  as unknown; the sibling emitters already handled it.
- Fix: tests that drove `build_cumulative` / `emit_triage_ledger_events` from
  a temp directory now pass `--findings-root`, and the `sweep` test creates
  its duplicate symlink the right way round. The path confinement is
  unchanged and still has its own tests.
- `remediate-finding` cites its manifest and mutation-evidence scripts by
  their full `harnessing/` paths, so the reference-integrity check passes
  again.
- `config/locations.example.yaml` lists every key with an empty default and
  documents `s3://` for `analysis_results` (credentials come from the
  environment, never the file).

## [0.11.1]

- **Stage-7 patch evidence is findable from `/patch`.** `remediate-finding`
  gains an `## Integrations` section naming its mutation (Phase 4b) and
  property (Phase 4c) evidence producers and the stage-8
  `scanner_differential`; `/patch` points to all three; the skill's heading
  said Stage 9 and now says Stage 7. `docs/artifacts.md` no longer claims
  `/verify-remediation` reads `*-remediation.json`.

## [0.3.0]

## Changes

- **Reverted the 0.10.0 findings.db and census changes.** Every consumer
  reads the previous nine-table `findings.db` projection again and the census
  walks reports as before. Pins: contracts 0.35.0 (the 0.33.0 storage
  contract), engine 0.16.0, ledger 0.6.32. 0.10.0 remains tagged and should
  not be pinned. Rebuild `findings.db` with `traust corpus findings-db` after
  upgrading; a store built by 0.10.0 is refused.

## [0.2.13]

- **The reachability graphs now say what they are for**, not just what they
  are. Their purpose is deciding whether an advisory reaches *your* code: a
  manifest pin proves a vulnerable package is present, not that anything calls
  the vulnerable function. `/impact-analysis` uses the answer as its strongest
  evidence tier, and `/secure-rpm-audit` uses it too.

  Documents the asymmetry that makes the tier trustworthy: a resolved
  first-party call promotes to evidence `symbol` and classification
  `affected`, package-level calls promote `manifest` → `symbol-usage`, and an
  absent call path **never demotes anything** — DI, reflection and
  MethodHandles hide edges from static analysis, so `no_call_sites_found` is
  recorded honestly. Also why the tier is gated on cheaper tiers (a CPG is
  expensive) and that an absent Joern records `skipped`, never a fake pass.

## [0.2.12]

- **`findings.db` removed from the graph list.** It is a relational projection
  of the findings corpus, not a graph — the page even said so while listing
  it. It appears now under an explicit "Not a graph" heading, because its
  location in `analysis-results/graph/` invites the assumption. One table
  inside it, `graph_edges`, is imported from repo-graph so findings can be
  joined to what ships them; a borrowed edge table does not make the database
  a graph.

- **Joern is described as what it is: a Code Property Graph.** AST, control
  flow and data flow in one queryable graph, built by `joern-parse` with the
  frontend named per language and queried with CPGQL. Calling it a "call
  graph" undersold it. Still transient — built in a temp dir and discarded
  with the run — so it and the govulncheck call graph are the richest graphs
  the harness touches and the only ones that cannot be queried afterwards.

## [0.2.11]

- **`docs/graphs.md` now covers every graph the harness builds or reads**, not
  two of them. Added: `findings.db` (the findings projection), the ATT&CK
  Navigator coverage layer and how its observed/modeled/derived scores differ,
  per-finding `attack_chains[]`, and the transient reachability call graphs
  built by `adapters govulncheck` / `adapters joern` — which are analysis
  steps with nothing persisted, worth saying so nobody looks for an artifact.

  Retitled: calling both graphs "portfolio graphs" reproduced the exact
  confusion the page exists to remove. One is `repo-graph`, one is
  `portfolio-graph`.

  Also dropped the doc's opening banner, which described how the page was
  researched rather than telling a reader anything.

## [0.2.10]

- **`docs/` is adopter-facing; estate specifics removed.** `docs/graphs.md`
  carried one deployment's graph sizes and node counts, and
  `docs/model-classes.md` carried development history. Neither is product
  documentation. Sizes are now stated as deployment-specific with a pointer to
  `repo-graph-stats.md`, which reports the reader's own.

- **New docs-consistency check, `docs/ estate neutrality`.** The deployment
  vocabulary was applied to `config/` but never to `docs/`, which is how those
  specifics passed every gate. The same block/review rules now run over
  `docs/**/*.md`. All 32 existing docs pass unchanged; mutation-tested by
  injecting a vocabulary match.

  Note the limit: estate-specific *figures* — graph sizes, corpus counts —
  match no pattern and stay a review concern. Write them as
  deployment-specific rather than quoting one deployment's numbers.

## [0.2.9]

- **New `docs/graphs.md`** — how `/repo-graph` and `/portfolio-graph` are
  actually used, which was documented nowhere. The two SKILL.md files were the
  only substantive source; every mention across `docs/` was a one-line passing
  reference with no section.

  Covers what each graph holds and the question it answers, the L0–L4 layer
  model, that `repo-graph.json` is `/portfolio-graph`'s L0 spine (so it is a
  prerequisite, not an alternative), the full consumer list for each artifact,
  and what a stale graph gets wrong — a stale repo-graph misstates coverage
  and ownership, a stale portfolio-graph *understates* blast radius, which
  reads as good news.

- **`/portfolio-graph` gains the `## Integrations` section it was missing.**
  `/repo-graph` had one; the skill holding the code-level graph
  documented neither its consumers nor what depends on it being fresh.

- **New docs-consistency check, `graph consumer lists`.** The consumer lists
  were built by searching for the artifact filenames, so they rot as soon as a
  new consumer lands. The check fails when anything opens
  `portfolio-graph.db` or `repo-graph.json` without being named in the doc.
  Mutation-tested with a throwaway module, and it caught two real cases while
  being written: itself (it holds the artifact names as data) and
  `check_drift`, which is documented under its skill name `/drift-watch`.

## [0.2.8]

- **Documents how an adopter configures their own models**, which was the one
  question `model-classes.md` could not answer. `model-registry.yaml` is a
  seeded shipped default and the copy in `$TRAUST_CONFIG_HOME` wins, but that
  was a single clause in `model-routing.md` and said nothing about how.

  New "Configuring your own models" section covers the per-role granularity
  (repoint one role, the rest keep their defaults), the exact schema
  requirements at provider/model/role level, that no vendor is assumed, that
  `validate` refuses a sub-floor approval, and what
  `install_traust --doctor`/`--force` do to a deliberate override. Linked from
  `model-routing.md`, `requirements.md` (which now says outright that the
  classes are defaults, not requirements) and `config/README.md`.

  Every claim was executed against a scratch config home, which caught the
  worked example being wrong: replacing a role block drops `candidates` and
  `ledger_validity_writer`, both schema-required, so the YAML an adopter
  would have copied failed validation. The example now changes only the
  `approved` line.

## [0.2.7]

- **New `docs/model-classes.md`**, linked from `requirements.md` and
  `model-routing.md`: what each of the four tier classes is for, the eleven
  role floors, which roles may write a validity verdict into the ledger, the
  escalation triggers, and a per-skill class index.

  Two things it clears up, because both were causing the question "where is
  this documented" to have no good answer. The per-skill classes live in *two*
  tables — `campaign-workflow.md` (21 pipeline skills) and
  `standalone-usage.md` (27 standalone skills) — which are complementary, not
  duplicates, so neither reads as authoritative. And skill frontmatter's
  `harness.tier` (`primary`/`secondary`/`tertiary`/`ci`) is a *different axis*
  entirely, which makes it look like the answer when it is not.

- **New docs-consistency check, `model-class index`.** The index is derived
  from the two usage tables and nothing links a skill to a class
  mechanically, so the check fails on a misclassed skill, a name that is not a
  skill, an indexed skill with no class in either table, or a classed skill
  missing from the index. Mutation-tested both ways.

## [0.2.6]

- Pin traust-contracts v0.5.0, traust-engine v0.2.5 and traust-ledger v0.3.0.
  Brings in the `evidence` projection column (so typed patch evidence is
  queryable in SQL, not just present in the payload), the fixed
  `traust_storage` PostgreSQL namespace, and the ledger's stamp/whoami REST
  verbs.

  Smoke-tested against the pinned copy rather than assumed: the
  proof-requires-both-observations rule still holds, the verification family
  still carries `evidence`, and both projection tables now report an
  `evidence` column from the pinned DDL.

## [0.2.5]

- Point every sibling pin at the new `traust-security` GitHub organisation:
  traust-contracts v0.4.0, traust-engine v0.2.4, traust-ledger v0.2.3.

  The org move could not be a URL edit. uv honours `[tool.uv.sources]` inside
  git dependencies, so a tag cut before the move carries the old URL and
  resolution fails with "conflicting URLs for package traust-contracts". The
  corrected URL only reaches consumers as a new tag, making this the same
  bottom-up train a schema change needs: ledger 0.2.3, engine 0.2.4, then
  here.

## [0.2.4]

- **The execution boundary is a config setting, not an invented env var.**
  0.2.3 added `TRAUST_SANDBOXED_RUNNER`, a variable nothing on the platform
  exports — a convention only this repo knew about, so the path it guarded
  would never have fired. Replaced by `sandbox:` in
  `$TRAUST_CONFIG_HOME/execution-boundaries.yaml`, with a template in
  `config/` seeded by `install_traust`.

  `sandbox: none` is the default: direct execution with a scrubbed
  environment, on a disposable copy rather than the worktree the diff comes
  from. `sandbox: podman` opts into a nested rootless container and is never
  silently downgraded — with no working runtime the lane reports
  `not_attempted`. Detection stays `podman info` rather than
  `command -v podman`.

  Verified on both lanes in both modes: default runs and returns `proves`
  (mutation 19/19; property failed-then-passed), a configured `podman` with no
  runtime refuses with that reason, and an invalid value falls back to the
  documented default. Documented in setup.md, config/README.md,
  external-dependencies.md and the orchestrator prerequisites.

## [0.2.3]

- **The evidence lanes no longer hard-require podman.** `run_mutation.sh` and
  `run_property.sh` accept either nested podman or a platform-attested
  sandbox, declared by the orchestrator as
  `TRAUST_SANDBOXED_RUNNER=<runner-label>`. On a central runner whose image
  carries the toolchain but cannot nest containers, both lanes would otherwise
  have returned `not_attempted` on every run, permanently.

  Still no *unattested* fallback: with neither boundary the lanes emit
  `not_attempted` rather than running target code in the open. The env var is
  a declaration of deployment fact, not a security control — its only job is
  to stop podman's absence from being read as permission.

- **Boundary detection uses `podman info`, not `command -v podman`.** The
  client binary is present on a host whose VM is stopped and in images that
  ship the CLI with no runtime; choosing podman there failed every run with
  exit 125 — the exact failure the change was meant to prevent. Caught by
  running it with the VM deliberately stopped.

- The resolved boundary is recorded in each evidence item's `command`, since a
  verdict from nested podman and one from an attested sandbox are not equally
  strong. `docs/external-dependencies.md` gains the boundary contract and
  names the new podman consumers; `docs/continuous-operations.md` gains the
  orchestrator prerequisite row.

## [0.2.2]

- Pin traust-contracts v0.4.0 / traust-engine v0.2.3 / traust-ledger v0.2.2,
  so a *verification* report can carry the typed patch-evidence block.
- **`/verify-remediation` gains its one executed claim** (ToB plan item 5b).
  Step 4-pre already re-ran the scanner on the patched checkout and compared
  against facts recorded in the original report — which is why it warned that
  a vanished fact can be rule evolution rather than a code change. New step
  4-pre.5 scans BOTH revisions and emits a typed `scanner_differential`
  evidence item, making the rule-evolution case an explicit
  `not_attempted` instead of a silent mis-read.

  §8a's stage-8 ceiling is lifted for that differential only: `proves` means
  the pattern the finding rested on is gone — pattern-level, since a diff can
  silence a scanner by moving the sink. Findings with no scanner backing stay
  analysis-only, and step 4a's root-cause check remains mandatory.

## [0.2.1]

- Pin traust-contracts v0.3.0, traust-engine v0.2.2 and traust-ledger v0.2.1 —
  the final hop of the train for the remediation `evidence[]` block. Until
  this pin, `reporting/validate.py` rejected any report carrying it, because
  the remediation schema is `additionalProperties: false`.

  Smoke-tested rather than assumed: the same evidence-carrying report
  validates with 0 errors against the newly pinned schema and is rejected
  against v0.1.1 with *"Additional properties are not allowed ('evidence' was
  unexpected)"*, and all eight enforcement cases behave — a `proves` claim
  missing either observation is refused, `not_attempted` without a reason is
  refused, and invented kinds/outcomes are refused.

## [0.1.1]

## Changes

- Event `occurred_at` is built through contracts' `to_rfc3339` via
  `traust.lib.event_time.report_occurred_at`, replacing the same f-string in
  four emitters. A report stating an unusable date now raises instead of
  getting a silent substitute; an absent one falls back to `recorded_at`.
  A triage report carrying `"triage_completed": true` previously emitted the
  literal `'TrueT00:00:00+00:00'`.

- `--recorded-at` is validated at the CLI boundary in all six producers. It
  fed `recorded_at` unchecked, whose `[:10]` prefix reaches interactive
  `source.ref` and therefore `event_id`.

- New migration `traust.migrations.fix_event_timestamps`: converts bare dates
  to midnight UTC (preserving the `[:10]` prefix, so `event_id` does not
  move), drops an unrepairable `occurred_at`, and reports a non-conforming
  `recorded_at` rather than rewriting a required field. Dry-run by default,
  idempotent, and a layer that arrives signed must leave signed.

- Read sites prefer a *parseable* timestamp over a merely present one.
  `build_trends.py` bucketed via `date.fromisoformat(value[:10])` and crashed
  on `'TrueT00:00'`.

- Unrelated fix, bundled: `check_reference_integrity` allowlisted only
  `<skill_dir>/scripts/` while the docs use `<skill-base>`, so it flagged a
  valid reference as stale and failed on a clean tree. It also missed a
  genuinely stale path in the same file. Both corrected.

### Upgrading

Pins move to contracts / engine / ledger 0.1.1, which enforce RFC 3339 on
`LayerEvent.recorded_at` and `.occurred_at` on read as well as write. Run the
migration against any existing corpus first:

```bash
python3 -m traust.migrations.fix_event_timestamps <results-root>          # dry run
python3 -m traust.migrations.fix_event_timestamps <results-root> --apply  # write
```

`--apply` re-roots each repaired layer, so it needs a signing identity
(`LAAS_SIGNING_KEY_PATH` + `COSIGN_PASSWORD`) for layers that are currently
signed. Unsigned layers only need re-stamping.

## [0.1.0]

Workflow engine for automated, multi-framework security assessment of
software portfolios — source repositories, container images, RPM packages,
Kubernetes operators, and infrastructure-as-code. Provides the skills, slash
commands, schemas, and prompt engineering that let an AI coding agent run
consistent, repeatable audits, then triage and validate findings, recording
every disposition in a signed ledger.
