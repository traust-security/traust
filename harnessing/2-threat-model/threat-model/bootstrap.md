# /threat-model bootstrap

> **Re-read note:** If you need this file mid-session and the Read tool
> reports "file unchanged", the prior result was evicted from context; reload
> with `cat <skill-base>/bootstrap.md` via Bash.

Derive a threat model from **code + past vulnerabilities** when no application
owner is available. Five stages: spawn a parallel research swarm, synthesize
its findings into sections 1-3 and a vuln working table, generalize vulns into threat
classes, gap-fill with STRIDE, emit the model file (`<model-file>` =
`<repo>-threat-model.md`; naming rule in `SKILL.md`) per `schema.md`.

This mode is read-only static analysis and is **language-agnostic**: the same
stages apply whether the target is C/C++, Rust, Go, Python, Java/Kotlin,
JavaScript/TypeScript, or polyglot. Do not build, run, or fuzz the target. The
Bash tool is permitted **only** for `git` (history mining), `find`/`ls`
(layout), `gh api` (public advisory lookup), and `cat` (re-reading skill
files). Do not execute anything from inside `<target-dir>`. The same
restriction applies to every subagent you spawn: pass it verbatim in each
prompt.

---

## Inputs

- `<target-dir>` (required): local checkout.
- `--vulns <path>` (optional): past vulnerabilities. Any of:
  - newline-separated CVE IDs (`CVE-2026-29022`)
  - CSV with columns `id,title,component,description` (extra columns ignored)
  - markdown pentest report (parse headings + body for finding descriptions)
  - JSON array of objects with at least `id` and `description` keys
- `--depth recon|full` (optional, default `full`): `recon` runs stages 1-2
  only. Still write all eight sections (schema requires sections 1-7; section 8 optional);
  leave section 4, section 5, and section 8 as header + empty table, and put "run with --depth full
  to populate" in section 6.
  Use for fast context-building before a deeper pass.

If `--vulns` is absent, the Vuln-file parser agent is skipped; the History
miner and Advisory fetcher agents in the Stage-1 swarm cover the same ground
from `<target-dir>`'s own git history and public advisories.

**Harness pipeline artifacts as vuln evidence.** When the target has been
through the harness pipeline, prefer its artifacts (typically at
`analysis-results/findings/<product>/<repo>/`) over raw scanner dumps, and
weight them by verdict and assurance — the taxonomy exists precisely so a
threat model doesn't treat all claims alike
(see `docs/disposition-ledger.md`, evidence classes):

- `*-findings-current.json` (disposition ledger view) is the best single
  input: each finding carries `validation_status` and
  `disposition.assurance`. `execution_proven` findings are the strongest
  likelihood evidence a threat row can cite; `machine_verified` (triage
  3-0) is strong; bare `claimed` is weak.
- **`hardening` findings are mitigation evidence, not attack evidence**:
  they don't raise a threat's likelihood directly, but they lower the
  "controls" side of section 4 for every threat crossing that component
  — a threat whose path traverses a component with open hardening gaps
  has weaker standing mitigations than the manifests suggest (the
  unhardened-blast-radius effect). Cite them in the threat's
  controls/status column, and surface clusters as section 8
  recommendations.
- **Countersigned `false_positive` findings are NOT evidence** for
  likelihood — but a *pattern* of FPs around one surface is worth a
  section 6 open question, and the `*-refuted-register.json` shows what
  remains scheduled for empirical falsification.
- `undetermined` findings belong in section 6 open questions verbatim —
  the pipeline itself could not decide.

- `--context <path[,path,…]>` (optional): external documentation the code
  scan won't find. Supported source types: OpenAPI/Swagger specs, SBOMs
  (CycloneDX/SPDX), Terraform/CloudFormation, k8s manifests or Helm values
  outside the tree, prior threat-model files (either naming convention),
  SAR/pentest exports
  (markdown or PDF-extracted text), architecture docs, Mermaid/PlantUML
  diagrams. Directories are ingested file-by-file for supported extensions
  (`.yaml`/`.yml`/`.json`/`.md`/`.tf`/`.hcl`/`.xml`); binaries are skipped
  with a note. Two rules are absolute: **never silently skip a source the
  user explicitly provided** (unreadable → say so, with the exact path),
  and **doc-vs-code conflicts are findings** — where a provided document
  says X and the code does Y, record the discrepancy as a candidate
  section 4 row or section 6 open question, never quietly prefer one.
- `--fresh` (optional): ignore any existing checkpoint in
  `./.threat-model-state/` and start from Stage 1.

---

## Checkpointing (runs before Stage 1 and after every stage)

On large codebases the Stage-1 swarm can exhaust context or hit rate limits
before Stage 5 emits the model file. Stage state persists to
`./.threat-model-state/` (in the **current working directory**, not
`<target-dir>`) so a fresh `/threat-model bootstrap` session can resume
without re-spawning the swarm. The state dir is cwd-relative because
`checkpoint.py` confines all paths to cwd as a guard against prompt-injected
writes outside the repo.

All checkpoint I/O goes through `python3 -m traust.cli admin checkpoint`
(atomic writes, JSON-validated). Never use the Write tool for `progress.json`
directly. Never pass payload via heredoc or stdin; target-derived strings
could collide with the heredoc delimiter and break out to shell. The
Write→`--from` pattern keeps repo-derived bytes out of Bash argv.

State files in `./.threat-model-state/`:
- `progress.json` — **single source of truth** for resume position:
  `{"status": "running"|"complete", "stage_done": N}`. Resume decisions read
  ONLY this file.
- `stageN.json` — data payload for stage N (schemas at the tail of each stage
  below).
- `_chunk.tmp` — transient payload buffer; overwritten before every
  `save`/`append` call.

**Start of run — resume check.** Bash:
`python3 -m traust.cli admin checkpoint load ./.threat-model-state`

- `status == "absent"` OR `"complete"`, OR `--fresh` in `$ARGUMENTS` →
  **fresh start.** Bash:
  `python3 -m traust.cli admin checkpoint reset ./.threat-model-state`,
  then proceed to Stage 1.
- `status == "running"` with `stage_done == N` → **resume.** Read
  `stage1.json` through `stageN.json` **in order**, merging keys into working
  state (later files override earlier — checkpoints may be deltas). Print
  `Resuming from checkpoint: Stage N complete`, and **skip directly to
  Stage N+1**.

**End of every stage N.** Two tool calls:
1. Write tool → `./.threat-model-state/_chunk.tmp` containing the
   stage's output JSON.
2. Bash → `python3 -m traust.cli admin checkpoint save ./.threat-model-state <N> <name> --key stage --from ./.threat-model-state/_chunk.tmp`

**End of run.** After writing `<target-dir>/<model-file>`, Bash:
`python3 -m traust.cli admin checkpoint done ./.threat-model-state 5 --key stage`

---

## Stage 1 — Research swarm

**Deterministic seed first.** Before spawning agents, run
`python3 -m traust.cli adapters checkov <target-dir> -o .threat-model-state/khs.json`
(skip and note when the target ships no Kubernetes YAML). Its
`tenancy_signals` block is machine-extracted section-3 material — CRDs
defined and CSV-owned/required (interfaces), webhooks with rules
(interception surfaces), structured RBAC grants, install modes, watch
scope, `InsecureSkipVerify` sites — which the Surface mapper and Infra
reader verify and extend rather than rediscover. Also look up the target
in `progress-tracker/metrics/repo-liveness.json` when present: an
`archived`/`missing` status is likelihood evidence for the
unmaintained-component threat class (CWE-1104 shape — no maintainer will
ship fixes; consumers inherit the exposure) and belongs in the Stage-3
scoring, plus the model's provenance notes.

Goal: gather everything needed to fill sections 1-3 and the vuln working table, in
parallel. Spawn the agents below **in a single batch** with the Task tool so
they run concurrently. Each agent gets a narrow brief, the absolute path to
`<target-dir>`, and the read-only restriction verbatim. Each returns a
structured text block; you synthesize in Stage 2.

Skip the swarm and run the briefs yourself sequentially if `<target-dir>` is
small (<50 source files) or `--depth recon` is set; the parallelism isn't
worth the overhead there.

| Agent | Brief | Returns |
|---|---|---|
| **Docs reader** | Read `README*`, `SECURITY.md`, `CHANGELOG*`, top-level `docs/`, and the build manifest (`setup.py` / `Cargo.toml` / `package.json` / `CMakeLists.txt`). Summarize what the project says it is, who uses it, and any security claims or fix entries it documents. | Prose system description; list of self-documented security fixes. |
| **Surface mapper** | Grep the source tree for entry-point signatures (table below). For each hit, name the surface, the file:function, and what crosses it. Include supply-chain surfaces (lockfiles, vendored deps, `curl \| sh` in build scripts). Bound the scan: exclude `vendor/`, `node_modules/`, `third_party/`, generated code; cap at ~5 representative hits per surface row. | Candidate section 3 rows: `{entry_point, kind, description, trust_boundary, file_refs, review_surfaces}` (`review_surfaces` only on rows from the review-surface kinds below). |
| **Infra reader** | Read deploy-time config: `*.tf`/`*.tfvars`, k8s manifests (`*.yaml` under `k8s/`/`deploy/`/`manifests/`), `Dockerfile*`, CI workflows, and any IAM/service-account/dataset-ACL files. For each, name (a) the identity it runs as and what that identity can reach, (b) any access grant not managed in this tree (ad-hoc IAM, hand-created SAs, missing column/policy tags), (c) credentials or principals that survive a migration or teardown. | Candidate section 3 rows for infra surfaces + candidate section 4 rows: `{threat, surface, asset}` where the config itself is the finding. |
| **Asset finder** | Identify what the code protects or produces: sensitive data it reads/writes (secrets, keys, user records, DBs), process integrity (always present for native code), service availability, and downstream embedder assets if it's a library. | Candidate section 2 rows: `{asset, description, sensitivity}`. |
| **History miner** | Two steps. **(a)** Glance at the build manifest and file extensions to identify language **and domain**, then derive 6-10 commit-message keywords specific to that stack on top of the base set `CVE- security vuln fix exploit`. Derive from what the code does, not from a lookup table; the three examples below illustrate the specificity bar, not coverage: native parser → `overflow OOB UAF integer`; web service → `injection SSRF IDOR traversal`; crypto → `timing constant-time nonce`. **(b)** `git -C <target-dir> log --all -i --grep='<base ∪ derived, \|-joined>' --oneline`, then read the full message + diff of each hit. Also grep any `issues/` or `bugs/` export in-tree. | Vuln rows: `{id (commit hash), title, component, class, vector}`. |
| **Advisory fetcher** | If `git -C <target-dir> remote get-url origin` is GitHub and `gh` is on PATH: `gh api /repos/{owner}/{repo}/security-advisories`. Otherwise return "no public advisory source". | Vuln rows: `{id (CVE/GHSA), title, component, class, vector}`. |
| **Vuln-file parser** | Only spawn if `--vulns <path>` was provided. Parse the file (newline CVE list, CSV, markdown report, or JSON array) into normalized rows. | Vuln rows: `{id, title, component, class, vector}`. |
| **Context ingester** | Only spawn if `--context <paths>` was provided. For each source: read it, extract security-relevant content per its type (endpoints/auth schemes from API specs; dependency inventory from SBOMs; identities/grants/network rules from IaC; prior threats + accepted risks from old threat models; findings + remediation state from SAR/pentest exports; topology from diagrams/docs). For each source, return a 1-2 line summary of what was extracted (so the orchestrator can confirm to the user), plus structured candidates. Report unreadable sources by exact path — never silently skip. Flag every doc-vs-code discrepancy found. | Per-source summaries; candidate section 2/3 rows; vuln rows `{id, title, component, class, vector}` from prior models/SARs; `conflicts: [{doc_says, code_does, where}]`. |

Surface-mapper grep targets (pass this table in its prompt). Treat the
"Look for" column as a **seed, not a checklist**: one concrete token per row
to set the specificity bar, then extend with the idioms of whatever
language/framework the target actually uses.

| Surface | Look for |
|---|---|
| Network | socket `listen`/`accept`/`bind`; HTTP route definitions (e.g., `@app.route`); RPC/gRPC/GraphQL service defs |
| File / format parsing | file-open calls (e.g., `open(`); format magic-byte checks; "parse"/"decode"/"load"/"unmarshal" function names |
| CLI / env | argv parsers (e.g., `argparse`); env reads (e.g., `getenv`) |
| Deserialization | language-native deserializers on external data (e.g., `pickle`, `ObjectInputStream`) |
| DB / query | raw query-string construction; ORM `.raw()`/`.query()` escapes |
| IPC / plugins | dynamic load (e.g., `dlopen`); subprocess spawn; `eval`/`exec` on config; dynamic import |
| Supply chain | dependency lockfiles; vendored libs; `curl \| sh` in build scripts |
| Infra / IAM | terraform `google_*_iam_*`/`aws_iam_*`; k8s `serviceAccountName`/WIF annotations; BigQuery dataset/table `access{}` blocks; secrets mounts |
| Credential verification / minting (`credential-acceptance`) | token verify or decode calls (e.g., `jwt.decode`); password and hash comparisons; session lookups; token signing and refresh or exchange endpoints |
| Ownership resolution (`ownership-resolution`) | lookups that tie an object to its owner by name rather than key (e.g., `LIKE`/`ILIKE` or prefix match on a name column) |
| Security config flags (`security-flags`) | settings defaults and environment fallbacks that switch a control (e.g., `DEBUG`, `verify=`, `insecure`/`skip_*` options); keys or secrets in shipped config |
| Outbound fetch (`outbound-fetch`) | server-side HTTP client calls whose destination someone other than the operator can influence: request input, config a lower-privileged role can edit, a value read from an unverified token (e.g., `requests.get(`); identity-provider discovery and key-set URLs; redirects the server follows. A destination only the operator sets, and links a user's browser follows, are not outbound fetches. |
| Shared content stores (`stored-content-integrity`) | digest-keyed or deduplicated blob storage; multipart or chunk assembly; server-side copy |
| LLM components (`llm-integration`) | the files `traust adapters llm-app` tags: model and agent-framework calls, MCP tool handlers, vector-store reads and writes, prompt templates |

The last six rows are review surfaces from
[review-surfaces.md](../../3-audit/secure-code-audit/review-surfaces.md);
the tag each one produces is in brackets. Tag every entry point those rows
produce with `review_surfaces`. The sixth surface, `scope-enforcement`, has no
row of its own: tag a Network entry point with it when the route sits behind
a role, scope or permission check, or when it acts on another user's data or
performs a privileged operation without one. Stage 4 walks every tagged
surface, and the audit's coverage diff reads the tags from the JSON.

**Checkpoint:** Write tool → `./.threat-model-state/_chunk.tmp`:

```json
{
  "stage": 1,
  "swarm": {
    "docs_reader": "<returned text block>",
    "surface_mapper": [ {entry_point, kind, description, trust_boundary, file_refs, review_surfaces} ],
    "infra_reader": { "surfaces": [...], "threats": [...] },
    "asset_finder": [ {asset, description, sensitivity} ],
    "history_miner": [ {id, title, component, class, vector} ],
    "advisory_fetcher": [ {id, title, component, class, vector} ],
    "vuln_file_parser": [ {id, title, component, class, vector} ],
    "context_ingester": { "sources": [...], "candidates": {...}, "vulns": [...], "conflicts": [...] }
  }
}
```

Then Bash:
`python3 -m traust.cli admin checkpoint save ./.threat-model-state 1 swarm --key stage --from ./.threat-model-state/_chunk.tmp`

This is the most expensive checkpoint — the swarm is the majority of the
mode's token spend. Agents that were skipped (no `--vulns`, no GitHub remote,
`--depth recon`) get an empty list/null. If the swarm was run inline
(small target), populate the same keys from your own sequential passes.

---

## Stage 2 — Synthesize

Goal: turn the swarm returns into `## 1-3` of the schema plus a vuln working
table. This stage runs in the orchestrating agent, not a subagent; it's the
join.

**Section 1: System context.** From the Docs reader's summary plus your own glance at
the tree layout, write 1-2 paragraphs: what it is, language, rough size, who
would embed or deploy it, where it would run.

**Section 2: Assets.** Take the Asset finder's rows (plus any Context-ingester
candidates). Dedupe, fill any obvious gaps (native code without "host process
integrity" → add it), assign `sensitivity`. Populate the optional
data-classification columns (`regulatory_scope`, `example_records` — see
schema.md) wherever the code or ingested docs make them discoverable: ORM
models and migrations name the fields; compliance annotations and ingested
SAR/architecture docs name the regimes. Leave a cell empty rather than guess
a regime.

**Doc-vs-code conflicts.** Each Context-ingester `conflicts` entry becomes a
candidate section 4 row (when the gap is itself an exposure — "docs say mTLS
between services; code dials plaintext") or a section 6 open question (when
it's ambiguity, not exposure). Never drop one silently.

**Section 3: Entry points & trust boundaries.** Merge Surface mapper + Infra reader
rows. Dedupe, name the trust boundary for each ("untrusted file → process
memory", "unauth HTTP → application logic", "namespace workload → WIF
identity"), and for each list which section 2 assets are reachable from it.
Supply-chain, build-time, and infra/IAM surfaces **are** entry points even
though no runtime input crosses them. **Every row here must get at least one
threat in Stage 3 or 4**; that's the coverage invariant the emit-time check
enforces.

**Vuln working table.** Concatenate rows from History miner + Advisory
fetcher + Vuln-file parser + Context ingester. Dedupe by `id`. For each row, decide which section 3
entry point it traversed; read the relevant source to confirm (e.g.,
"CVE-2026-29022 is in `drwav__read_smpl`, reached via the WAV file-parsing
entry point"). If a vuln's entry point isn't in section 3, the Surface mapper missed
one; add it now. Hold this table in your working notes; it does **not** go
into the model file verbatim. It becomes the `evidence` column in Stage 3.

**Checkpoint:** Write tool → `./.threat-model-state/_chunk.tmp`:

```json
{
  "stage": 2,
  "section1_context": "<markdown prose>",
  "section2_assets": [ {asset, description, sensitivity} ],
  "section3_entry_points": [ {entry_point, kind, description, trust_boundary, reachable_assets, review_surfaces} ],
  "vuln_table": [ {id, title, component, class, vector, entry_point} ]
}
```

Then Bash:
`python3 -m traust.cli admin checkpoint save ./.threat-model-state 2 synthesize --key stage --from ./.threat-model-state/_chunk.tmp`

---

## Stage 3 — Generalize: vulns → threats

Goal: cluster Stage-2 vulns into threat rows at the right abstraction level.

### 3a. Cluster

Group the Stage-2 vuln table by `(entry point, bug class, asset reached)`.
Each cluster becomes **one** candidate threat. Examples:

- 3 heap overflows + 1 integer overflow, all in WAV/FLAC parsers, all
  reaching process memory → **one** threat: "Memory corruption leading to RCE
  via untrusted audio file parsing". Evidence: all 4 IDs.
- 2 SQL injections in different endpoints → **one** threat: "Data exfiltration
  / tampering via SQL injection in HTTP API". Evidence: both IDs.

Apply the litmus test to each cluster's threat statement: would it still be
true after every listed evidence item is patched? If not, you're still at vuln
level; zoom out.

### 3b. Variant scan (raises likelihood)

For each cluster, look for **siblings**: code paths with the same shape that
weren't in the vuln list. Grep for the same pattern (other format parsers,
other endpoints calling the same unsafe helper, other size fields multiplied
without overflow checks). You are not trying to prove these are exploitable;
you are estimating how much of the surface shares the pattern. More siblings →
higher `ease_of_discovery` and `ease_of_exploit`.

Keep sibling locations in your working notes and surface them in the hand-back
(Stage 5, item 4). Do **not** put `file:func` references in the section 4 `evidence`
cell; evidence is for confirmed past vulns only. Sibling counts inform the
likelihood factors, not the evidence column.

### 3c. Rate

Rate each cluster with the OWASP Risk Rating Methodology. The factor
definitions and the JSON form are in the schema.md
[Scoring guide](schema.md#scoring-guide). For each cluster, assign:

- `actor`: from the entry point (file parsing → whoever supplies the file;
  network endpoint → `remote_unauth` or `remote_auth` depending on whether
  auth precedes it).
- `risk_rating`, scored factor by factor on the **technical** basis
  (bootstrap has no business context):
  - Impact factors come from the asset and the bug class. Memory corruption
    in a network service scores high on integrity and confidentiality; a
    leak of non-sensitive data scores low on everything.
  - Likelihood factors start from the evidence. A confirmed past vuln in
    this exact surface puts `awareness` high. A public exploit or active
    exploitation puts `ease_of_exploit` high too. Siblings found by 3b raise
    `ease_of_discovery`. The `actor` sets `population_size`.
  - Score the residual risk: lower the factors the controls below act on.
  - Give a reason for each factor that evidence or a control moved.
- `controls`: grep for mitigations relevant to the stack (size caps, input
  validation, sandboxing/seccomp; ASLR/stack-protector/CFI in native builds;
  parameterized queries / ORM; auth middleware / CSRF tokens / CSP; rate
  limiting; SecurityManager/JEP-411 replacements in Java; etc.). `none` if
  none found.
- `status`: `unmitigated` unless you found a control that fully closes it.
- `recommended_mitigation` (working notes, not a section 4 column): for each cluster,
  name **one class-level control** that would close or materially shrink the
  whole threat regardless of which instance is found next (e.g., "sandbox the
  decoder process", "parameterized queries everywhere", "drop `pickle` for
  `json`", "enable CSP `default-src 'self'`", "size-cap all length fields
  before allocation"). Prefer a control that survives the next bug over a
  patch for the last one. These become section 8 rows in Stage 5.

Write each cluster as a section 4 row.

**Checkpoint:** Write tool → `./.threat-model-state/_chunk.tmp`:

```json
{
  "stage": 3,
  "section1_context": "...",
  "section2_assets": [...],
  "section3_entry_points": [...],
  "section4_threats": [ {threat, actor, surface, asset, risk_rating, status, controls, evidence, review_surfaces} ],
  "mitigation_notes": [ {cluster, recommended_mitigation} ],
  "sibling_locations": [ {threat, locations: ["file:func", ...]} ]
}
```

Then Bash:
`python3 -m traust.cli admin checkpoint save ./.threat-model-state 3 generalize --key stage --from ./.threat-model-state/_chunk.tmp`

---

## Stage 4 — Gap-fill (the part past vulns can't give you)

Past vulnerabilities are biased toward what's already been found. A threat
model must also cover what hasn't. For **every section 3 entry point that has no section 4
row yet**, walk STRIDE and add at least the plausible ones:

| | For this entry point, could an attacker… |
|---|---|
| Spoofing | …pretend to be a trusted source? |
| Tampering | …modify data in transit or at rest? |
| Repudiation | …act without leaving attributable logs? |
| Info disclosure | …read data they shouldn't? |
| DoS | …exhaust a resource (CPU, memory, disk, connections)? |
| Elevation | …end up with more privilege than they started with? |

Also walk the entry points that **do** have rows: is the existing row the only
plausible threat, or are other STRIDE categories live too? (A file parser with
an RCE threat probably also has a DoS threat.)

For **infra/IAM entry points** (from the Infra reader), STRIDE maps less
cleanly than for code. Walk these instead:

- **Over-grant**: does the identity reach more than the app needs (whole
  dataset vs one table; project-level vs resource-level)?
- **Lateral identity**: can a co-located workload (same namespace, same node,
  same SA) assume this identity?
- **Drift**: is any grant managed outside this tree (click-ops IAM, ad-hoc
  ACL, unmanaged SA), so it won't be reviewed or torn down with the code?
- **Residual access**: do credentials or principals from a predecessor system
  survive the migration?
- **Column exposure**: does a broad table read expose identity/PII columns
  the app doesn't need?
- **Scope enforcement**: where an automated approval, merge, or write path
  exists, what bounds it to its intended scope (path allowlist, label,
  reviewer set)?

For **review-surface entry points** (tagged with `review_surfaces`), STRIDE
misses the classic defects, so also walk each tagged surface's check in
[review-surfaces.md](../../3-audit/secure-code-audit/review-surfaces.md):

- **credential-acceptance:** can a credential issued for another purpose
  (another audience, a short-lived or refresh token) pass this verifier, and
  does revocation actually stop it?
- **ownership-resolution:** can one owner's name match another owner's
  objects (unescaped wildcard, prefix), on read, rename and delete paths?
- **security-flags:** what does the shipped default do, does any reader of
  the flag switch a control off, and does a control fail open when it is
  unconfigured?
- **outbound-fetch:** who controls the destination, including through
  stored config or an unverified token, and is the guard applied to the
  address actually connected to?
- **stored-content-integrity:** are the bytes verified the bytes stored
  after assembly, and can one bad object reach other tenants through
  deduplication?
- **scope-enforcement:** does every route and credential type apply the
  scope check its siblings do?
- **llm-integration:** can untrusted text reach a prompt that can call
  tools, does model output reach a sink, and is each tool no broader than
  its task (the checks in
  [llm-application-review.md](../../3-audit/secure-code-audit/llm-application-review.md))?

Each plausible answer is a section 4 row tagged with only the surfaces
that threat exercises: a subset of the tags of the entry points its
`surface` names (their union, when it names several). A check on a tagged
surface that turns up nothing goes in `## 5. Deprioritized` with the reason,
tagged with that surface in `review_surfaces` (for example, threat "SSRF
through the proxy", reason "the destination host is set only by the
operator", `["outbound-fetch"]`). Untagged surfaces need no section 5 line.

**LINDDUN privacy overlay (conditional).** If section 2 contains
personal-data assets (PII, user records, identifiers, behavioral/audit
data about people), walk the data flows and stores touching those assets
through the seven LINDDUN categories — Linking, Identifying,
Non-repudiation, Detecting, Data disclosure, Unawareness, Non-compliance —
and add the plausible ones as section 4 rows with a leading `linddun:` tag
in the threat cell (schema.md section 4). Skip the overlay entirely when no
personal data is in scope; say so in one line. Do not run PASTA or OCTAVE —
their organizational stages duplicate the interview mode and the portfolio
segment graph.

Threats added in this stage have empty `evidence`. That's fine; score the
likelihood factors from technique prevalence and surface reachability alone. **The
final section 4 table must contain at least one row with empty evidence**, or this
stage didn't run.

Populate `## 5. Deprioritized` with STRIDE categories you considered and
ruled out, with the reason ("Repudiation: not applicable, no multi-user
actions"). These rows carry no `review_surfaces` unless the ruled-out
threat sits on a review surface.

**Checkpoint:** Write tool → `./.threat-model-state/_chunk.tmp`:

```json
{
  "stage": 4,
  "section1_context": "...",
  "section2_assets": [...],
  "section3_entry_points": [...],
  "section4_threats": [ {...stage3 rows + gap-fill rows with empty evidence} ],
  "section5_deprioritized": [ {threat, reason, review_surfaces} ],
  "mitigation_notes": [...],
  "sibling_locations": [...]
}
```

Then Bash:
`python3 -m traust.cli admin checkpoint save ./.threat-model-state 4 gap-fill --key stage --from ./.threat-model-state/_chunk.tmp`

---

## Stage 5 — Emit

**Coverage check (do this before writing the file).** For every section 3 entry
point, confirm at least one section 4 row names it in the `surface` column. Match on
the entry-point's name string, not the concept; the downstream scorer is a
text match. Any section 3 row with zero section 4 coverage means Stage 4 was incomplete; go
back and add the missing threat now.

Run `python3 -m traust.cli reporting rate-threats <repo>-threat-model.json`
to fill in every rating's scores, levels and severity. Then sort section 4
by severity, impact score and likelihood score, all descending. Assign
`id` = `T1`, `T2`, … in sorted order.

**Section 1 layering.** Open with the 1-2 paragraph jargon-free executive
summary (schema.md section 1: top 2-3 threats in plain language + the single
most important action — write it after section 4 is final), then the
technical context prose. Close the section with a `### Threat actor
landscape` subsection: pick 2-4 personas from the schema.md list and give
each one sentence of motivation derived from **this system's** assets
("holds pull-secrets for fleet clusters → supply_chain and apt are
primary"). The personas are prose color; the section 4 `actor` column stays
the access-position enum.

**Section 9 attack scenarios.** For the top 3-5 threats by severity, write one `### Tn — <threat text>` subsection each:
3-5 present-tense sentences telling the attack as a story — persona, path
(name the section 3 entry point), concrete impact, and one sentence on why
current controls don't stop it. Writing bar per schema.md: readable by a
non-technical VP, no jargon, no file:line.

Populate `## 6. Open questions` with everything the code couldn't tell you:

- Deployment context ("Is this exposed to the network or only local?")
- Intended actors ("Who supplies the input files in practice?")
- Controls you couldn't verify ("Is there a WAF / sandbox / size limit
  upstream of this?")
- Risk appetite ("Is DoS acceptable for this use case?")

These seed a later `/threat-model interview --seed <model-file>`
pass.

Populate `## 8. Recommended mitigations` from the Stage-3c working notes: one
row per class-level `mitigation`, listing the `threat_ids` it covers, whether
it `closes_class` (yes/partial), and required `effort` per schema.md section 8:
a canonical size when supported, or JSON `null` when unknown. Record
`blocked_external` independently only when known; otherwise omit it, not
`false`. If two clusters are closed by the same control, emit one row with
both clusters' ids. Gap-fill threats from Stage 4 get rows here too where
an obvious class-level control exists.

**Emit the JSON, then render.** Compose `<target-dir>/<repo>-threat-model.json`
against `threat-model.schema.json`, exactly as SKILL.md *Step 2 — Shared
output contract* describes: each `## N.` section above is a field of that
document (`system_context`, `assets`, `entry_points`, `threats`,
`deprioritized`, `open_questions`, `mitigations`, `attack_scenarios`), not
Markdown to assemble. Never hand-author the `.md`.

Set `provenance`:

```json
{"mode": "bootstrap", "date": "<today>",
 "target": "<target-dir> @ <git rev-parse --short HEAD, or \"not a git repo\">",
 "inputs": "<--vulns path; --context paths; or \"git-log + CHANGELOG mined\">",
 "harness_version": "<VERSION file semver>-<harness git short SHA>"}
```

Leave `owner` out: bootstrap has no owner, and the schema treats an absent
owner as unset.

**Validation gate.** The run is not complete until the same three commands
every artifact uses pass:

```bash
python3 -m traust.cli reporting rate-threats <repo>-threat-model.json
python3 -m traust.cli reporting validate <repo>-threat-model.json
python3 -m traust.cli reporting render   <repo>-threat-model.json -o <repo>-threat-model.md
```

Fix every error `validate` reports and re-run until it passes with 0 errors;
nothing is rendered from an invalid artifact. A large model can be built in
pieces under `./.threat-model-state/` (one `_chunk.tmp` per section, merged
into the JSON), so a stalled step loses one section, not the model.

**Checkpoint (final):** After the JSON validates and the `.md` is rendered, Bash:
`python3 -m traust.cli admin checkpoint done ./.threat-model-state 5 --key stage`

Hand back to the user:

1. Paths to the JSON artifact and its rendered `.md`.
2. Top 5 threats (id, threat, severity).
3. Count of threats with evidence vs without (shows gap-fill ran).
4. Stage-3b sibling locations as candidate leads for `/vuln-scan` or the
   pipeline `find` stage.
5. The section 8 recommended mitigations, top 3 by (closes_class, known
   effort in size order). Keep unknown effort separate, never cheapest;
   carry any reported external-blocking state with each recommendation.
6. The section 6 open questions, framed as "ask the owner".
7. If `--context` was used: per-source one-line ingestion summaries and any
   doc-vs-code conflicts recorded (so the user can course-correct a
   mis-parsed source).
8. The `reporting validate` result line.
