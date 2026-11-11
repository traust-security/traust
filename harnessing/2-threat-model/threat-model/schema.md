# Threat-model file schema

> **Re-read note:** If you need this file mid-session and the Read tool
> reports "file unchanged", the prior result was evicted from context; reload
> with `cat .claude/skills/threat-model/schema.md` via Bash.

Both `/threat-model interview` and `/threat-model bootstrap` author
`<target-dir>/<repo>-threat-model.json`, then render its `.md` companion
(naming rule in `SKILL.md`; portfolio copies under
`analysis-results/findings/` may be branch-suffixed and carry the identical
contract). `THREAT_MODEL.md` is the legacy read name; the skill never
authors it. The section headings and table columns below describe the
rendering and legacy read format. New JSON follows the schema's
`#/$defs/canonical_write` contract; historical read acceptance is broader.

---

## Required sections, in order

```markdown
# Threat Model: <system name>

## 1. System context

## 2. Assets

## 3. Entry points & trust boundaries

## 4. Threats

## 5. Deprioritized

## 6. Open questions

## 7. Provenance

## 8. Recommended mitigations

## 9. Attack scenarios

## 10. Tenant boundaries

## 11. Risk ratings
```

A consumer that only needs the threat table can regex for `^## 4\. Threats$`
and read until the next `^## `. Sections 8, 9, 10, and 11 are optional and
additive: older threat models may omit them, and consumers must tolerate
their absence. Section 10 applies **only to multi-tenant services** —
single-tenant targets never carry it. Section 11 is present exactly when
section 4 carries OWASP-rated threats, and the renderer writes it.

**Deterministic gate:** follow SKILL.md *Step 2 — Shared output contract*
to validate the JSON before rendering and recording it. `python3 -m
traust.cli reporting lint` checks legacy prose models (sections, table
columns, enums, coverage, provenance and evidence hygiene); it is not a
substitute for the canonical-write contract.

---

## Section contents

### 1. System context

Prose, in two parts:

1. **Executive summary first** (new emissions): open with 1-2 short
   paragraphs readable by a non-technical leader — what the system is, the
   top 2-3 threats in plain language, and the single most important action.
   No jargon: "an attacker could steal customer payment details through a
   flaw in the search feature", not "STRIDE-identified information
   disclosure via SQLi".
2. Then one to three paragraphs of technical context: what the system is,
   what it does, who uses it, where it runs. This is the answer to "what are
   we working on?".

Optionally end the section with a **threat actor landscape** subsection:

```markdown
### Threat actor landscape
```

2-4 personas from {`apt`, `organized_crime`, `malicious_insider`,
`negligent_insider`, `hacktivist`, `opportunistic`, `competitor`,
`supply_chain`}, each with **one sentence of system-specific motivation**
derived from the assets table ("this operator holds cluster-admin
credentials for fleet clusters → supply-chain and APT personas are
primary"). The persona layer is prose color for humans; the section 4
`actor` column (access position) remains the scoring input. Never replace
the `actor` enum with persona names.

### 2. Assets

Markdown table. One row per thing worth protecting.

| asset | description | sensitivity |
|---|---|---|

`sensitivity` ∈ {`low`, `medium`, `high`, `critical`}.

Two optional columns may be **appended** (data classification; new
emissions should populate them when the information is discoverable):

| asset | description | sensitivity | regulatory_scope | example_records |
|---|---|---|---|---|

- `regulatory_scope`: comma-separated regimes governing the asset (`GDPR`,
  `CCPA`, `HIPAA`, `PCI-DSS`, `SOX`, `export-control`, …) or `none`.
- `example_records`: concrete field or record names ("name, email,
  address"; "kubeconfig, pull-secret").

Consumers address columns by header, so appended columns are safe; never
insert columns between the original three. Beyond report quality, tenancy
and data-sensitivity context here feeds the same `tenancy_profile`
derivation the ledger emitter uses for hardening λ weights.

### 3. Entry points & trust boundaries

Markdown table. One row per place untrusted input enters the system or
privilege level changes.

| entry_point | description | trust_boundary | reachable_assets |
|---|---|---|---|

`trust_boundary` is free text naming the crossing (e.g. "untrusted file →
process memory", "unauth network → authenticated session").
`reachable_assets` is a comma-separated list of asset names from section 2.

### 4. Threats

Markdown table. **This is the threat model proper.** One row per
actor-wants-outcome pair, at the abstraction level where it survives a patch.

Threats are rated with the **OWASP Risk Rating Methodology** (see
[Scoring guide](#scoring-guide)). A rated model's table carries
`severity | likelihood | impact` where legacy models carry
`impact | likelihood`:

| id | threat | actor | surface | asset | severity | likelihood | impact | status | controls | evidence | attack_refs |
|---|---|---|---|---|---|---|---|---|---|---|---|

- `severity` ∈ {`critical`, `high`, `medium`, `low`, `note`}, or
  `unrated` for a threat whose rating hasn't been done yet.
- `likelihood`: `<level> <score>`, e.g. `medium 4.375`.
- `impact`: `<level> <score> <basis>`, e.g. `high 7.25 technical`.
- An `unrated` row writes its legacy labels as `legacy <label>`
  (`legacy possible`, `legacy critical`).

You never type these cells. You author the factor scores in the JSON
(`risk_rating`), `traust reporting rate-threats` computes the scores,
levels and severity, and `render` writes the table and section 11. The
linter recomputes every rating from section 11 and fails a row that
disagrees.

The legacy table below is what models written before the OWASP rating
carry. It stays valid until the model is next updated:

| id | threat | actor | surface | asset | impact | likelihood | status | controls | evidence | attack_refs |
|---|---|---|---|---|---|---|---|---|---|---|

The trailing `attack_refs` column is **default for new emissions** (harness
≥ 0.82.0 — the lint gate errors on a ten-column table whose provenance
carries a ≥ 0.82.0 harness version). Legacy ten-column models remain
valid; `update`/`review` passes must not renumber or reorder rows, and add
the column only when they emit a new file version anyway.

A second trailing column, `isolation_dimensions`, is **optional** (never
default) and appears only after `attack_refs`, only in models of
multi-tenant services that carry a section 10:

| id | threat | actor | surface | asset | impact | likelihood | status | controls | evidence | attack_refs | isolation_dimensions |
|---|---|---|---|---|---|---|---|---|---|---|---|

Two more optional trailing columns, `owasp_llm_references` and then
`atlas_refs`, come last (after `review_surfaces` when present), either or
both, and only when a threat against an LLM, agent or MCP component has
values: OWASP Top 10 for LLM Applications category IDs (`LLM01`…) and MITRE
ATLAS technique IDs (`AML.T0051`), the latter validated against the pinned
ATLAS table.

- `id`: `T1`, `T2`, … Stable across edits; do not renumber when rows are
  removed. In `update`/`review` passes a removed threat's id is **retired,
  never reused**: the row moves to section 5 with the removal reason and
  date, and the next new threat takes the next never-used number.
- `threat`: One sentence, active voice, names the outcome. "Remote code
  execution via untrusted media parsing", not "buffer overflow in dr_wav".
  Rows produced by the optional LINDDUN privacy overlay carry a leading
  `linddun:` tag in this cell (e.g., "linddun: re-identification of tenants
  via correlated audit-log exports") so a reviewer can trace which pass
  produced them.
- `actor`: one or more of {`remote_unauth`, `remote_auth`,
  `adjacent_network`, `local_user`, `local_admin`, `supply_chain`,
  `insider`}, comma-separated when a threat is reachable from more than
  one position (e.g. `remote_auth, insider`). List the weakest-position
  actor first; scoring reads the first entry.
- `surface`: Which entry point(s) from section 3 this threat traverses.
- `asset`: Which asset(s) from section 2 this threat compromises.
- `impact` (legacy tables only) ∈ {`low`, `medium`, `high`, `critical`,
  `existential`}.
- `likelihood` (legacy tables only) ∈ {`very_rare`, `rare`, `possible`,
  `likely`, `almost_certain`}.
- `status` ∈ {`unmitigated`, `partially_mitigated`, `mitigated`,
  `risk_accepted`}.
- `controls`: Current mitigations, or `none`.
- `evidence`: CVE IDs, issue links, pentest finding IDs, or git commit
  hashes that **instantiate** this threat. May be empty. **Evidence raises
  likelihood (the awareness, ease-of-discovery and ease-of-exploit
  factors); it is not the threat.**
- `attack_refs` (default column for new emissions; absent only in legacy
  models): comma-separated MITRE ATT&CK technique IDs (`T1611`,
  `T1552.007`) naming the adversary behavior the threat describes. **Bounded selection, not narrative**: IDs must exist and be
  non-revoked/non-deprecated in the harness's pinned ATT&CK table — check
  with `traust attack validate <ids>`; sub-technique preferred over parent when one fits;
  2 IDs is typical, more than 4 means the threat row is too broad — split
  it. Leave the cell empty rather than guessing: the `/attack-coverage`
  roll-up treats an explicit ID as *modeled* coverage, so a wrong ID
  pollutes the fleet heat-map. ATT&CK(R) content is (c) The MITRE
  Corporation, used with attribution.
- `isolation_dimensions` (optional trailing column; multi-tenant services
  with a section 10 only): comma-separated subset of the five
  isolation-hardening dimension keys — `privilege`, `encryption`,
  `authentication`, `connectivity`, `hygiene` (same vocabulary as
  `contracts/schemas/isolation-review.schema.json`) — tagging which dimension(s) the
  threat stresses. Empty cell valid: not every threat in a multi-tenant
  model is an isolation threat. The `/threat-register` roll-up reads the
  tags to rank the fleet's weakest tenant boundaries.

Sort the table so the top rows are the priorities: by severity, then
impact score, then likelihood score, all descending, with any `unrated`
rows last. Legacy tables sort by (impact, likelihood) descending.

### 5. Deprioritized

Markdown table. Threats considered and explicitly parked.

| threat | reason |
|---|---|

Common reasons: out of scope, actor not in threat model, asset not present,
risk accepted by owner.

### 6. Open questions

Bullet list. Things the mode could not determine. For `bootstrap` these are
questions for a human owner; for `interview` these are claims the owner made
that were not verifiable in code.

### 7. Provenance

```markdown
- mode: interview | bootstrap | bootstrap-then-interview
- date: YYYY-MM-DD
- target: <path or repo url @ commit>
- inputs: <design doc path | --vulns path | --context paths | "none">
- owner: <name, for interview> | <unset, for bootstrap>
- harness_version: <semver>-<short sha>
```

`harness_version` is required for new emissions and marks the schema/
taxonomy epoch, exactly like `metadata.harness_version` in audit reports
and `triage_context.harness_version` in triage artifacts — read the semver
from the harness `VERSION` file and append the short git SHA. Legacy
artifacts predate it; the linter warns rather than errors on its absence.

When an `update` or `review --apply` pass modifies the file, append an
**update history** table inside this section (additive; `mode` keeps the
original value):

```markdown
### Update history

| date | changes | reason |
|---|---|---|
| YYYY-MM-DD | Retired T3, added T12, T5 likelihood 6.1→4.9 (auth now required) | review vs HEAD abc1234 |
```

### 8. Recommended mitigations

Optional, additive: older threat-model files may omit this section, and
consumers must tolerate its absence. Each row is **one class-level control**,
not a per-finding patch: a mitigation that closes or materially shrinks an
entire threat cluster regardless of which instance is found next.

```markdown
| mitigation | threat_ids | closes_class | effort |
|---|---|---|---|
```

- `mitigation`: imperative, one line (e.g., "sandbox the decoder process",
  "parameterized queries everywhere", "drop pickle for json", "enable CSP
  default-src 'self'", "size-cap all length fields before allocation").
- `threat_ids`: comma-separated section 4 ids (e.g., `T1,T3`) this mitigation covers.
- `closes_class`: `yes` | `partial` | `no` (`no` = worthwhile
  defense-in-depth that does not close the class).
- `effort`: required in the JSON, even when unknown. New emissions use
  `xs` | `s` | `m` | `l` | `xl`, or JSON `null` for an unknown size.
  These are ordered size labels, not duration bands; do not invent hour,
  day or sprint thresholds. Unknown is not a size and must never rank
  ahead of known sizes as the cheapest recommendation.
- `blocked_external`: independent optional boolean in the JSON. Use
  `true` for a known external block, `false` for known absence of one, and
  omit the field when unknown. Never substitute a blocking label for
  `effort`, infer blocking from the size, or default unknown blocking to
  `false`. The rendering may carry it as an optional trailing column;
  preserve a reported boolean when displaying or deriving recommendations,
  and distinguish unknown from `false`.

The source of truth is the
[mitigation-effort registry](https://github.com/traust-security/traust-contracts/blob/development/enums/v1/mitigation-effort.json)
and the threat-model schema's `#/$defs/canonical_write` contract.
Historical `XS`, `S`, `M`, `L` remain readable; their only approved
replacements in freshly authored canonical output are respectively `xs`,
`s`, `m`, `l`. This is an exact alias mapping, not arbitrary lowercasing.
Do not rewrite stored historical artifacts. Unknown effort is JSON
`null`, not an omitted key or a guessed size. The rendered unknown marker
is `-` for size or blocking; it is not a size estimate or a known `false`.

Cells containing a literal `|` (regex alternations, `\|\| true`) must
escape it as `\|` per GFM — an unescaped pipe fractures the row for every
table consumer, not just the linter.

### 9. Attack scenarios

Optional, additive: older files may omit it, and consumers must tolerate its
absence. **New emissions should include it** for the top 3-5 threats by
severity. This is the narrative layer for humans — the tables
above remain the machine contract.

One subsection per scenario, heading anchored to the section 4 id:

```markdown
### T1 — <threat text from section 4>

<3-5 sentences, present tense, describing the attack as it unfolds: who the
attacker is (persona if a landscape subsection exists, otherwise the actor
position), the path taken (name the section 3 entry point), and the impact
in concrete terms — "reads every tenant's pull-secret", not "data breach".
Close with one sentence on why current controls don't stop it (or how far
they get).>
```

Writing bar: readable by a non-technical VP; no framework jargon, no CWE
numbers. `file:line` citations stay out of section 9 for the same reason
they stay out of `evidence` — narratives must survive a patch.
`/generate-team-report` lifts this section verbatim into team packages.

### 10. Tenant boundaries

Optional, additive — and **only for multi-tenant services** (a service where
distinct customers/tenants share running instances or data paths).
Single-tenant targets must omit it; older models may omit it regardless, and
consumers must tolerate its absence. One row per interface through which a
tenant drives input into the service or through which tenant data flows.
The vocabulary is deliberately shared with the `isolation-review` skill
(`contracts/schemas/isolation-review.schema.json`) so boundary rows and full
service-level isolation reviews line up. The lens is informed by **PEACH**,
Wiz Research's tenant-isolation methodology
([peach.wiz.io](https://peach.wiz.io)), applied **by reference only** —
cite it by name/URL; never copy or adapt its rubric text, tables, or
examples into a model (the python3 -m traust.cli check content-licenses fingerprint
gate fails the pre-push hook on re-imported adapted text; all wording here
is original to this repository).

```markdown
| boundary_id | interface | kind | exposure | complexity | privilege | encryption | authentication | connectivity | hygiene | threat_ids | isolation_review_ref |
|---|---|---|---|---|---|---|---|---|---|---|---|
```

- `boundary_id`: `IF-1`, `IF-2`, … — stable, never renumbered or reused
  (same discipline as section 4 threat ids). When a full isolation review
  exists, keep ids aligned with its `interfaces[].id` values.
- `interface`: the interface's name (e.g. "cluster provisioning API").
- `kind` ∈ {`api`, `data-store`, `queue`, `ingress`, `webhook`, `cli`,
  `other`}.
- `exposure` ∈ {`public`, `tenant`, `partner`, `internal`} — `public` is
  reachable without tenant credentials; `internal` is operator/control-plane
  only but carries tenant data.
- `complexity` ∈ {`low`, `medium`, `high`} — how much leverage a malicious
  tenant gets from the input the interface accepts (rating criteria in
  `harnessing/3-audit/isolation-review/SKILL.md`).
- `privilege` / `encryption` / `authentication` / `connectivity` /
  `hygiene`: the five isolation-hardening dimension results, each ∈
  {`yes`, `partial`, `no`, `na`} — the same result vocabulary the
  isolation-review skill scores with (dimension definitions live there;
  a threat model states results, the full review carries the evidence).
- `threat_ids`: comma-separated section 4 ids the boundary's weaknesses
  instantiate (may be empty). This is the join the `/threat-register`
  roll-up uses to attach boundary context to register rows.
- `isolation_review_ref`: empty, or the
  `analysis-results/isolation/<service-slug>/` directory of the full
  `/isolation-review` artifact when one exists.

### 11. Risk ratings

Written by `render` whenever section 4 carries a rated threat; never
hand-authored. It opens with a one-line citation of the method, then has
one subsection per rated threat, headed with its id and severity, holding
every factor score and its reason:

```markdown
### T1 — high

| factor | score | reason |
|---|---|---|
| skill_level | 5 | |
| awareness | 9 | the decoder's overflow history is public |
```

Rows follow the method's order: the eight likelihood factors, the four
technical-impact factors, then the four business-impact factors when the
rating has them. `reason` may be empty. The linter recomputes each
rating from these rows and fails it if the severity, levels or scores in
section 4 don't follow.

---

## Scoring guide

Threats are rated with the **OWASP Risk Rating Methodology** (OWASP
Foundation, <https://owasp.org/www-community/OWASP_Risk_Rating_Methodology>;
licence terms in `docs/external-dependencies.md`). This guide restates the
method in original wording and
adds how to apply it to a threat model. It doesn't reproduce the
method's example scales; read the source for those. The arithmetic lives
in `traust_contracts.v1.risk_rating`, and the harness does it for you.

### How the rating is built

1. Score each factor below from **0 to 9**. Higher always means more
   likely, or more harmful.
2. **Likelihood** is the mean of the eight likelihood factors, and
   **impact** is the mean of the four impact factors on the chosen basis.
3. Each mean becomes a **level**: below 3 is `low`, below 6 `medium`,
   otherwise `high`.
4. **Severity** combines the two levels:

   | impact ↓ / likelihood → | low | medium | high |
   |---|---|---|---|
   | **high** | medium | high | critical |
   | **medium** | low | medium | high |
   | **low** | note | low | medium |

Score the **residual** risk, after the controls the threat's `controls`
cell names. A control earns its effect only where you can point to it.

### Likelihood factors

Who would attack (the threat agent):

- `skill_level`: how skilled the most capable group likely to attempt
  this is. A population that includes practised attackers scores high; a
  threat only an unskilled user would try scores low.
- `motive`: how much that group stands to gain. Direct payoff (money,
  credentials, a foothold in other tenants) scores high; little or no
  reward scores low.
- `opportunity`: how little access and resource the attack needs. Nothing
  beyond network reach scores high; a need for insider position, special
  hardware or long preparation scores low.
- `population_size`: how many people are in a position to try. The
  `actor` column is the guide: `remote_unauth` is the whole internet and
  scores high, while `local_admin` or `insider` is a small trusted group
  and scores low.

How exposed the weakness is (the vulnerability):

- `ease_of_discovery`: how easily an attacker finds the weakness. Tooling
  or a scanner that finds it scores high; finding it only with source
  access and deep study scores low.
- `ease_of_exploit`: how easily an attacker turns it into the outcome. A
  public exploit or a trivially scriptable path scores high; a purely
  theoretical path scores low.
- `awareness`: how widely known this class of weakness is for this
  surface. Past CVEs, advisories or public write-ups on the same surface
  score high; an obscure, unpublished issue scores low.
- `intrusion_detection`: how likely an attempt goes unnoticed. No
  logging scores high; logged but unwatched scores somewhat lower; active
  detection with response scores low.

Evidence in the `evidence` cell raises `awareness`, `ease_of_discovery`
and `ease_of_exploit`. It doesn't change who the attacker is. A control
lowers the factor it acts on: authentication shrinks `population_size`
and `opportunity`, and alerting lowers `intrusion_detection`.

### Impact factors

Technical impact (what the attack does to the system and its data):

- `confidentiality`: the volume and sensitivity of what an attacker gets
  to read. Anchor it on the section 2 `sensitivity` of the assets the
  threat reaches: a critical asset exposed in bulk scores high.
- `integrity`: the extent of data, configuration or code an attacker can
  change, weighted by how much damage the change does.
- `availability`: the share of the service an attacker can take down, and
  how much users depend on that part.
- `accountability`: whether the attacker's actions can be traced back to
  them. Actions nobody can attribute score high; actions tied to a named
  identity score low.

Business impact (what the attack costs the organization):

- `financial`: direct and recovery cost.
- `reputation`: damage to trust in the product or the organization.
- `non_compliance`: exposure to regulatory or contractual breach. Use the
  section 2 `regulatory_scope`.
- `privacy`: how much personal information could be exposed.

**Choosing the basis.** The method prefers business impact when you know
it. Use `technical` unless the owner has told you the business stakes:
bootstrap runs are technical, and interview runs are business when the
owner answered the business questions. You may record business factors
beside a technical basis. The basis decides which set sets the score.

### Reasons

Give a one-line reason (the rating's `rationale`, keyed by factor name)
for every factor that evidence, a control or an owner statement moved.
Leave the others empty. A reviewer should be able to check each unusual
score without re-running the analysis.

### Authoring a rating in the JSON

Write the factors, the basis and the reasons, and nothing derived:

```json
"risk_rating": {
  "method": "owasp-risk-rating",
  "likelihood": {"factors": {"skill_level": 5, "motive": 2, "opportunity": 7,
    "population_size": 1, "ease_of_discovery": 3, "ease_of_exploit": 6,
    "awareness": 9, "intrusion_detection": 2}},
  "impact": {"basis": "technical", "technical": {"confidentiality": 9,
    "integrity": 7, "availability": 5, "accountability": 8}},
  "rationale": {"awareness": "the decoder's overflow history is public"}
}
```

Then run `python3 -m traust.cli reporting rate-threats <repo>-threat-model.json`.
It fills in every score, level and severity. `validate` rejects a
rating whose derived values disagree with its factors, so never edit
them by hand. A rated threat carries no legacy `impact` or `likelihood`.

### Models rated before the OWASP method

Older models carry the legacy labels (impact `low`..`existential`,
likelihood `very_rare`..`almost_certain`). Those labels were not a
published standard and don't convert to OWASP scores. **Any pass that
writes a new version of a model (`update`, or `review --apply`) rates
every threat that lacks `risk_rating` and drops its legacy labels.** The
whole model moves at once, so a table never mixes the two scales for
long. Until then, fleet roll-ups order legacy threats beside rated ones
with a fixed crosswalk (traust-core's threat-register view) and mark
them `legacy-crosswalk`. That crosswalk orders threats; it isn't a
rating.

---

## Example (excerpt)

```markdown
## 4. Threats

| id | threat | actor | surface | asset | severity | likelihood | impact | status | controls | evidence | attack_refs |
|---|---|---|---|---|---|---|---|---|---|---|---|
| T1 | Memory corruption leading to RCE via untrusted audio file parsing | remote_unauth | dr_wav/dr_flac decoders | host process integrity | critical | high 7.25 | high 8 technical | unmitigated | none | CVE-2026-29022, CVE-2025-14369 | T1203 |
| T3 | Supply-chain compromise of vendored single-header dependency | supply_chain | build pipeline | host process integrity | high | medium 4.25 | high 8.25 technical | partially_mitigated | pinned commit |  | T1195.001 |
| T2 | Denial of service via resource exhaustion on decode | remote_unauth | dr_flac decoder | service availability | medium | high 6.375 | low 2.5 technical | unmitigated | none | CVE-2025-14369 | T1499 |

<!-- sections 5-10 omitted -->

## 11. Risk ratings

Rated with the [OWASP Risk Rating Methodology](https://owasp.org/www-community/OWASP_Risk_Rating_Methodology) (OWASP Foundation). Each factor is scored 0-9; likelihood and impact are the means of their factors.

### T1 — critical

| factor | score | reason |
|---|---|---|
| skill_level | 6 |  |
| motive | 5 |  |
| opportunity | 8 |  |
| population_size | 9 | any uploader on the internet |
| ease_of_discovery | 7 |  |
| ease_of_exploit | 6 |  |
| awareness | 9 | two public CVEs in these decoders |
| intrusion_detection | 8 |  |
| confidentiality | 9 |  |
| integrity | 9 |  |
| availability | 7 |  |
| accountability | 7 |  |

<!-- T3 and T2 follow in the same form -->
```

T1 stays in the model after both CVEs are patched: attackers will still send
malformed audio files. The CVEs are evidence the surface is fertile, not the
threat itself.
