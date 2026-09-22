# The Disposition Ledger — Design and Rationale

**Audience.** Anyone trying to understand how the harness remembers what
it believes. This document explains the *why* behind the disposition
ledger — the reasoning that produced the design — rather than operating
instructions ([track-findings SKILL.md](../harnessing/4-triage/track-findings/SKILL.md));
the triage-to-ledger wiring is §6b.
For the full pipeline picture, start with
[artifacts.md](artifacts.md).

---

## 1. The problem the ledger solves

An audit produces *claims*: "this code path is vulnerable." Those claims
then live for months while many parties weigh in — a developer comments
on a merge request, a Jira ticket gets resolved, an adversarial triage
run refutes three findings, a fuzzer reproduces a crash, a human
countersigns a dismissal. Each of those actors has different
reliability, arrives at a different time, and sometimes they disagree.

Without a designed record, the answer to "what do we currently believe
about finding X, and why?" degrades into archaeology across MR threads,
ticket histories, and report versions — and worse, the record becomes
*editable*, which means both honest mistakes and deliberate manipulation
can silently rewrite what the portfolio believes about its own risk.

The disposition ledger is the harness's answer: **one append-only event
log per audited repository** (`*-findings-layer.json`), from which every
"current state" is *derived* — never stored, never hand-edited.

## 2. Design tenets

Everything else in this document follows from six decisions:

1. **Append-only.** Events are never edited or deleted; a correction is
   a new event. This buys tamper-evidence (an edited event breaks its
   own hash), full auditability (both sides of every disagreement remain
   visible), and time travel (any past state reconstructs by replaying
   only the events before a date).

2. **Events, not state.** The ledger stores *what happened*; the current
   disposition is computed by pure code
   (`src/traust/cli/build_cumulative.py`). The model gathers
   and interprets sources; deterministic code decides state. Ten reruns
   give ten identical outputs, so dashboards are reproducible and
   arguments about "what the number was" have a mechanical answer.

3. **Attribution always.** Every event names its actor — a human
   (identity-verified where it matters) or a machine (`triage/0.27.0`,
   `validate-findings`). Anonymous determinations don't exist, which is
   what makes accountability signals (like per-identity FP-override
   rates) possible at all.

4. **Evidence strength beats actor authority.** When determinations
   conflict, the *kind* of evidence decides, not who spoke last or who
   outranks whom organizationally (§5).

5. **Asymmetric caution.** Wrongly confirming a finding wastes
   attention; wrongly dismissing one silently deletes real risk from the
   record. The machinery therefore makes dismissal categorically harder
   than confirmation (§6).

6. **Determinism at metric time.** Anything a metrics job needs — risk
   weights, tenancy profiles, event identity — is resolved and recorded
   *when the event is written*, never re-derived during replay. No model
   call ever sits inside a dashboard build.

## 3. Anatomy of the ledger

### Where ledgers live

One ledger annotates one audit report, and it lives **next to the report
it annotates** in the findings store:

```
analysis-results/findings/<product>/<repo>/
├── <repo>-security-audit.json        ← the audit baseline (claim-hashed, §10; see below)
├── <repo>-security-audit.md          ← derived rendering of the JSON
├── <repo>-findings-layer.json        ← THE LEDGER (append-only events)
└── <repo>-findings-current.{json,md} ← derived cumulative report (cache)
```

Container-image audits (`/secure-container-audit`) are baselines too,
and they share the code audit's directory
(`findings/<product>/<image>/`). Their ledger artifacts therefore keep
the **full report stem** so nothing collides with the code audit's
companions:

```
├── <image>-container-audit.json                        ← baseline
├── <image>-container-audit-findings-layer.json         ← its ledger
└── <image>-container-audit-findings-current.{json,md}  ← its cumulative
```

Cloud-config audits (`*-cloud-config-audit.json`, own tree, no
collision risk) keep the short `<target>-findings-layer.json` naming.

### "Immutable" means *fixed for a commit*, not *never written*

Earlier revisions of this document called the baseline "immutable", which was
misleading in both directions and is worth stating precisely:

- **Only `/secure-code-audit`, `/secure-rpm-audit` and `/secure-container-audit`
  may write one.** Every other producer writes a ledger layer. Enforced by
  alignment gate **A15**, not convention.
- **They do rewrite it** — a re-audit cuts a fresh baseline at a new commit, and
  `rebaseline()` re-points the layer at it. What is fixed is the claim set *for a
  given commit*, which is what `metadata.claim_hashes` pins.
- **It was not honoured until 2026-08-17.** Three producers
  (`impact-analysis`, `verify-remediation`, `vuln-scan`) had appended findings
  directly into baselines — mutating the claim set with no event
  recording it, which breaks tenet 2 and bypasses the rescan router's authority
  over when a new baseline is cut. It went unnoticed because the code called the
  write "the sanctioned-append flow" while this document called the baseline
  immutable, and no gate checked either claim.

A finding discovered *between* audits therefore rides on its event
(`event.finding`, §10c), and `build_cumulative` unions it back at replay. See
[findings-routing.md](findings-routing.md) for the producer side.

Because the campaign keeps one **canonical** audit report per repository
(other products shipping the same repo hold symlinks to it), this works
out to **one ledger per audited repository**, beside the canonical
report. `metadata.audit_report` holds the relative path back to the
JSON report, and every event's `finding_ref` must join to a finding ID
inside it.

Where the store itself lives — a local checkout or object storage — is a
deployment matter, and the ledger design does not depend on it: a layer binds
the exact bytes of the report it annotates (`audit_report_sha256`) and of every
sibling artifact (`artifact_digests`), both inside the signature (§10b), so a
moved copy is verifiable wherever it lands.

Three things that are deliberately *not* ledgers:

- **`<repo>-findings-current.{json,md}` is a derived cache, not a
  record.** `build_cumulative.py` regenerates it from scratch on every
  run by replaying the ledger over the audit baseline; it is named
  `-findings-current` (never `-security-audit-*`) so portfolio roll-ups
  that glob `*security-audit.*` cannot double-count it.
- **There is no fleet-wide cumulative ledger.** Portfolio state is
  always derived by replay, never stored: `findings-trends` replays
  every repo's ledger against time buckets, `countersign` sweeps all
  ledgers for pending human decisions, and the executive-summary
  aggregates the per-repo reports. A global mutable roll-up file would
  be exactly the kind of editable state the design refuses (tenet 2).
- **The `.md` files are renderings.** The JSON report is the original
  and the thing the claim hashes protect (§10); the markdown is
  regenerated from it.

Ledgers are created **lazily** — a repo gets its layer on its first
`track-findings` run — or in bulk:
`python3 harnessing/4-triage/track-findings/scripts/baseline_claims.py sweep analysis-results/findings`
creates a minimal layer (and pins all claim hashes) for every canonical
audit report that lacks one, so baselines are tamper-evident *before*
any triage feedback arrives.

### The event record

The ledger's `events` array is the record;
its `needs_review` array is the queue of statements that were *noticed*
but did not meet the bar to change state (ambiguous phrasing, unverified
identity, an undetermined triage verdict, an audit-valve sample).

Each event carries:

| Field | What it is — and why it is shaped that way |
|---|---|
| `event_id` | sha256 of `source.ref\|finding_ref\|validity\|resolution`. Deterministic, so re-ingesting the same source is a no-op (idempotency) and an after-the-fact edit is detectable (the hash stops matching — validator-enforced). |
| `finding_ref` | The canonical `{REPO_SLUG}-{SHORTSHA}-{NNN}` finding ID, so every event joins back to exactly one audit finding. |
| `fingerprint` | The annotated finding's **identity as observed when the event was recorded** — copied from the baseline report's `finding.fingerprint`, never recomputed here. `finding_ref` is scan-scoped and changes on re-audit; the fingerprint is what survives one. See *Identity* below. |
| `fingerprint_algo` | Which recipe version produced that value (`v1`, `v2`, …). Recorded per event so an algorithm bump stays readable at replay instead of being inferred from the recording date. |
| `recorded_at` / `occurred_at` | When the event was *appended* vs. when the determination *actually happened* (commit date, Jira transition, report date). Trends bucket by `occurred_at` so late ingestion cannot distort a time series — discovering an old comment today must not look like risk changing today. |
| `source` | `{type, ref, actor}` — the source class (§5), a permalink, and the attributed actor. |
| `disposition` | The claim itself, on one or both axes (§4). |
| `rationale` | A *verbatim quote* of the statement or machine verdict — evidence, not paraphrase. |
| `evidence_refs` | file:line citations, PoC paths, crash artifacts. |
| `risk_weight` | On hardening events: the λ, weight-table version, and tenancy profile resolved at emission time (tenet 6). |
| `auto_accept_tier` | Marks the narrow class of machine false positives allowed to set state without countersign (§6). |

### Identity: which finding an event is about

`finding_ref` names a finding *within one scan* — `{REPO_SLUG}-{SHORTSHA}-{NNN}`
is tied to the commit that was audited, so the same exposure re-audited next
quarter gets a different ref. That is fine for joining an event to its report and
useless for the question the ledger exists to answer: **is this the thing we
already decided about?**

The **fingerprint** answers that. It is a `sha256` over three canonicalized
components of the finding — repository URL, its sorted set of location *paths*,
and its primary CWE:

```
fingerprint = sha256( canon_repo(repo_url) | ";".join(sorted set of canon_path(locations[].path)) | primary_cwe )
```

**Line numbers are never hashed** (they live in `locations[].lines`), and neither
are title, description or severity. That is the whole point: a finding survives
every edit above it and every rewording by a later model, so a false-positive
verdict signed in March still attaches to the same finding in August. Only the
*first* CWE enters identity. A moved file or a re-tagged primary CWE produces a
**new** identity — which is what rebaseline alias events exist to bridge.

**The harness computes it; nothing else does** (ledger plan decision D7). The
recipe has exactly one implementation, in `traust_ledger/_internal/identity.py`, and one
prose contract, `traust-ledger/docs/finding-identity.md`. Report writing stamps the value as
a required post-validation step (python3 -m traust.cli corpus finding-identity
fingerprint `<report>` --write; see [report-structure.md](report-structure.md)),
and the report validator's `check_finding_identity` then **recomputes every stamp
and compares** — an absent fingerprint is an error (2026-08-13, once the corpus
reached 100% stamped) and so is one that does not reproduce, which is what makes a
forged stamp fail validation rather than propagate. A producer that mints findings
without routing through the harness submits **unstamped** rather than inventing an
identity.

**Two fields, different provenance, routinely conflated.** `findings[].fingerprint`
in the audit report is the wire format — plain JSON, protected only by the
validator's recompute. The event's `fingerprint` is the durable record: under
leaf format 2 (§10b) the leaf is the whole event, so identity sits **inside the
Merkle root** and editing it breaks the root. A consumer saying "the fingerprint"
must say which one it read.

**Stamped once, never corrected in place.** `attach_identity` refuses to
overwrite an existing value, because an event is a historical observation — *"at
time T this finding's identity was X"* stays true even after the current answer
changes. `event_id` is untouched by identity stamping; the two hashes answer
different questions and neither is derived from the other.

**It is not a key.** One finding audited under many parents has the same
fingerprint by design, so keying dispositions on it merges records from distinct
audit contexts — measured, that loses *more* rows than the defect it was proposed
to fix. Dispositions stay keyed by layer plus `finding_ref`; the fingerprint is a
correlation column, for the cross-repo question *"where else does this exact
finding appear?"*. It is also not a security control: it is an unkeyed digest of
public inputs, and what makes a stamp trustworthy is the signature over the root
that contains it.


## 4. Two independent axes

Every determination answers one (or both) of two questions that are
deliberately kept separate:

- **validity — "is the finding real?"**
  `not_verified` (default; never set by an event) → `confirmed`,
  `corrected`, `hardening`, or `false_positive`.
- **resolution — "is it dealt with?"**
  `open` (default) → `fix_in_progress`, `resolved`,
  `partially_resolved`, `risk_accepted`, `regression_introduced`.

Conflating them loses real information: a confirmed finding whose risk
was formally accepted is *real and undealt-with* — it belongs on the
accepted-risk register, not in the "closed" pile. Likewise `hardening`
is a validity answer ("real, but not an exploitable vulnerability"), not
a resolution — the gap is still open work.

Resolution has its own small authority ladder (verification reports,
which actually re-test the code, outrank Jira status, which outranks
everything else), and one deliberate friction: a commit message can set
`fix_in_progress` but never `resolved` — the claim that something is
fixed belongs to the skill that verifies fixes.

Cross-repo fixes add a second friction (v0.146, the two-legged rule):
when the fix lands in a *different* repository (upstream library,
vendored dependency, base image), verify-remediation checks both legs —
Leg A re-audits the fix in the fix repo, Leg B runs the deterministic
propagation check (python3 -m traust.cli check fix-propagation) against the
original repo. Leg A alone maps `partially_resolved` +
`propagation: pending` to `fix_in_progress`; only `consumed` promotes
to `resolved`, because an upstream merge does not resolve a finding the
product still ships vulnerable.

## 5. Evidence classes: who can say what

Sources fall into three classes, and validity conflicts resolve by
class first, recency second — *within* a class the latest determination
wins, but no amount of recency lets a weaker class override a stronger
one:

| Class | Sources | Why this rank |
|---|---|---|
| **1 — Execution-verified** | `validation_report`, `verification_report`: reproducing exploits, crashes, re-tested fixes — since v0.179, only events evidence-graded **E0** (observed effect) or **E1** (authenticated success on the exploit action) | An executed proof is not an opinion. A crash reproduces or it doesn't. |
| **2 — Human static** | Identity-verified human determinations via MR comments, Jira, interactive sessions — **and any human-actored event regardless of its source type** (see demotion rule below) | Human judgment reading code — usually right, but fallible and, in the adversarial case, pressurable. |
| **3 — Machine static** | `triage_report`, `impact_report` (dependency-reachability filings from `route_impact_findings.py`), and other machine events — including **E2/E3-graded** events from execution sources | Adversarial multi-vote LLM verification with cited evidence — strong signal, but still a model reading code. |

**Human-actor demotion rule** (`event_class`,
`src/traust/cli/build_cumulative.py:73-97`): an event whose
*actor* is a verified human classes as **2 even when its source type is
an execution report** — a human recording a determination against a
validation report is a human judgment about that report, not executed
proof. (Before this rule, human FPs recorded on verification events
classed 1 and `exec_decisive` discarded them — the finding pended
forever.) Actor beats source; grade beats both.

Class 1 is conditional, not automatic (v0.179): an execution *source*
earns execution-class rank only when its evidence grade shows something
actually happened — E0/E1. An E2/E3-graded event from a validation or
verification report is machine static evidence with a grade annotation
(`build_cumulative.py` `event_class`), and ungraded confirmations from
reports at/after 0.179.0 never become events at all — the emitter
(python3 -m traust.cli ledger emit-validation) quarantines them into
`needs_review` until graded (pre-0.179.0 reports are grandfathered).

The consequences are deliberately uncomfortable in one direction: a
human can overrule any machine *opinion*, but not a machine-*executed
proof* — provided it really is one: only an E0/E1-graded execution
event carries that override power. That is the point — the hierarchy
is about falsifiability, not rank.

## 6. The false-positive discipline

`false_positive` is the most dangerous disposition in the system: it is
the one that removes risk from the record. The ledger therefore treats
every FP as a **falsifiable claim under standing scrutiny**, through
six stacked controls:

1. **The soundness gate.** A machine refutation that rests on an
   unsound probe — an error-signature transcript, a zero-subject RBAC
   probe, a target that never deployed — never enters as FP evidence at
   all: the verdict is downgraded to `inconclusive` with a
   machine-readable `soundness_flag`, and the emitter queues an
   `unsound_refutation` needs_review item instead
   (`harnessing/5-validate/validate-findings/SKILL.md`,
   python3 -m traust.cli ledger emit-validation; legacy reports are
   linted retroactively by python3 -m traust.ops.lint_refutation_soundness). A
   probe that never soundly tested the claim proves nothing either way.
2. **Machine FPs pend by default (countersign rule).** A machine
   refutation — triage vote or live-validation `refuted` — enters as
   *evidence* and shows as "refuted, awaiting human sign-off" until an
   identity-verified human countersigns. Machines propose dismissal; they
   don't (generally) enact it.
3. **A narrow, measured auto-accept tier.** The exception: triage FPs
   with at least two concurring false-positive votes and no
   true-positive or hardening dissent, verdict-citation-lint clean
   (every cited line of refutation evidence actually exists),
   confidence ≥ 8, *and* claimed low/informational may set state
   directly (the `is_auto_accept` predicate in the emitter; a lone FP
   vote is not corroboration and routes to countersign) — the cases
   where human review queues would otherwise fill with rubber-stamping.
   A 1-in-10 sample still goes to a human (`fp_audit_valve`), so the
   tier's error rate is continuously *measured*, not assumed. The sample
   is keyed by a **secret operator salt** (`HARNESS_VALVE_SALT`) over
   the immutable event fields — an event-id key would be grindable by
   the agent that authors the findings. **Fail-closed:** with no salt set,
   every auto-accepted FP queues for human audit; operators must
   provision the salt (outside any agent-visible environment) to keep
   the tier at 10% sampling.
4. **The refuted register.** Machine-refuted FPs are exported to
   `*-refuted-register.json` at triage-emission time
   (`emit_triage_ledger_events.py`; validation runs merge-append via
   `emit_validation_ledger_events.py`), and the register *feeds*
   fuzz-harness target selection and live-validation scoping. Nothing
   leaves verification scope because someone said "false positive";
   dismissal buys an entry on the falsification worklist, not immunity.
   **Known limit:**
   `/countersign` writes no register entries, so a *human-only* FP —
   one first asserted at the workbench rather than by triage — never
   reaches the register today; register entries carry the machine
   `asserted_by`, not the countersigner.
5. **Execution override, loudly.** If fuzzing or live validation later
   reproduces the "false positive," class-1 precedence flips validity to
   confirmed and surfaces `fp_overridden` with the original
   countersigner attributed. Dashboards report FP-override rates
   per identity — a pattern of one person's dismissals being overturned
   by execution evidence is an insider-risk or competence signal that
   should be visible without forensic replay.
6. **The two-person rule.** After an executed proof, a single human
   cannot flip the finding back to false positive
   (`fp_reassertion_blocked`); it takes two independent identity-verified
   humans with a justification that addresses the PoC.

The threat model behind all six: a countersigner who is mistaken — or
who is deliberately dismissing findings to shield a codebase from
assessment. Either way the control is identical: FP assertions stay
visible, stay testable, and lose to evidence.

### 6a. The countersign workbench

"Awaiting sign-off" is derived state, not a stored queue — so
python3 -m traust.cli admin countersign provides the human inbox over it:

- **`queue`** walks a findings tree, derives every pending decision
  (awaiting-signoff findings + pending `needs_review` items), and
  renders one **decision card** per item: the audit claim, the machine
  refutation with its lint-verified evidence and vote data, and exactly
  what signing records. A card is self-contained by design — the
  reviewer decides without opening any report.
- **`apply` / `record`** turn decisions into ledger events: the
  signer's identity is verified before anything is recorded — the
  signer is the holder of the ledger identity token, the SDK verifies
  the token and stamps that identity on every event it writes, and
  nothing the CLI asserts about the signer reaches the layer. Machine
  tokens cannot countersign. Self-minted local tokens
  (`identity_provider: local`) verify against a key in the signer's own
  config directory, so any code executor could mint "human, verified"
  events for two names and defeat the two-person rule; countersign
  refuses them unless the deployment sets
  `HARNESS_COUNTERSIGN_ALLOW_LOCAL=1` (adopters with no identity
  provider). An employee-directory cross-check ("is this account
  current") is a deployment command the ledger runs
  (`LEDGER_DIRECTORY_COMMAND`, see the ledger's service-identity doc),
  applied on every write path; it is not part of the identity proof. Mechanism and
  variables: the identity-verification section of
  [countersign SKILL.md](../harnessing/4-triage/countersign/SKILL.md). A blank
  rationale on a countersign adopts the machine rationale *explicitly
  framed as the signer's adopted determination*, rejecting a refutation
  (`keep_open` → human `confirmed`) requires the reviewer's own words,
  events get canonical ids (idempotent per signer-day-and-level), and the
  cumulative report is rebuilt deterministically with a printed receipt.
- The annotatable `countersign-queue.md` also works asynchronously —
  mark decisions in an editor or an MR, apply later.
- **Human overrides** extend the workbench beyond the queue —
  a finding need not be pending to act on it, and all three demand a
  rationale in the signer's own words: `reopen` flips a false positive
  back to confirmed (a human `confirmed` event);
  `override_false_positive` flips a confirmed/open finding to FP, with
  evidence-class precedence still applying (over an executed proof a
  second independent signer must concur); `severity=<level>` records an
  upgrade or downgrade — the audit report's severity is never
  rewritten, the cumulative report carries it as `effective_severity`
  plus a `severity_overrides` table (python3 -m traust.cli admin countersign).

None of the §6 safeguards are relaxed: the workbench removes the memory
burden and the ceremony, not the verification, the rationale
requirement, or the override machinery.

### 6b. How triage verdicts become events

`/triage` Phase 6e runs the emitter and then rebuilds the cumulative
report; both are deterministic and can be re-run by hand:

```bash
python3 -m traust.cli ledger emit-triage \
    <repo>-triage.json --audit <repo>-security-audit.json \
    --lint .triage-state/verdict-lint.json   # --layer, --weights, --tenancy-profile optional
python3 -m traust.cli build cumulative \
    <repo>-security-audit.json <repo>-findings-layer.json
```

The emitter routes and gates only. It never flips validity itself; the
merge engine and the countersign rule decide. Only findings with a
canonical `orig_id` (`{REPO_SLUG}-{SHORTSHA}-{NNN}`) emit events,
because `finding_ref` must join back to the audit report; a batch
without one (third-party scanner input) skips emission with a logged
warning.

| Triage verdict | Ledger effect |
|---|---|
| `true_positive` | validity `confirmed`, machine actor. Confirmation is the low-risk direction, so it stands without countersign; the resolution axis is untouched. |
| `true_positive` with `verify_verdict: needs_manual_test` | no validity event; a `needs_manual_test` needs_review item, so the unconfident confirmation reaches the countersign inbox instead of evaporating. |
| `false_positive` | validity `false_positive`, machine actor — auto-accepted under the §6 tier or pending countersign otherwise — plus a refuted-register entry. |
| `hardening` | validity `hardening`, with λ, weight-table version and tenancy profile recorded in `risk_weight` (§7a). |
| `undetermined` | no validity event; an `undetermined_finding` needs_review item. The ledger default `not_verified` already expresses the state. |
| `duplicate` | nothing; the canonical finding's event covers it. |

**Event shape.** `event_id` is the ledger's canonical sha256
(`compute_event_id` over source ref, finding ref, validity and
resolution; resolution is empty on triage events), so re-emitting the
same triage appends nothing. `source.type` is `triage_report` with actor
`triage/<harness_version>` and `identity_verified: false`;
`occurred_at` is the triage completion time; `rationale` is the triage
rationale capped at 500 characters, with refute reasons and the
exclusion rule appended on false-positive events; `evidence_refs` are
the finding's first links.

**Edge cases.** Re-triage at a new commit yields new canonical IDs and
the cross-commit identity handling of §3 applies unchanged. A verdict
that changes between runs appends a new event; last-wins-per-axis takes
the newer `recorded_at`, and both events stay visible.

**Who computes what.** The emitter produces events, the refuted
register and queue items. `build_cumulative.py` derives the
evidence-class merge, `fp_overridden`, the two-person state and the
`assurance` grade. `build_trends.py` derives the assurance views and
their deltas, FP-override rates, the hardening burndown and the
blast-radius annotation. The executive summary computes none of those;
it reports severity, credential and ledger-coverage headlines only.

## 7. Hardening: real risk that isn't a vulnerability

`hardening` exists on the validity axis because the older binary forced
a lie: an accurately-described CIS/STIG/Scorecard/SLSA gap with no
concrete exploit path is not a *false* positive (it's true) and not a
*confirmed vulnerability* (nothing is exploitable). Recording it as
either corrupts a different metric.

Hardening findings remain **risk-bearing**: absent hardening degrades
posture and compounds co-located vulnerabilities, so each event records
a category-aware weight λ (tenancy-load-bearing categories near 1.0 on
multi-tenant products), resolved from a versioned weight table at
emission time. (λ is per-event context only, never a headline index;
the headline trend metrics are
`owasp_high_plus_pct` and `mean_cvss_open`, per
docs/risk-rating-methodology.md.) Dashboards
also flag the **unhardened blast radius** — components where open
confirmed vulnerabilities co-locate with open hardening gaps — because
that co-location is exactly where a "medium" is effectively worse than
its score. What hardening never does: inflate confirmed-vulnerability
counts or trigger defect filing on its own.

### 7a. The weight table

λ lives in a versioned, owner-tunable config —
`$TRAUST_CONFIG_HOME/hardening-risk-weights.json` (template:
[config/hardening-risk-weights.example.json](../config/hardening-risk-weights.example.json))
— keyed by the finding's existing category slug, so no fresh
classification happens at metric time. The values encode one judgment:
**how much does this class of absent hardening change what co-located
confirmed findings are worth?** Tenancy-load-bearing categories
(isolation, network exposure, workload configuration, authentication,
authorization) sit at or near 1.0; observability gaps sit at the floor,
which is also the `default` for any unlisted category. The current
values are in the file; this page does not duplicate them.

Two modifiers complete the resolution:

- **Tenancy profile and dampening.** The profile is derived from exactly
  one artifact: the audit report's `peach_isolation_review.applicable`
  flag (`true` → `multi_tenant`), or an explicit `--tenancy-profile`
  override on the emitter. No threat-model or repo-graph leg exists.
  With neither present the profile defaults to `single_tenant`, which
  multiplies every weight by `single_tenant_dampening` (0.5 by default),
  because the tenancy-load-bearing categories are weighted for exactly
  the blast radius a single-tenant deployment doesn't have — so emit
  PEACH blocks rather than trusting the default.
- **Emission-time recording (tenet 6).** `emit_triage_ledger_events.py`
  resolves λ *when the event is written* and records the weight, the
  table version, and the tenancy profile into the event's `risk_weight`
  field. Replays never re-read the config — editing the table affects
  only future emissions, so `findings-trends` stays deterministic under
  weight changes, and every historical risk number remains explainable
  by the version stamped on its events. Bump `version` on any edit.

## 8. Replay: what the ledger buys you

Because state is derived, one event stream yields several products:

- **The cumulative report** (`*-findings-current.{json,md}`) — current
  validity/resolution per finding, plus an `assurance` grade
  (`claimed → machine_verified → human_reviewed → execution_proven`):
  the highest evidence class that has spoken, i.e., a one-word answer to
  "how sure are we?"
- **Trends** (`findings-trends`) — replaying the same events against
  monthly boundaries gives burndown, velocity, MTTR, FP rates, and the
  headline risk signals (`owasp_high_plus_pct`, `mean_cvss_open`; the
  retired λ-CVSS composite survives only as legacy history) with no
  stored snapshots to drift.
- **Assurance views** — replaying with progressively stronger evidence
  admitted gives three portfolio pictures: **claimed** (audit only),
  **verified** (plus static triage/human events), **proven** (plus
  execution evidence). Their deltas are metrics in their own right:
  claimed−verified is *triage compression* (how noisy the raw audit
  was), verified−proven is the *validation gap* (how much believed risk
  has never been empirically demonstrated — the standing priority queue
  for fuzzing and live validation).

### 8a. What a *patch* has been proven to do

The assurance ladder above grades a **finding** — how sure are we the
vulnerability is real. It says nothing about a **fix**, and the two are
graded by different machinery. State the fix side explicitly, because the
strongest evidence available depends entirely on which input produced the
patch.

| Patch path | Strongest evidence it can carry | Ceiling |
|---|---|---|
| `/patch` **execution-verified mode** (`vuln-pipeline` input) | the build → reproduce → regress → re-attack ladder with executable oracles; `verified: ladder_passed` / `ladder_failed` | behavioural: the original failure is observed before and not after |
| `/patch` **static mode** (audit/triage/vuln-scan input) | `fact_differential: cleared` — the backing scanner, re-run on a scratch worktree with the diff applied, no longer fires | **pattern-level only** |
| `/patch` static mode, finding **not** scanner-backed | `fact_differential: not-applicable: <reason>` | none; the reviewer verdict is the only signal |
| `/remediate-finding` | the target repo's own build/test suite, run in containment; optionally a typed `evidence[]` item per kind (`mutation` — Phase 4b, Go only; `property` — Phase 4c, Python only) | the project's suite, which was not written for this bug. A `mutation` item raises the ceiling only for the package it ran on: `proves` means the suite detects changes to that code, and `fails_to_prove` means the regression test asserts nothing about them — neither says the fix is correct. A `property` item is the strongest kind available outside the pipeline ladder: `proves` means the property FAILED on the unpatched revision and passes on the patched one, so it witnesses this finding and now guards it — but only over the input domain its strategies generate |
| `/verify-remediation` | a targeted re-audit against the patched code, same frameworks as the original audit; plus an executed `scanner_differential` evidence item when the finding is scanner-backed (step 4-pre.5, both revisions scanned) | analysis for everything except that one differential. A `scanner_differential: proves` says the pattern that evidenced the finding is gone — **pattern-level only**, since a diff can silence a scanner by moving the sink. Findings with no scanner backing stay analysis-only |

Three consequences worth keeping in view:

- **A cleared fact is not a correct fix.** `/patch` says so itself: the pattern
  is gone, not that the fix is correct or minimal. A diff can silence a scanner
  by moving the sink.
- **The executable ladder has a narrow footprint.** It needs `vuln-pipeline`
  input, so it does not reach findings that arrived from an audit, triage, or
  `/vuln-scan`. Those findings can still carry *typed* evidence — `mutation`
  and `property` from stage 7, `scanner_differential` from stage 8 — but each
  kind's ceiling is its own, and none of them is the behavioural ladder.
- **`verified−proven` has a fix-side twin.** The *validation gap* above measures
  believed risk never empirically demonstrated. The same question asked of
  remediation — believed fixes never empirically demonstrated — has no metric
  yet. Closing that is tracked in
  `progress-tracker/plans/tob-skills-integration-plan.md` §4.1.

Nothing here is a reason to distrust a patch. It is a reason not to read
"patched" as "proven", and to keep the two words apart in dashboards and
reports.

## 9. A finding's worked timeline

```
T0  audit          finding ACME-1a2b3c4-007, high, "SSRF in webhook"
                   -> validity not_verified, resolution open, assurance: claimed

T1  triage         3-0 TRUE_POSITIVE, evidence lint clean
                   -> event: triage_report / machine / confirmed
                   -> validity confirmed, assurance: machine_verified

T2  human review   senior engineer, identity-verified: "validated upstream,
                   not reachable" -> interactive / human / false_positive
                   -> validity false_positive (class 2 > class 3)
                   -> finding enters the refuted register; conflict flag set

T3  fuzzing        crash reproduces the SSRF -> validation_report /
                   machine / confirmed (class 1)
                   -> validity confirmed, fp_overridden: true (T2 asserter
                      attributed), assurance: execution_proven

T4  same engineer  re-asserts false_positive
                   -> BLOCKED: fp_reassertion_blocked (two-person rule);
                      validity stays confirmed until a second independent
                      identity-verified human concurs against the PoC
```

Every step above is still in the ledger at T4 — including the overridden
dismissal — which is precisely what makes the record trustworthy.

## 10. Claim hashes: extending tamper-evidence to the baseline

The event hashes above protect the *ledger*; until harness 0.39.0, the
audit report the ledger annotates was protected only by convention
("never hand-edit `validation_status`") and by git history — an in-place
edit to a finding's description or severity would flow silently into the
derived cumulative report rather than conflict with it.

`metadata.claim_hashes` in the layer closes that gap. At every
track-findings run, `harnessing/4-triage/track-findings/scripts/baseline_claims.py record` pins a sha256 of
each finding's **canonical claim fields** — id, title, severity, cwes,
locations, description, remediation — from the **`*-security-audit.json`**
(the JSON is the original; the `.md` is a rendering of it and is not
hashed). Three properties follow:

1. **Add-only.** New findings (sanctioned appends from `/create-fuzzing`
   follow-ups, `/vuln-scan` supplements, `/validate-findings` novel
   findings, or `/verify-remediation` regression routing —
   python3 -m traust.cli route regressions) get pinned on the next run; an existing
   hash is never overwritten — except for a finding explicitly named with
   `--rebaseline` whose `validation_status` is `corrected`, the one
   sanctioned in-place revision path. The revision is thereby visible and
   attributable instead of silent.
2. **`validation_status` is deliberately excluded** from the hash: it
   changes via the sanctioned human/execution paths, and the ledger —
   not the file — is the authority on current belief anyway.
3. **Verification has teeth in two places**: `validate_report.py` checks
   every baselined claim whenever the layer is validated (missing finding
   → error; drifted claim → error unless `corrected`), and
   `build_cumulative.py` **refuses to rebuild** the cumulative report
   from a baseline whose claims drifted — a tampered audit can no longer
   quietly become the portfolio's current view.

## 10b. Merkle roots: sealing the event *set* (and making it signable)

The two hashes above protect content — `event_id` breaks when an event's
canonical disposition fields are edited, claim hashes break when a
baseline finding's claim is edited. Neither notices an event being
**deleted, inserted with internally-consistent hashes, or reordered**.
Since harness v0.66 (feat/merkle-tree-hashing), every write path
(`emit_triage_ledger_events`, `emit_validation_ledger_events`,
countersign recording, `build_cumulative`) re-stamps the layer with an
RFC 9162 SHA-256 Merkle root (`metadata.merkle_root` / `merkle_size` /
`merkle_epoch`; pre-epoch events on layers adopted mid-history are
pinned by `pre_merkle_checkpoint`). The validator recomputes it on
every pass.

**Leaf format 2 (v0.200.0, self-audit `-001`):** leaves are the
canonical JSON of the FULL event object (sorted keys, `merkle_*` fields
excluded), so editing *any* event field — actor identity, rationale,
timestamps, `auto_accept_tier` — breaks the root. The legacy format 1
(leaves = `event_id` only) bound just the four disposition fields;
format-1 layers still verify but emit a loud content-unbound warning,
and any recording-tool write restamps them to format 2
(`metadata.leaf_format`). Out-of-range `merkle_epoch` values are now
REFUSED at stamp time, never silently reset — a truncated events array
can no longer restamp cleanly.

**Where the signature lives.** The signature is stored **inside the layer it
signs**, as three sibling keys in the same `metadata` block — there is no
sidecar `.sig` file and no separate signature store:

```
<repo>-findings-layer.json
├── metadata
│   ├── merkle_root              "e3b0c442…"   ← what is attested
│   ├── merkle_size / merkle_epoch / merkle_algorithm / leaf_format
│   ├── claim_hashes             { … }
│   ├── merkle_root_signature    "{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json"…}"
│   ├── merkle_signing_method    "keypair" | "identity"
│   └── merkle_signature_format  2
├── events                       ← what the root commits to
└── needs_review
```

`merkle_root_signature` holds a **sigstore bundle serialized as a JSON string**,
not a bare base64 signature; `merkle_signing_method` tells the verifier which
backend produced it, and `merkle_signature_format` which payload it covers.
Because the signature sits inside the file, it cannot cover the file's bytes —
cosign signs a SHA-256 digest over a canonical document. The current format is
**4**; each format is a superset of the one before, and the verifier
reconstructs the payload for whichever format a layer was signed under:

| Format | Payload adds | Closes |
|---|---|---|
| 1 | `merkle_root` only | — (transplantable onto any layer with the same root) |
| 2 | `leaf_format`, `merkle_epoch`, `merkle_size`, `pre_merkle_checkpoint`, digest of `claim_hashes` | replay after rollback; re-scoping by editing epoch/format; baseline claim substitution |
| 3 | `audit_report_sha256` | pointing a layer at a substituted report by rewriting its digest |
| 4 | digest of `artifact_digests` (every sibling artifact's sha256) | unverifiable sibling artifacts after a move to object storage |

One consequence worth knowing: **re-serializing a layer cannot break its
signature** (the digest is computed from parsed values, not on-disk bytes), while
editing any event, the claim set, the annotated report, or any digested sibling
can. One signature per layer file — every layer in the corpus carries its own,
not one signature over the corpus and not one per checkpoint. See
[signing.md](signing.md) for the full lifecycle.

Division of labor, deliberately layered: **merkle root** = the event set
and order are exactly what was written (and one 64-hex value a signature
can attest — `ledger sign` / `ledger verify-signature`, cosign and OIDC backends,
`LAAS_SIGNING_REQUIRED=1` to make an unsigned root a fail-closed **ERROR**
— not a warning, and deleting a signature is therefore not a downgrade path; see
[signing.md](signing.md)); **event_id** = each event's disposition
content; **claim hashes** = the audited claims underneath. With leaf format 2
the merkle root pins every event field's bytes directly (the historical
scope note — that actor/rationale/timestamps were pinned only via git
history — applies to legacy format-1 stamps only).

## 10c. Data flow: how an event reaches the ledger, and what gets signed

Every path below converges on one function. There is no second way in.

```
  EVIDENCE PRODUCERS                    LEDGER WRITERS                      ARTIFACT
  (produce verdicts, write no ledger)   (append + stamp + sign)

  /triage            ──┐
   *-triage.json       ├─► emit_triage_ledger_events ───────┐
                       │        (append events)              │
  /validate-findings ──┤                                     │
   *-validation.json   ├─► emit_validation_ledger_events ────┤
                       │        (append events)              │
  human decision    ───┤                                     ├─► traust-ledger stamp_and_sign(layer)
   (identity-verified) ├─► countersign (workbench / CLI)     │      │
                       │        (append events)              │      ├─ 1. stamp_merkle_metadata()
  /track-findings    ──┤                                     │      │     recompute merkle_root
   MR/commit/tracker   └─► build_cumulative ─────────────────┘      │     over ALL events
                                (rebuild)                           │     set merkle_size / epoch /
                                                                    │     algorithm / leaf_format=2
  re-audit           ───► rebaseline()  ⚠ re-points, does not stamp │
                                                                    ├─ 2. sign_if_configured()
  a scan by itself   ───► (nothing — a scan is not an event)        │     LAAS_SIGNING_KEY_PATH
                                                                    │     → signed, format 4
                                                                    ▼
                                                    <repo>-findings-layer.json
                                                      metadata.merkle_root
                                                      metadata.merkle_root_signature
                                                      events[…]
```

**Read it as four claims.**

1. **A scan does not sign anything.** Producing a finding writes an audit report, not a ledger
   event. A finding reaches the ledger only as a *disposition event* — and it is the event that
   triggers the write, the stamp, and the signature. So: **the ledger is signed when the ledger
   changes**, never on a schedule and never merely because a scan ran.

2. **Stamp always precedes sign, in one call.** `stamp_and_sign()` recomputes the root and only then
   signs it, so signing a stale root is impossible by construction. Reversing the order would attest
   a root that no longer describes the events.

3. **The signature covers the root's *interpretation*, not just the root.** The current format
   (4) signs a SHA-256 digest over `merkle_root` + `leaf_format` + `merkle_epoch` + `merkle_size` +
   `pre_merkle_checkpoint` + a digest of `claim_hashes` + `audit_report_sha256` + a digest of
   `artifact_digests` (§10b). So a signature cannot be transplanted onto another layer that
   happens to reproduce the same root, replayed after a rollback, re-scoped by editing
   `leaf_format`/`merkle_epoch` beneath it, or kept valid while the annotated report or a sibling
   artifact is swapped.

4. **One signature per layer file — not per event, not per checkpoint.** A layer with 163 events has
   one signature, replaced wholesale on the next write. Checkpoint signing
   (`merkle_epoch` + `pre_merkle_checkpoint`) belongs to the future single-event-store design and is
   **unused today**: every layer sits at `merkle_epoch: 0`.

**Failure modes, none of them silent:**

| `SignAttempt.status` | Cause | Writer behaviour |
|---|---|---|
| `unconfigured` | no `LAAS_SIGNING_KEY_PATH` (or no OIDC token for identity signing) | layer stamped and written, **unsigned**. Expected only on a workstation without the key; every layer in the corpus is signed, and `LAAS_SIGNING_REQUIRED=1` makes this state a validator ERROR |
| `signed` | key present, cosign succeeded | signature written to `metadata.merkle_root_signature` |
| `failed` | key present, signing broke | **warns on stderr** — a configured-but-broken signer never degrades quietly |

Enforcement is the validator's job, not the writer's: `LAAS_SIGNING_REQUIRED=1` makes an unsigned
root a fail-closed ERROR. A writer that refused to write unsigned would stall ingestion instead.

Full lifecycle, including where the key lives and how rotation works:
[signing.md](signing.md). The producer side — every router and
ledger writer, how ids are minted, how re-runs stay idempotent, and the rule that
only the three `secure*audit` skills may write a baseline:
[findings-routing.md](findings-routing.md).

## 11. What the ledger is not

- **Not a task tracker.** Jira owns work; the ledger records what Jira
  *concluded*, attributed to the resolving human.
- **Not editable history.** There is no update or delete; if an event
  was wrong, the correction is another event, and both remain visible.
- **Not a severity authority.** Severity is derived by the audit and
  triage stages; the ledger tracks belief and disposition, and the
  metrics layer applies weights recorded at emission.
- **Not a place for prose.** Rationales are verbatim quotes of the
  determining statement — the ledger preserves evidence; it does not
  editorialize.
- **Not a database.** The ledger of record is the per-repo append-only
  JSON files — deliberately, because the entire tamper-evidence stack
  (canonical event ids, claim hashes, content-bound Merkle roots,
  signatures, git history) is built on immutable files; a mutable
  store would undermine exactly those properties. See §11b for the SQL
  window that exists *over* it.

## 11b. findings.db — the SQL window, never the ledger

There **is** a single place to query every finding with SQL:
`analysis-results/graph/findings.db`, the traust-contracts storage/v1 store
on SQLite — a **projection** built by python3 -m traust.cli corpus findings-db
(the `/findings-db` skill) over all the per-repo ledgers and reports,
rebuilt by `/census`, and read through the contract's views. It answers
corpus-shaped questions ("open criticals by business unit", "distinct
CWE-1104 exposure") in one query instead of walking ~8k JSON files,
and several harness tools use it as an accelerator (diff-mode baseline
resolution, sweep scoping, dashboards).

Two rules keep the record/projection relationship honest:

1. **Projection, never authority.** The DB can be one census behind —
   including behind events a sweep itself just emitted. Anything
   consequential (a verdict, a resolution, a countersign) confirms
   against the live `*-findings-layer.json` before acting; "the DB
   lists candidates; the ledger decides."
2. **Writes never go to the DB.** Every mutation path in the harness
   appends events to the layer files through the recording tools;
   `findings.db` is regenerated from them, read-only, and none of the
   integrity machinery (§10–10b) applies to it — deleting or editing
   the DB destroys nothing and proves nothing.

The full consumer roster — which skills read the DB and at what
touchpoint — lives in the `## Integrations` section of
`harnessing/findings-db/SKILL.md`.

## 12. Pointers

| Topic | Where |
|---|---|
| Operating the ledger (ingest sources, tiers, interactive countersign) | `harnessing/4-triage/track-findings/SKILL.md` |
| Querying the corpus via the SQLite projection (`findings.db`) | `harnessing/findings-db/SKILL.md` |
| Countersign workbench (decision cards, apply/record) | python3 -m traust.cli admin countersign (§6a) |
| Triage → ledger wiring (verdict → event mapping, emitter) | §6b; `src/traust/cli/emit_triage_ledger_events.py` |
| λ weight table (versioned, owner-tunable) | `$TRAUST_CONFIG_HOME/hardening-risk-weights.json` (§7a) |
| Whole-pipeline map (artifacts, producers, consumers) | [artifacts.md](artifacts.md) |
| Merge engine (the derivation code) | `src/traust/cli/build_cumulative.py` |
| Trend replay | `harnessing/findings-trends/scripts/build_trends.py` |
| Fingerprint recipe, `ALGO_VERSION`, strict mode, what identity is *not* | `traust-ledger/docs/finding-identity.md` (beside `traust_ledger/_internal/identity.py`) |
| Schemas | `schemas/v1/layer.schema.json`, `schemas/v1/report.schema.json` |
