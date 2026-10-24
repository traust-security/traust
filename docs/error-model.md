# The Error Model — how the harness handles Type I and Type II errors

Every scanner — human or machine — makes two kinds of mistakes: it
reports problems that aren't real (**Type I, false positives**) and it
misses problems that are (**Type II, false negatives**). A harness that
claims otherwise is hiding its error rates, not avoiding them. This
document explains where each error class enters the pipeline, the
control that catches it, why each control exists, and the residual risks
accepted with eyes open. The rates themselves are measured per
deployment (§5) and live with that deployment's metrics, not here.

Companion reading: [artifacts.md](artifacts.md) (how a finding's artifacts
move stage to stage), [disposition-ledger.md](disposition-ledger.md)
(the event-sourced state machine underneath; §6b for the verdict →
event mapping). This page is the error-theory view across all three.

---

## 1. Two orders of error

**First-order (detection) errors** happen when findings are produced:

| | The error | The cost |
|---|---|---|
| Type I | The audit reports a vulnerability that isn't real | Wasted engineering attention; erodes trust in every future report |
| Type II | The audit misses a real vulnerability | A shipped vulnerability nobody is looking for |

**Second-order (disposition) errors** happen when findings are *judged*
— and they invert: wrongly **dismissing** a real finding as a false
positive converts a true positive into a *de facto* Type II (the vuln is
real, and now nothing downstream will ever look at it again). Wrongly
**confirming** a false positive is a contained Type I (remediation
effort is wasted, but `/verify-remediation` and patch review catch it).

That inversion is the single most important asymmetry in the design:
**a wrong confirmation is self-correcting downstream; a wrong dismissal
is silent and terminal.** Every control below follows from it.

## 2. The asymmetric-caution doctrine

> Machines may **confirm**. Only humans may **dismiss** — with one
> bounded, audited exception.

- A machine **confirmation** backed by execution evidence (class-1: a
  fuzz reproducer, a live exploit transcript, a successful forbidden
  action) is accepted directly. The evidence is *self-certifying*: if
  the probe were broken, the artifact would not exist.
- A machine **refutation** ("I probed it and it isn't exploitable") is a
  *negative claim* — only as strong as the probe's soundness: right
  target actually deployed, right credentials, right oracle, probe
  actually executed. A broken probe and a genuinely-safe target produce
  identical-looking negative transcripts. So a machine `refuted` verdict
  never sets state: it is recorded as evidence and the finding pends as
  `refuted_awaiting_signoff` until an identity-verified human countersigns
  (`traust findings queue` / `confirm`), with the **raw probe output rendered verbatim on the
  decision card** so the signer sees what "refuted" actually looked like.
- **The bounded exception (auto-accept tier):** triage may set
  `false_positive` without countersign only for claims of severity
  **low/informational** that clear the corroboration, citation-lint and
  confidence bar defined in [disposition-ledger.md §6](disposition-ledger.md),
  and a salted 1-in-10 sample of those auto-accepts is routed back into
  the human queue as an audit valve (fails closed to queueing everything
  when the salt is unset). The blast radius of a wrong dismissal at that
  tier is bounded by the severity cap.
- **Two-person rule over execution proof:** once a finding carries a
  class-1 execution confirmation, re-asserting false positive requires
  **two distinct identity-verified humans** post-dating the proof. A
  single attempt is blocked and flagged (`fp_reassertion_blocked`).

## 3. Why the doctrine is calibrated, not cautious-by-default

The rules above are not tradition — they are responses to measured
failure. An audit of every live-validation false-positive event in a
production ledger found:

- **Most machine refutations were unsound** — the probe never tested the
  claim. The classes, in descending frequency: zero-subject template
  probes (an RBAC check enumerating no subjects and reporting "none
  allowed"); probe execution failures recorded as "refuted" (an
  authentication error such as `Forbidden: User "<service account>"`
  presented as proof of absence); alias fan-out propagating one verdict
  across unrelated findings; and wrong-oracle scans. Whole runs emitted
  refuted verdicts while their own `install-failure.yaml` showed the
  target never installed.
- A large share of those refutations overturned findings that triage had
  **confirmed**, including criticals whose dismissal rested on probes
  that never executed.
- First-order rates are severity-dependent: the residual false-positive
  rate is low at critical and rises steeply toward informational (which
  is why auto-accept is only legal at the bottom of that curve), and
  single-pass high-severity recall is well below dual-pass recall, with a
  bimodal miss profile concentrated in configuration and credential-class
  findings. Two independent passes merged by union are therefore the
  default.

The structural fixes that came out of that analysis are the fail-closed
gate stack every live verdict passes — target attestation, positive
controls, differential probing, evidence grades, soundness signatures,
conflict routing, and the countersign rule at ingest — defined once in
[validation-process.md](validation-process.md). Two consequences of that
stack matter for the error theory here: an unattested run cannot ledger
*any* verdict, confirmed or refuted, so a broken environment produces
quarantine rather than a false negative or a false dismissal; and the
human gate only works because countersign cards render the raw probe
output, so "refuted" that means an authentication error is visible as
such.

## 4. Controls by stage

| Stage | Type I control (don't ship noise) | Type II control (don't miss real bugs) |
|---|---|---|
| Audit / scan | Deterministic pre-scan anchors (an opengrep pack calibrated on the deployment's own ledger, checkov, pqc-scan) pin claims to `file:line` before any model judgment; citation gate rejects unverifiable claims; the Precision Gate, carried by **all four scanning skills** (secure-code-audit, vuln-scan, secure-container-audit, secure-rpm-audit) — downgrade-not-drop rules calibrated on adversarially-refuted crit/highs (dependency reachability, vendor applicability, manifest-only lint) applied before any finding is filed, each report recording the pass in `metadata.additional.precision_gates` (a crit/high-bearing report with no block is an incomplete run, so a silently-skipped gate is itself detectable) | Recall benchmark + per-language recall cut; CVE-replay false-negative monitor (known-vulnerable commits must be re-found); coverage-first review prompts (report everything, filter downstream); dual-pass union-merge + threat-model coverage diff — two independent audit passes merged by union, every threat-model surface must end with a finding or an explicit negative result |
| Triage | N independent adversarial verifiers per finding; exclusion-rule taxonomy with per-rule precision tracking; severity-bounded auto-accept only; shared-component FP-precedent annotations from the tiered cache route settled human-countersigned refutations to a reduced vote tier — context with provenance, never a verdict | `undetermined` routes to `needs_review`, never silently dropped; duplicate collapse preserves occurrence counts |
| Live validation | Machine `refuted` pends for countersign; soundness gate quarantines unsound probes; probe transcripts are evidence, not verdicts | Attack plans include replay + chained + **novel** probes, not just confirmation of known findings |
| Fuzzing | (Fuzz cannot refute — structurally no FP path) | Refuted register feeds fuzz **targeting**: every human-signed FP is a falsifiable claim, and a later crasher overrides it loudly (`fp_overridden`, attributed) |
| Disposition | Countersign (identity-verified against the deployment's directory); two-person rule over execution proof; machine actors can never carry severity overrides | Un-countersigned refutations stay **open** in every consumer (findings-db `v_open`, census denominators, dashboards) — pending ≠ dismissed |
| Remediation | `/verify-remediation` re-audits each finding against the patched code with the original evidence standards | Verification sweeps re-open regressions (REG events) rather than trusting fix claims |

## 5. Self-measurement (how we know the rates)

The harness measures its own error rates rather than asserting them:

- **recall-benchmark** — seeded-vulnerability corpus, per-language
  recall floors; a model/skill change that drops recall fails promotion.
- **CVE-replay FN monitor** — repos at known-vulnerable commits; the
  audit must re-find the CVE or the miss is logged as ground truth.
- **Precision gate / scanner_correlation** — per-rule precision from
  ledger outcomes calibrates which deterministic rules are trusted.
- **Refutation-soundness linter** (`lint_refutation_soundness.py`) —
  scans validation evidence for unsound-refutation signatures, both as
  a forward gate and retroactively over historical events.
- **Class-generalization sweeps** (python3 -m traust.cli sweep) —
  every confirmed finding with a syntactic signature becomes a candidate
  opengrep rule swept corpus-wide by default; hits are `/triage`
  candidates, never filed findings — the ledger's own confirmations
  hunting their un-found siblings (a Type II control fed by adjudicated
  ground truth).
- **Injection canaries** — adversarial repository content (CWE-1427)
  probes that must *not* steer the auditor.
- All probe/benchmark artifacts live in `harness-qa` corpus trees,
  registered but excluded from every metrics lens, so self-measurement
  can never inflate campaign numbers.

The measured rates — false-positive rate by severity, single- and
dual-pass recall, the unsound-refutation share — belong to the
deployment's error-analysis record and are re-measured on the benchmark
cadence.

## 6. The improvement loop — how measured misses become detectors

Self-measurement (§5) tells us the rates; this loop is what makes them
move. Every error class has a capture channel that converts it into the
next detector, and each channel is deterministic, aggregated, and
consumable without archaeology:

| Signal | Capture channel | Feeds |
|---|---|---|
| Confirmed TPs in the ledger | python3 -m traust.cli sweep mine (over traust-core's recorded findings); `rule-mining.{json,md}` + `tp-corpus.jsonl` from `sweep rule-lane` | The opengrep rule-authoring backlog (uncovered CWE×language clusters) and per-rule precision |
| Syntactic-shaped confirmations | `python3 -m traust.cli sweep rule-lane` (rule-expressibility routing) | Draft rules swept corpus-wide; hits enter `/triage` as candidates |
| Semantic-shaped confirmations (authn/authz/ordering — never rule-expressible) | Precedent cards (python3 -m traust.ops.compile_precedent_cards): predicate over a shipped enumerator's output schema, or REJECTED | The semantic sweep tier — `sweep-candidates-semantic.json` into `/triage` |
| What the enumerators could NOT cover | Structured `metadata.additional.coverage_gaps` in every report (recording convention in the enumerator pre-scan sections) + skipped `deterministic_steps` | `traust assessments coverage` (traust-core's `AssessmentService.coverage`) — the repos-affected-ranked enumerator-expansion backlog |
| Rule-expressible shapes surfaced in benchmark runs | the benchmark rule-candidate extractor (post-scoring) | `benchmark-rule-candidates.{json,md}` under the rule-mining metrics — identity-only pattern exemplars for rule authors |
| Missed benchmark/CVE anchors | `fn_cve_replay_missed.jsonl` + the benchmark near-miss tier | Ground-truth queue for match-ladder and technique work |

Two boundary rules keep the loop honest:

- **Benchmark isolation is preserved.** Benchmark-run reports never
  enter the findings store or any ledger (§5, contamination rule). The
  rule-candidate extractor deliberately carries *identity only* (repo,
  finding id, CWE, file, title) under a banner forbidding ingestion as
  findings — the loop learns the *shape*, never launders the finding.
- **Volume is not expressibility.** The mine-ledger backlog's largest
  clusters are typically semantic (missing-authn CWE-306,
  confused-deputy CWE-441) — those route to enumerators and precedent
  cards, not opengrep. Reading raw cluster size as a rule-authoring
  priority repeats a measured mistake: a rule pack for a configuration
  class can ship while recall for that class barely moves, because the
  class was never rule-expressible.

## 7. Residual risks (accepted, documented)

- **The downstream gate is implicit.** Pending refutations stay open
  because FP validity is *withheld*, not because dashboards check for a
  pending flag. Consumers must read the derived
  `*-findings-current.json` (all documented consumers do); reading raw
  layer events would bypass the gate.
- **Auto-accept is a real machine-dismissal path.** It is severity-
  bounded and audit-sampled, but "all FPs need a human" is not literally
  true — reason about it as *bounded autonomy*, not zero autonomy.
- **Negative probes can be environmentally invalid** even when sound:
  a lab cluster with a feature flag off, a scoped-down service account,
  or a different deployment shape yields honest-looking negatives. The
  soundness gate cannot detect these; the countersign human and
  deployment-context attestation are the mitigations.
- **Historical events predating the soundness gate** may carry unsound
  refutations into a ledger; the retroactive linter pass and
  re-adjudication of affected criticals close that window.

## 8. For consumers: what a disposition actually means

| You see | It means |
|---|---|
| `confirmed` + class-1 evidence | Exploitability was *demonstrated* (artifact exists), not opined |
| `confirmed` (triage) | N adversarial verifiers agreed with cited evidence; no execution proof yet |
| `false_positive` (human-signed) | An identity-verified reviewer examined the raw evidence and signed the dismissal — and it remains falsifiable: a later crasher reopens it loudly |
| `false_positive` (auto-accept) | Low/informational only; zero TP/hardening votes + at least two concurring FP votes (`is_auto_accept`); salted-hash audit-sampled, fail-closed without the salt |
| `refuted — awaiting human sign-off` | A machine probe claims non-exploitability; **the finding still counts as open everywhere** until a human signs |
| `needs_review` / `unsound_refutation` | A probe claimed "refuted" but its own transcript shows it never tested the claim; quarantined, never an FP |
