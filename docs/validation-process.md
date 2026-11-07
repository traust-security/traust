# Validation Process — from observations to core-owned decisions

The validate lanes assess claims against explicitly authorized targets. Scope and
live execution remain separate from recording already-produced evidence. The
[validate-findings skill](../harnessing/5-validate/validate-findings/SKILL.md)
describes the existing guarded runner; the [record protocol](cli-reference.md#machine-validation-recording)
is callable without contacting any live target.

`traust admin attest-target --url <authorized-target> --out <run>/target-attestation.json`
records only browser-lane HTTP answer presence, separately from authentication,
authorization, browser usability and finding validity. An answering non-5xx endpoint,
including HTTP 401, 403 or 429, satisfies `url-reachable`; it does not prove that the
validator can log in or exercise the intended action. Transport errors, TLS failures
and HTTP 5xx responses fail that required check. `attested` remains the AND of every
required check: an answering URL cannot override a failed version or cluster check.
The command writes its artifact and exits zero for either attestation result;
consumers must inspect `attested` and the individual checks, not infer success from exit status.

The pack owns this narrow preflight policy in `attest_target._url_answer_check`, with
the cutoff pinned by the HTTP-status matrix in `tests/test_target_attestation.py`.
Both normal responses and HTTP errors pass through that same policy. Preflight uses
one urllib GET operation with a 15-second `urlopen` timeout and normal redirect handling;
it closes responses without reading bodies and does not apply application retries or
wait on `Retry-After`.

This is deliberately not Core's provider-fetch success policy. Core is a required,
installed dependency, selected by `pyproject.toml`; its public `Context.http` door
owns retried body fetching. Its public `get`/`fetch` results do not retain successful
HTTP status, and `stream` promises body consumption, not a status-probe result.
Provider refusals and exhausted retries therefore are not an interchangeable
attestation taxonomy. Sharing this transport would first need a public status-only,
one-attempt probe preserving HTTP answers, rather than importing Core provider internals,
copying retry policy or silently changing the preflight claim.

The [main-branch remediation (PR #353)](https://github.com/traust-security/traust/pull/353)
uses the same non-5xx-answer policy. This development follow-up preserves that URL
semantics; authorization and soundness remain separate validation gates.

## Recording owner and gates

`traust validation record` parses exact report bytes as core's
`ValidationArtifact`, then calls `Context.services().validation.record` with explicit
stored source/finding bindings and the actual producer run's provenance. It does
not discover baselines, reinterpret source labels as UUIDs, walk source paths,
authenticate a machine as a human, or write a second ledger/state format.

When publishing and approving a structured HTTP plan, Core's immutable scope
snapshot carries the explicit context API, targets and discovery grants,
credential permissions, TLS/session policy and lease deadline. Anonymous
Service tunnels require the explicit namespace/resource authorization, not a
blanket loopback or Route/Node host grant. Approval does not replace the live
resolver's per-resource, method and destination checks.

Core's `ValidationObservations.soundness` owns the policy;
legacy executor/report adapters translate observations into those models, not a
second app implementation of the rules.

| Gate | Required observation and outcome |
|---|---|
| Target attestation | Full embedded or explicitly supplied `target-attestation.json`; explicit false voids EVERY verdict, at any age. Missing required evidence retains `attestation_missing`; failed evidence retains `environment_invalid`. Both route to review without a validity decision. |
| Positive controls | Real same-session controls on refuting probes; failed controls are unsound at every age, missing passing controls are unsound when required. No control is fabricated from an expected result. |
| Differential probe | An authz oracle must distinguish the claimed action from a known-different neighbour when required. A nondiscriminating observation is unsound at every age. |
| Transcript soundness | Probe errors, validator Forbidden/auth failures, zero-subject RBAC, unsubstituted templates, absent target and supplied install-failure observations cannot refute a claim. Their retained detailed cause reaches review. |
| Explicit evidence grade | E3 confirmations and current-policy ungraded confirmations request review. Missing grades remain null; report type, channel, actor and version never infer proof strength. |
| Canonical recording | An admitted confirmation records `confirmed`; a sound refutation records `false_positive` pending verified human signoff, never automatic dismissal. Inconclusive/blocked/not-attempted evidence cannot become a validity conclusion. |
| Severity proposal | A supplied proposal is review-only. Machine validation never writes severity overrides. OWASP risk-rating methodology is unchanged; CVSS observation fields do not replace it. |
| Native integrity | Source membership/digests and ledger integrity gate the whole aggregate, including replay review mutations. Refusal leaves no partial decision, review, assessment or evidence metadata. |

Soundness flags are retained in immutable core evidence and linked to the finding
through existing external references, including voided verdicts with no decision
row. Review uses the canonical review-reason vocabulary; detailed causes stay in
the evidence, not invented registry values. Human review cards expose those linked
observations for inspection.

## Current and historical admission

`ValidationRecordInput.policy` defaults to `current`. The version reset does not
make a current run legacy: attestation, controls, differential probing and explicit
confirmation grades remain required. The existing unattended runner requires
current policy and an isolated `environment: lab` rules-of-engagement scope.

Only a deliberate `historical` replay applies the original introduction cutoffs:
attestation 0.176.0, controls 0.177.0, differential 0.178.0 and confirmation grades
0.179.0. Malformed/unknown versions refuse instead of silently grandfathering.
Explicit failed attestation, failed controls, nondiscriminating oracles and actual
error signatures remain invalid at every age. An admitted legacy confirmation's
missing grade stays unknown; it is not promoted to execution proof.

Core preserves explicit evidence precedence. Existing E0 proof stays open until
two independent later E0 human judgements concur; an ungraded legacy record or
machine refutation cannot bypass that rule. Replays are idempotent and append
history without rewrites; distinct runs/target environments remain distinct.

## Artifact flow

```text
explicit authorized scope + actual preflight observations
    -> existing guarded execution (full service port remains separate)
    -> StepResult observations, audit log and evidence companions
    -> report.build_validation_json -> report.write (typed pre-write gate)
    -> traust validation record + stored source bindings + actual provenance
    -> core immutable validation artifact + recording evidence
    -> canonical decision OR retained-cause review item
    -> core ReviewItemCase -> verified human countersign when required
```

`run.py` performs that report/record handoff and records an actual run UUID/start
instant before execution. For external producers, supply their original run
provenance instead of creating a new UUID/time on each import. Source references
stay opaque report labels; every source report and finding needs a validated
binding. The report's original source IDs survive planner-local multi-repo prefixes.
Auxiliary surface/credential counts and an exact datetime lease expiry, when
present, live under `metadata.additional.validation_producer`; the schema's
`metadata.expires` remains date-only. The declared `not_attempted_reason` retains
skip causes. Chain context is bounded; transcripts
are not multiplied across every chain.

### Credential-safe execution evidence

The guarded adapters share the skill-local
[`adapters/credentials.py`](../harnessing/5-validate/validate-findings/adapters/credentials.py)
redactor for artifact content and observed transcripts. Core's public
`traust_core.v1.models.redaction.SecretDetector` owns the secret shapes shared with
publication redaction. This adapter owns only strict marker rendering and recursive
JSON Secret/SecretList `data`/`stringData` traversal; execution, classification,
rollback and artifact storage remain in `AdapterBase`.
Every Secret-map value is masked, including arbitrary custom keys. Plain-text
credential assignments retain their key prefixes; DSN passwords, JWTs, PEM/key
material and forge/cloud tokens are masked without retaining a secret prefix.
Existing redaction markers retain their evidence lengths/digests on repeat passes.

`_save_artifact` hashes the **original UTF-8 content**, writes only redacted
content, and retains the existing `type`, relative `path`, `sha256` and `caption`
metadata, adding `redacted: true` when the stored content differs. The digest is
not a checksum of the sanitized file. Verdict logic still reads the original
in-memory transcript; observed text is redacted before its display-length cap
so truncation cannot prevent Secret-map traversal.

`SecretDetector.evidence_rules()` includes every publication detector automatically,
plus stricter evidence variants and key-material shapes owned in that same Core
catalog. A new shared shape therefore reaches saved evidence without a second local
regex table. Publication keeps its existing prefix/marker semantics through
`core.services().redaction`; validation never calls that weaker renderer. Only known
emitted tags with canonical ASCII lengths and 12 lowercase hexadecimal digest
characters (or length-only `secret-data` markers) are opaque. Marker-like wrappers,
unknown tags and embedded legitimate markers cannot hide surrounding credentials.

No local cumulative rebuild, refuted-register refresh or retired emitter is part
of this path. Supplied install-failure text and full target-attestation checks are
retained by core; adjacent files are never silently discovered at the CLI edge.
The runner does not fabricate controls, grades, replay artifacts or novel intake
that the unfinished live execution port has not produced: missing required
observations route safely to review.

Supplied CVSS observations and chain context remain evidence for a human's
severity review, including downgrades as well as upgrades. They do not change the
rating methodology or authorize a machine severity override. Core retains a
supplied severity proposal as review-only evidence rather than writing severity.

## Remaining boundaries

This is the step19 machine-recording producer/readiness slice, not completion of
plan24 preparation, planning, authorization or live execution services. Novel
finding intake, browser-specific report adaptation, scanner adapter/model and
carried/cumulative families remain separate work. Historical deployment/corpus
mapping acceptance and live portfolio counts are separate gates and are not
certified here.

Related references: [error model](error-model.md),
[human review workflow](../harnessing/4-triage/track-findings/SKILL.md),
[artifact catalog](artifacts.md), and
[benchmark fixtures](../harnessing/5-validate/validate-findings/benchmark/expected.json).
