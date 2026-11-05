---
name: sla-view
description: >-
  Use when the user asks about SLA compliance, overdue findings, response/remediation deadlines, breach counts, or escalation lists — e.g. "what's past SLA", "criticals overdue", "are we meeting the 30-day clock", "SLA view for FedRAMP", "who's most overdue". Replays the clocks of the findings recorded in traust-core against a schema-validated SLA policy (default: the deployment's sla-policy.yaml in the config home) and emits sla-view-<policy>.{md,html,json} with per-team overdue tables and a human-gated escalation digest.
metadata:
  harness.tier: "secondary"
---

# SLA View — Owner-Response Clocks

> **Paths.** `analysis-results/…` and `progress-tracker/…` in this skill are the
> default workspace layout. They resolve through `locations:` in `traust.yaml` in
> `$TRAUST_CONFIG_HOME` (`docs/setup.md`, Storage locations); substitute your
> configured roots.


Per-severity resolve clocks over every clocked finding, scored against a
policy file: traust-core's `SlaView`, through `traust dashboard view sla`.
This is the adoption metric that replaced the retired
"team packages delivered" count: it measures whether owners respond,
not whether we shipped them lists.

## The one rule that matters

**SLAs are policy data, never code.** The default policy is the
deployment's, recorded with `traust dashboard sla-policy <file>` (until one
is recorded: the security pack's `packs/security/sla-policy.yaml`; gated by
`contracts/schemas/sla-policy.schema.json`, provenance + retrieval date
inside). It never falls back to placeholder SLAs.
Different SLAs — customer contracts, per-BU policies — are a different
file passed with `--sla-policy`, never an edit to the script. The
severity mapping (PSIRT Important→high, Moderate→medium, Low→low) is
part of that data, because external severity vocabularies and the
harness enum are different languages and the join must stay auditable.

## Procedure

1. **Freshness first** — *retired:* the view reads recorded state, so
   there is no projection to rebuild.

2. **Build the view** (every profile of the policy, the default first):

   ```bash
   python3 -m traust.cli dashboard view sla \
       [--sla-policy <other-policy.yaml>] [--as-of <ISO time>] \
       [--product <slug>…] [--team-id <uuid>…] \
       --out progress-tracker/metrics/dashboards/sla
   ```

   Output: `progress-tracker/metrics/dashboards/sla/sla-view-<policy>.{md,html,json}`.
   *Retired:* `--profile` (every profile is in the one view; read the one
   asked for) and `--pd-cache-dir` (no product-definitions door yet; the
   report says "Accountable contacts: unavailable").

3. **Report back**: overdue count (lead with criticals), resolved-SLA
   compliance %, the per-team overdue table, and the unclocked /
   out-of-scope counts (transparency rows — findings the profile does
   not clock are counted, never silently dropped). Label the profile on
   every number: internal-cve and fedramp-rosa-gc figures are different
   clocks over the same findings, not different findings. When a digest
   row carries an `accountable_contact` (Product Security registry),
   report it with the caveat that an accountable contact is an
   escalation path, **not** an owner — anyone acting on one checks the
   contact against the deployment's employee directory first (the
   `traust.yaml` `identity.directory_command`, where one is configured).

## Clock semantics (deterministic, stated in the artifact)

- Clock start ladder (`clock_start: first_routed_or_filed`): first Jira
  link → earliest report or decision → first report. No
  ladder rung ⇒ `unclocked`, counted and shown, never guessed.
- `resolve_days: null` = tracked, never overdue (PSIRT Low).
- `cvss_floor_days` (FedRAMP ARO): CVSS ≥ threshold overrides the
  severity clock.
- Resolved findings score compliance against their due date; median
  days-to-resolve is reported per severity.

## Constraints

- **The escalation digest is generated, never auto-sent.** Routing it
  to individuals or channels requires human review of the list first.
- **The registry join is optional and corroborating.** Accountable
  contacts come from python3 -m traust.cli registry products at trustworthy
  match tiers only (`mapped`/`repo-url` — a slug guess never lands in an
  unattended artifact). An absent or off-VPN cache reads as
  `source_status: unavailable` in the metadata with null contacts —
  never a failed run. Escalation contacts confer no disposition
  authority, and only tier 1 is embargo-cleared (see
  `assign-findings-owners` Step 6 for the rules — not restated here).
- Branch re-audits are *retired* (one finding per repository fingerprint,
  one clock); hardening/FP classes are excluded like every dashboard.
  Risk-accepted findings are counted under `accepted`, never overdue.
- The census remains the denominator authority; when an SLA headline
  will be quoted upward, state the profile, the policy retrieval date,
  and the `as_of` (all embedded in the artifact metadata).
- When touching the shipped policy file, re-verify the values at the
  source URL and update `source.retrieved`.

## Integrations

**Consumes:** traust-core's findings, decisions, Jira links and repository
owners (`SlaView`); the recorded SLA policy, else `packs/security/sla-policy.yaml`
(human-curated policy data); `analysis-results/feeds/product_definitions.json`
(producer: python3 -m traust.cli feeds fetch-products, read via
python3 -m traust.cli registry products) plus the recorded product map (`registry product-map`)
for the accountable-contact join (NEED(core: a product-definitions provider
giving `SlaView` each product's accountable contacts; until then the view
reports contacts unavailable)).

**Emits:** `progress-tracker/metrics/dashboards/sla/sla-view-<policy>.{md,html,json}` —
read by humans and quoted by the executive dashboards; the escalation
digest inside it is generated, never auto-sent.
