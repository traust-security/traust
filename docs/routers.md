# Routers — the authoritative index

"Router" is overloaded in this harness. **Seven distinct kinds** carry the name,
implemented across **16 components** (the two tables below are grouped by kind, so
one row can name more than one module). They do different and sometimes opposite
jobs, and confusing them has caused real defects. This page is the single index:
what each one is, what it may and may not write, and where the detail lives.

If you are auditing coverage, the 16 are: `build_rescan_worklist.py` (work
routing + the budget guard inside it), `budget_shadow.py`,
`traust_engine.registry.models`, `route_regressions.py`,
`route_impact_findings.py`, `/assign-findings-owners` (internal extension),
`/reassign-findings-owners` (internal extension), `/file-security-defect`,
`emit_drain_tranche.py`, `traust remediation verify-sweep`, `build_pqc_worklist.py`,
`traust impact sweep`, `traust feeds fetch` (`feeds_fetch.py`).

| Kind | Routes | Implementation | Detail |
|---|---|---|---|
| **Work routing** — *the rescan router* | repos → one of 12 scan lanes | `build_rescan_worklist.py` | [continuous-operations.md](continuous-operations.md) |
| **Cost routing** — *the budget guard* | **drops queued work to fit a USD ceiling** | budget guard inside `build_rescan_worklist.py`; `budget_shadow.py` | [continuous-operations.md](continuous-operations.md) |
| **Model routing** | a task → a model tier, and what it costs | `traust_engine.registry.models`, `config/model-registry.yaml` | [model-routing.md](model-routing.md) |
| **Findings routing** | a producer's findings → ledger events | `route_regressions.py`, `route_impact_findings.py` | [findings-routing.md](findings-routing.md) |
| **Owner routing** | findings packages → teams and named maintainers | `/assign-findings-owners` (internal extension), `/reassign-findings-owners` | those skills' `SKILL.md` |
| **Defect routing** | findings → Jira issues | `/file-security-defect` (internal extension) | those skills' `SKILL.md` |
| **Feed routing** — *the security-data refresh* | external sources → traust-core feed snapshots | `traust feeds fetch` (`ExposureService.refresh_feeds`), `config/feeds.yaml` | [continuous-operations.md](continuous-operations.md) |

### Worklist builders — routing's other half

A router decides *what* and a **worklist builder** materialises *which*. They are
listed separately because each one is a selection decision that can silently drop
work, and none of them authors a finding:

| Builder | Selects | Detail |
|---|---|---|
| `emit_drain_tranche.py` | this week's tranche from the router's drain ordering | [continuous-operations.md](continuous-operations.md) |
| `traust remediation verify-sweep` (traust-core `VerificationService.sweep`) | the `/verify-remediation` full-sweep worklist | `harnessing/8-verify/verify-remediation/SKILL.md` |
| `build_pqc_worklist.py` | one entry per unique repo URL for the PQC sweep | `harnessing/3-audit/pqc-readiness/SKILL.md` |
| `traust impact sweep` (traust-core `ExposureService.sweep`) | `/dependency-watch`'s bootstrap / full-baseline OSV sweep | `harnessing/3-audit/dependency-watch/SKILL.md` |

---

## 1. Work routing — the rescan router

**Decides what work to do.** Reads fleet change signals and emits
`rescan-worklist.json`: one row per repo, each assigned a lane —
`full-audit+validate`, `full-audit`, `impact-lane`, `iac-lane`, `iac-baseline`,
`release-passthrough`, `threat-model-review`, `deps-lane`, `diff-scan`,
`diff-scan-quarterly`, `threat-model-quarterly`, `none`.

**Writes:** the worklist, nothing else. Read-only over its inputs, it **never
authors a finding, verdict, or audit**, and never self-tunes.

**Why it matters beyond scheduling:** it holds the authority over **when a new
baseline is cut** — exactly what a producer appending findings straight into a
baseline used to bypass (§4).

→ **[continuous-operations.md](continuous-operations.md)**

## 2. Cost routing — the budget guard

**Decides what the harness can afford to do.** This is a router in the literal
sense: when the projected spend of the routed worklist exceeds the ceiling in
`$TRAUST_CONFIG_HOME/budget-policy.yaml`, **lowest-tier table-routed full audits are dropped
to fit** and listed in `dropped_for_budget`. Event-injected rows are never
dropped.

**Know before relying on it:** `enforcement` in
`$TRAUST_CONFIG_HOME/budget-policy.yaml` takes `none | observe | advisory |
enforced`. At `observe` the guard does shadow accounting only: the ceiling is a
recorded verdict, not a control, and **nothing is ever withheld**. Only
`advisory` and `enforced` bind a run, and moving to either is a deliberate
deployment decision, never a side effect. The code states the principle plainly:
*"a config that documents its own non-enforcement is honest; one that implies
enforcement it lacks is a vulnerability."* `budget_shadow.py` does the shadow
accounting for observe mode.

**Writes:** the worklist's drop list and shadow ledger. Never a finding.

→ **[continuous-operations.md](continuous-operations.md)**

## 3. Model routing

**Decides which model does what, and what it costs.** Skills name a *tier class*
and resolve it through the registry; concrete model identifiers may appear only in
`config/model-registry.yaml`, enforced by alignment rule **A12**.

**Writes:** nothing in the findings pipeline — it selects the executor and records
spend attribution. CLI: `python3 -m traust.cli registry models
{validate|list|resolve|stamp|spend}`.

→ **[model-routing.md](model-routing.md)**

## 4. Findings routing

**Records work already done.** Turns a producer's findings into ledger events, so
nothing audit-grade lives only inside a producer's report — an unrouted finding
has no owner, no SLA clock, no disposition history, and no dashboard presence.

**Writes:** the disposition layer (`*-findings-layer.json`) — stamped and signed.
**Never the baseline.** Only `/secure-code-audit`, `/secure-rpm-audit` and
`/secure-container-audit` may write `*-{security,rpm,container}-audit.json`,
enforced by alignment gate **A15**.

- **`route_regressions.py`** — the `regressions[]` array of a `/verify-remediation` verification report
- **`route_impact_findings.py`** — `/impact-analysis` `affected` dependency CVEs

→ **[findings-routing.md](findings-routing.md)**

## 5. Owner routing

**Decides who is accountable.** Resolves two lead developers per findings package
from `owners.csv`, org team structures, CI `OWNERS` files, directory-service
verification, and git commit email resolution.

**Writes:** progress-tracker control files, document-share permissions, the
ownership tracker. Never a baseline, never a ledger event.

→ `assign-findings-owners` / `reassign-findings-owners` (internal extension repo)

## 6. Defect routing

**Moves a finding into the tracker.** Files a Jira defect with the Security Level
set, or syncs a backlog against the ledger's current state.

**Writes:** Jira. The ledger records the issue key as evidence; Jira never becomes
the system of record — `/track-findings` ingests ticket state back into the
ledger, not the other way round.

→ `file-security-defect` (internal extension repo; backlog sync against a
specific tracker project is an internal-extension skill, not part of the harness)

## 7. Feed routing — the security-data refresh

**Decides which external sources to pull, and when.** Reads
`config/feeds.yaml` — the registry covering both the cached tier this
snapshots and the live tier `fetch_advisory.py` queries — and snapshots
every cached source through traust-core (`ExposureService.refresh_feeds`);
the pack's `feeds_cache` cadence decides when.

**Why it is a router and not a pipeline job:** the same reason every other
runner here is one. A router is the orchestrator-neutral seam — the same
command behaves identically from an operator session, cron, a platform
worker, or an enterprise scheduler. Binding the refresh
to a CI pipeline in this repository would couple it to one orchestrator and
break that property, which is precisely what the abstraction exists to
prevent.

**Writes:** a traust-core `feed_snapshot` per source, its bytes in core's
object store (the `rh-cve` snapshot is what its next run builds on).
**Never a finding, never a
baseline, never a worklist.** Read-only over its registry; it does not
self-tune and cannot advance a pin.

**Cadence:** daily. Every security source in the registry is public, so the
lane needs no private network and no credentials. Network-gated,
non-security registries (such as `product-definitions`, a product/ownership
registry) are deliberately excluded from `--feed all`, so a run outside the
private network never fails.

**Backstop:** drift rows `feeds:*` at 48h — one missed run plus slack. Paired
`feed-source:*` rows probe both tiers for liveness, so a source that starts
answering 404 surfaces as `drift` instead of failing silently.

CLI: `python3 -m traust.cli feeds fetch --feed all`

→ **[continuous-operations.md](continuous-operations.md)**

---

## The distinction worth remembering

The **rescan router** and the **findings routers** are the two most easily
confused, and they do opposite jobs:

|  | rescan router | findings routers |
|---|---|---|
| Question answered | *what should we scan?* | *what did we find?* |
| Direction | forward-looking | backward-recording |
| Authors findings | **never** | that is its entire job |
| Baseline authority | decides **when one is cut** | may **never write one** |

They meet at exactly one point, and it is the point that breaks when the two
are confused: a producer appending to a baseline records a finding *against a
commit it was not found at*, without the rescan router's re-baseline decision.
Gate A15 exists to close exactly that path.
