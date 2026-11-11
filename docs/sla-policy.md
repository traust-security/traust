# SLA Policy — Configuring Your Own Service Levels

**SLAs are policy data, never code.** Nothing in Traust hardcodes a
remediation deadline. A deployment states its own numbers in an
`sla-policy` artifact, and every view, dashboard and query inherits them.

Policy home: recorded in traust-core. Until you record one, the SLA view uses the security
pack's default, [`packs/security/sla-policy.yaml`](../packs/security/sla-policy.yaml) (the
FedRAMP Rev. 5 RA-5 timelines, with CISA BOD 19-02 as a second profile, sources cited in the
file). Record yours with `traust dashboard sla-policy <file>`: the newest recorded policy is
the view's from then on, and `traust dashboard view sla --sla-policy <file>` uses another for
one run. Schema: `artifacts_schema/v1/sla-policy.schema.json` in traust-contracts.

## Why an artifact and not a config file

A config file would be simpler, and wrong for three reasons:

- **Scope-bound.** A policy binds to a scope, so a per-business-unit or
  per-engagement policy is a *different binding*, not a fork of a shared
  file. A deployment that partitions by business unit gets per-BU SLAs
  with no code change.
- **Versioned and content-addressed.** "Which SLA were we judged against
  in July?" stays answerable. That matters as soon as you trend anything:
  a policy that silently tightened would otherwise look like a spike in
  breaches.
- **One ingest path.** It travels the same route as every other artifact,
  so it works identically whether you keep artifacts in git or in a
  database.

## The shape

```json
{
  "policy_name": "acme-baseline",
  "source": {
    "name": "ACME Security Policy v4",
    "retrieved": "2026-01-15"
  },
  "severity_mapping": {
    "sev1": "critical",
    "sev2": "high",
    "sev3": "medium"
  },
  "clock_start": "first_routed_or_filed",
  "profiles": {
    "baseline": {
      "default": true,
      "description": "Applies unless a stricter profile is selected.",
      "slas": {
        "critical": { "resolve_days": 7,  "acknowledge_days": 1 },
        "high":     { "resolve_days": 30 },
        "medium":   { "resolve_days": 90 },
        "low":      { "resolve_days": null }
      }
    },
    "regulated": {
      "description": "For boundaries under an external obligation.",
      "slas": {
        "critical": { "resolve_days": 3 },
        "high":     { "resolve_days": 14 }
      },
      "cvss_floor_days": { "9.0": 3 }
    }
  }
}
```

## Choosing a clock start

**The same finding has three defensible start times, and they give
different answers.** This is a policy decision, so the policy states it:

| `clock_start` | The clock starts when… |
|---|---|
| `audit_date` | a scanner first reported the finding |
| `first_event` | someone first adjudicated it in the ledger |
| `first_routed_or_filed` | it reached a tracker or a review (**default**) |

`first_routed_or_filed` falls back to `first_event`, then to
`audit_date`, so it degrades to the next-best clock rather than dropping
the finding.

Pick deliberately. `audit_date` measures your whole pipeline including
triage latency; `first_routed_or_filed` measures the owning team's
response once work reached them. Neither is more correct — they answer
different questions, and a mixed estate should not silently use both.

## Three states that are NOT "compliant"

Collapsing any of these to "within SLA" makes an estate look healthier
than it is, so the contract keeps them distinct:

| Situation | `resolve_days` | `breached` |
|---|---|---|
| Past the deadline | a number | `1` |
| Inside the deadline | a number | `0` |
| Severity tracked but deliberately unclocked | `null` | **`null`** |
| No policy ingested at all | `null` | **`null`** |

`breached` is **never** `false` for the last two. An estate with no policy
must not render as fully within SLA.

Likewise, still-open findings are **included** in `finding_sla`. The
breaches are precisely the findings that never closed, so a
closed-findings-only SLA view inverts the metric it claims to report.

## Profiles

Ship as many as you need; mark exactly one `default: true`. The default is
what `sla_threshold` and `finding_sla` resolve. Selecting a stricter
profile is a query-time choice, not a schema change — resolving every
profile at once would give one finding two contradictory deadlines.

A severity absent from a profile's `slas` is **unclocked** under it, and
yields no threshold rather than a fabricated one.

## Reading it back

Both language bindings expose the policy itself, not only who breached it,
so a dashboard can show what the commitment *is*:

| | Python | Go |
|---|---|---|
| the thresholds | `Store.query_sla_threshold` | `Client.QuerySLAThreshold` |
| per-finding state | `Store.query_finding_sla` | `Client.QueryFindingSLA` |

`finding_sla` reports `policy_name`, `profile_name`, `clock_start` and
`clock_started_at` alongside `age_days` and `breached`, so every number is
traceable to the policy that produced it.

## Related

- [disposition-ledger.md](disposition-ledger.md) — the dated event stream
  the clock is computed from
- [storage.md](storage.md) — how artifacts reach the views
