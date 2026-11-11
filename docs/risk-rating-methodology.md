# Risk-rating methodology

How the harness turns per-finding scores into portfolio risk metrics, and
why. Implemented in traust-core's `RatingPolicy`
(`traust_core.v1.services.findings.rating`); surfaced by `/findings-trends`
(`traust dashboard view findings-trend`) and `/traust-metrics`.

## Machine-readable definition

The factor mappings, bucket thresholds, 3×3 matrix, and fallbacks below
are the tables in `RatingPolicy` (ported from methodology 1.1.0, which
lived in a JSON file beside the findings-trends skill until its port). To evolve the methodology, change them there
and let core's table-driven rating tests gate the change.

## The methodology: OWASP Risk Rating

Portfolio risk headlines follow the
[OWASP Risk Rating Methodology](https://owasp.org/www-community/OWASP_Risk_Rating_Methodology):

> **risk = likelihood × impact**

Each factor scores 0–9 and buckets **LOW** (< 3) / **MEDIUM** (< 6) /
**HIGH** (≥ 6); the two buckets combine on the OWASP 3×3 matrix into an
overall band:

| overall risk | impact LOW | impact MEDIUM | impact HIGH |
|---|---|---|---|
| **likelihood LOW** | Note | Low | Medium |
| **likelihood MEDIUM** | Low | Medium | High |
| **likelihood HIGH** | Medium | High | Critical |

## Deriving the factors from finding data

OWASP's worksheet factors (threat-agent skill, opportunity, ease of
discovery/exploit, technical impact, …) are estimated per finding. Our
findings carry CVSS 3.x vectors authored at audit time, and those vectors
already encode the evidence-backed subset of the OWASP factors, so the
factor scores are derived deterministically — no per-finding
re-estimation, fully reproducible from the report JSON plus (when the
exploitation-evidence factor below applies) the pinned threat-intel
feeds-cache snapshot:

**Likelihood** = mean of the exploitability metrics present in the vector:

| CVSS metric | OWASP factor it evidences | scores |
|---|---|---|
| Attack Vector (AV) | opportunity | N=9, A=7, L=5, P=3 |
| Attack Complexity (AC) | ease of exploit | L=9, H=3 |
| Privileges Required (PR) | skill / access required | N=9, L=5, H=2 |
| User Interaction (UI) | victim interaction needed | N=9, R=4 |

**Exploitation-evidence factor** (methodology v1.1.0): when a finding
carries a CVE id and the threat-intel feeds cache is present
(`<results-root>/feeds/`, FIRST EPSS + CISA KEV), `threat_intel_score()`
(`RatingPolicy`) appends one more score to the likelihood mean
alongside the CVSS exploitability metrics: KEV membership scores 9;
otherwise the highest EPSS score across the finding's CVEs maps through
the `threat_intel_factor.epss_bands` in the methodology JSON
(≥ 0.5 → 9, ≥ 0.1 → 7, ≥ 0.01 → 5, else 2). No CVE id or no feeds
cache means the factor is simply absent and likelihood uses the CVSS
factors only (the engine warns on stderr when the feeds are
unavailable). Because the feeds change over time, reproducing a rating
that used this factor requires the same feeds-cache snapshot.

**Impact** = mean of the technical-impact metrics (per C, I, A):
H=9, L=4, N=0.

**Fallback** (finding has no CVSS 3.x vector): impact comes from the
severity band (critical 9, high 7, medium 5, low 2, informational 0) and
likelihood defaults to MEDIUM (4.5). Unknown exploitability is never assumed
HIGH, so vector-less findings cannot reach the Critical risk band. The share
of vector-less findings is a property of each corpus, not of the
methodology.

Business-impact factors (financial, reputational, compliance, privacy) are
not assessable from source code and are deliberately out of scope; per
OWASP, technical impact is the correct basis when business context is
unavailable.

## Portfolio roll-up

Per time bucket (ledger replay, open findings only):

- `owasp_open` — count of open findings per band
  (critical/high/medium/low/note): the headline distribution.
- `owasp_high_plus_pct` — % of open findings rated High or Critical: the
  single ratio-scale trend number (0–100, lower is better), charted on
  the executive dashboard as "OWASP High+Critical share of open (%)".

## Retired series

The earlier headline was a "risk index" (`risk_index`,
`risk_index_combined`): raw sums of effective CVSS scores over open
findings (plus a λ-weighted hardening term). It was retired as a headline
because a sum of severity scores is unnormalized — it scales with corpus
size, has no bounded scale, and CVSS v4.0 explicitly states scores measure
severity, not risk, with no basis for summing. `mean_cvss_open` (the interim
replacement) is likewise demoted: it is a severity intensity, not a risk
measure. The engine still computes both into every trend snapshot, and the
trends dashboard still shows them as legacy columns beside the OWASP bands,
so historical series stay comparable; they are no longer the headline and
are never revised in the append-only metrics ledger.

## Threats

Threat models use the same method at full strength: a threat has no CVSS
vector to derive factors from, so the author scores all eight likelihood
factors and the four technical (and, when the owner supplies them, four
business) impact factors directly. The factor guide is the threat-model
skill's [Scoring guide](../harnessing/2-threat-model/threat-model/schema.md#scoring-guide);
the arithmetic is `traust_contracts.v1.risk_rating`, and the rendering and
lint rules are `traust_engine.reporting.threat_rating`. The threat register
ranks threats by the resulting severity. Models written before the method
carry legacy labels until their next update, and are ordered meanwhile by a
labelled crosswalk that is never reported as a rating.
