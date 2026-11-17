# Risk-rating methodology

How the harness turns per-finding scores into portfolio risk metrics, and
why. Implemented in traust-core's `RatingPolicy`
(`traust_core.v1.services.findings.rating`); surfaced by `/findings-trends`
(`traust dashboard view findings-trend`) and `/traust-metrics`.

> **Status (2026-11-17).** The **threat-model** rating ([Threats](#threats)) is
> live. The **per-finding** rating is **in development**: the factor
> derivation, the exploitation-evidence (EPSS/KEV) factor and the portfolio
> OWASP roll-up below. `RatingPolicy` implements the derivation, but no finding
> read calls it, and the findings-trend view reports no OWASP bands. Findings
> are ranked today by severity (a person's re-rating, else the scanner's), by
> the SLA due date, and by the [risk index](#risk-index-the-current-headline).
> The scoring is still under review before it rates findings, so the tables
> below may change.

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

## Deriving the factors from finding data (in development)

OWASP's worksheet factors (threat-agent skill, opportunity, ease of
discovery/exploit, technical impact, …) are estimated per finding. Our
findings carry CVSS 3.x vectors authored at audit time, and those vectors
already encode the evidence-backed subset of the OWASP factors, so the
factor scores are derived deterministically — no per-finding
re-estimation, fully reproducible from the report JSON plus (when the
exploitation-evidence factor below applies) the pinned threat-intel
feeds-cache snapshot:

An advisory-backed finding (a dependency, image or SBOM finding tied to a CVE or GitHub advisory) takes its CVSS from the vulnerability feeds instead, ranked NIST > GitHub > CNA > ADP > Red Hat > scanner: see [vulnerability-feeds.md](vulnerability-feeds.md) for the precedence, how a score is resolved, and what is live today.

**Likelihood** = mean of the exploitability metrics present in the vector:

| CVSS metric | OWASP factor it evidences | scores |
|---|---|---|
| Attack Vector (AV) | opportunity | N=9, A=7, L=5, P=3 |
| Attack Complexity (AC) | ease of exploit | L=9, H=3 |
| Privileges Required (PR) | skill / access required | N=9, L=5, H=2 |
| User Interaction (UI) | victim interaction needed | N=9, R=4 |

**Exploitation-evidence factor** (in development): `RatingPolicy`
appends one more score to the likelihood mean alongside the CVSS
exploitability metrics. KEV membership scores 9; otherwise the highest EPSS
score across the finding's CVEs maps to a band (≥ 0.5 → 9, ≥ 0.1 → 7,
≥ 0.01 → 5, else 2). No CVE, or no EPSS/KEV snapshot, means the factor is
absent and likelihood uses the CVSS factors only. Nothing supplies the
factor yet. EPSS and KEV are fetched daily (`traust feeds fetch`) and will
first be shown per CVE on a finding's detail and in its report, as
exploitability. Until the per-finding rating is settled they change no
severity, due date, risk index or rating. Because the feeds change over time,
reproducing a rating that used this factor will require the same snapshot.

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

## Portfolio roll-up (in development)

Planned, per time bucket (ledger replay, open findings only). The
findings-trend view does not report these yet:

- `owasp_open` — count of open findings per band
  (critical/high/medium/low/note): the headline distribution.
- `owasp_high_plus_pct` — % of open findings rated High or Critical: the
  single ratio-scale trend number (0–100, lower is better), to be
  charted on the executive dashboard as "OWASP High+Critical share of open (%)".

## Risk index: the current headline

Until the OWASP roll-up is live, the findings-trend view's headline is the
**risk index** (`risk_index`): the sum of open findings' CVSS scores, with a
finding that has no CVSS counting its severity band's midpoint (critical 9.5,
high 8.0, medium 5.5, low 2.0, informational 0). The **accepted risk index**
(`accepted_risk_index`) is the same sum over risk-accepted findings.

It is meant to be replaced, because a sum of severity scores is unnormalized:
it scales with corpus size, has no bounded scale, and CVSS v4.0 explicitly
states that scores measure severity, not risk, with no basis for summing. Once
the OWASP roll-up is live, the risk index stays as a legacy series, so
historical trends stay comparable.

## Threats

Threat models use the same method at full strength: a threat has no CVSS
vector to derive factors from, so the author scores all eight likelihood
factors and the four technical (and, when the owner supplies them, four
business) impact factors directly. The factor guide is the threat-model
skill's [Scoring guide](../harnessing/2-threat-model/threat-model/schema.md#scoring-guide);
the arithmetic is `traust_contracts.v1.risk_rating`, and the rendering and
lint rules are `traust_core.v1.services.reporting.threat_rating`. The threat register
ranks threats by the resulting severity. Models written before the method
carry legacy labels until their next update, and are ordered meanwhile by a
labelled crosswalk that is never reported as a rating.
