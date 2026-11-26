---
description: "Score accepted phased-audit findings with CVSS v3.1 and Red Hat severity ratings."
---

Assess CVSS v3.1 base scores and Red Hat severity ratings for accepted findings from the security code audit in progress.

Read the following files from the current working directory before starting (in this order):
1. `$AUDIT_DIR_NAME/review.json` — to get finding dispositions
2. `$AUDIT_DIR_NAME/phase4-final.json` — for finding ID index and P4 cross-cutting finding details
3. `$AUDIT_DIR_NAME/phase3-hunt.json` — for P3 finding full details
4. `$AUDIT_DIR_NAME/phase2-prior-vulns.json` — for P2 variant finding details (may be empty)
5. `$AUDIT_DIR_NAME/phase6-reproducers.json` — reproducer results that inform Attack Complexity scoring (may be absent; skip gracefully if missing)

Do not rely on any prior conversation context. Treat this as a fresh, independent assessment.

### Finding Lookup Logic

`review.json` `finding_dispositions[]` lists which findings to score and their dispositions. `phase4-final.json` `final_report.all_findings[]` is a **summary index only** — used to determine originating phase, NOT for full finding details. Full details come from the originating phase file.

Use the following lookup priority order based on originating phase:

| Finding phase | Where to look | Fields available |
|---|---|---|
| P4 (cross-cutting) | `phase4-final.json` → `cross_cutting_findings[]` (match by `id`) | All fields: trigger_scenario, impact, evidence, minimum_access_required |
| P3 | `phase3-hunt.json` → `category_results[].findings[]` (match by `id`) | All fields: trigger_scenario, impact, evidence, minimum_access_required |
| P2 (variant) | `phase2-prior-vulns.json` → `pattern_analyses[].variants_found[]` (match by location+description) | Limited: location, description, cwe, severity_estimate only |

If finding phase is ambiguous, use the `phase` field from `final_report.all_findings[]`.

**Fallback**: if a finding cannot be resolved in any phase file, set `detail_missing: true`, score at maximum conservatism (worst-case metric values), and document in `scoring_notes` which files were searched.

### Reproducer-Informed Scoring

If `phase6-reproducers.json` is present, look up each finding's reproducer entry before assessing CVSS metrics. Use the reproducer results as follows:

| Reproducer result | Effect on CVSS scoring |
|---|---|
| `reproducer_type: "not_reproducible"` | Score Attack Complexity as `High` unless there is strong independent evidence that exploitation is straightforward. Document the `not_reproducible` status in `scoring_notes`. |
| `reproducer_confidence: "High"` | The trigger scenario is confirmed reachable. Score Attack Complexity based on the scenario's inherent difficulty, not speculation. |
| `reproducer_confidence: "Medium"` | Score Attack Complexity conservatively (lean toward `High` when ambiguous). |
| `reproducer_confidence: "Low"` | Score Attack Complexity as `High` and note the uncertainty in `scoring_notes`. |
| Finding absent from reproducer output | No reproducer was attempted (e.g., finding was skipped). Score based on the trigger scenario alone; note the absence in `scoring_notes`. |

The reproducer result does not override other metric assessments — it informs AC specifically, and only when it provides useful signal about real-world exploitability.

### CVSS v3.1 Metric Assessment

Use the following metric quick-reference table:

| Metric | Full Name | Options |
|---|---|---|
| AV | Attack Vector | Network (N), Adjacent (A), Local (L), Physical (P) |
| AC | Attack Complexity | Low (L), High (H) |
| PR | Privileges Required | None (N), Low (L), High (H) |
| UI | User Interaction | None (N), Required (R) |
| S | Scope | Unchanged (U), Changed (C) |
| C | Confidentiality Impact | None (N), Low (L), High (H) |
| I | Integrity Impact | None (N), Low (L), High (H) |
| A | Availability Impact | None (N), Low (L), High (H) |

For each accepted or severity_adjusted finding, assess all eight metrics. For each metric record:
- The selected value (e.g., `Network`)
- Its abbreviation (e.g., `AV:N`)
- A **finding-specific justification** that references the trigger scenario, minimum access level, or quoted evidence. Generic descriptions are not acceptable.

Example of ACCEPTABLE justification:
> "Attack Vector: Network (AV:N) — The trigger scenario requires sending a crafted HTTP request to the API endpoint; no local access is needed."

Example of UNACCEPTABLE justification:
> "Attack Vector: Network (AV:N) — The attack can be performed remotely over a network."

After assessing all eight metrics:

1. Construct the CVSS v3.1 vector string: `CVSS:3.1/AV:X/AC:X/PR:X/UI:X/S:X/C:X/I:X/A:X`

2. Score it with the CVSS calculator — never by hand or from formulas:

   ```bash
   python3 -m traust.cli reporting rate-cvss --vector "CVSS:3.1/AV:X/AC:X/PR:X/UI:X/S:X/C:X/I:X/A:X"
   ```

   It prints `{"vector", "score", "severity"}` from traust-core's CVSS
   calculator (the `cvss` library, FIRST's formulas). Copy `score` into the
   finding exactly; a vector it refuses is malformed — fix the metrics, never
   the number.

### Red Hat Severity Rubric and Label Assignment

Assign a Red Hat severity label using the following four-point rubric:

**Critical**: Flaws that could be easily exploited by a remote unauthenticated attacker and lead to system compromise (arbitrary code execution) without requiring user interaction. Flaws that require authentication, local or physical access, or an unlikely configuration are not Critical. These are worm-exploitable vulnerabilities.

**Important**: Flaws that can easily compromise the confidentiality, integrity, or availability of resources. Includes: local or authenticated users gaining additional privileges; unauthenticated remote users viewing resources protected by authentication or other controls; authenticated remote users executing arbitrary code; remote users causing a denial of service.

**Moderate**: Flaws that may be more difficult to exploit but could still lead to some compromise of the confidentiality, integrity, or availability of resources under certain circumstances. Applies to vulnerabilities that could have been Critical or Important but are less easily exploited based on technical evaluation, or affect unlikely configurations.

**Low**: All other issues that may have a security impact. Requires unlikely circumstances to exploit, or a successful exploit would give minimal consequences. Includes flaws present in source code with no current or theoretically possible exploitation vectors found during technical analysis.

Assign the label by matching the finding's characteristics against these rubric criteria — NOT by mapping the CVSS numeric score to a range. The CVSS score informs the assessment but does not mechanically determine the label.

`rh_severity_rationale` must name which rubric criterion applies (quote or paraphrase the relevant text), not just state the label.

Example rationale: "Important — this flaw allows an authenticated remote user to execute arbitrary code, matching the Important rubric criterion for authenticated RCE."

Common score guidance (informational — use rubric criteria for label assignment):
- Local unprivileged kernel crash (DoS): typically 5.5
- Local unprivileged privilege escalation to root: typically 7.8
- Cross-site scripting: typically 6.1 (Low C/I, no A impact)

### Special Case Handling

**`needs_more_investigation` findings** (from `review.json` `needs_more_investigation[]`):
- Include in `scored_findings` (NOT `rejected_findings`)
- Set `disposition: "needs_more_investigation"`
- Score at the most conservative (worst-case) reasonable interpretation of the ambiguity
- Populate `scoring_notes` with: (a) the ambiguity, (b) worst-case interpretation per affected metric, (c) a note that the score may change when the investigation resolves

**P2 variant findings** (`phase2-prior-vulns.json` `variants_found[]` — no trigger_scenario/evidence):
- Set `source_phase: "P2"`
- Populate `scoring_notes`: "Trigger scenario and evidence not available for this P2 variant finding. Scoring is based on location, description, CWE, and severity estimate. Metrics are assessed conservatively."
- Score using description, cwe, severity_estimate; use conservative values where ambiguous

**`detail_missing` findings** (ID not found in any phase file):
- Set `detail_missing: true`
- Set all metrics to worst-case: AV:N, AC:L, PR:N, UI:N, S:C, C:H, I:H, A:H → score 10.0
- Set `rh_severity: "Critical"` with rationale noting worst-case assumed due to missing data
- Populate `scoring_notes` with the finding ID and list of phase files searched

### JSON Output

Output only valid JSON conforming to this schema:

```json
{
  "summary_table": "| CVSS Score | Red Hat Severity | ID | Name |\n|---|---|---|---|\n| 9.8 | 🔴 Critical | PODMAN-20260406-XXXX-001 | Title here |",
  "scored_findings": [
    {
      "finding_id": "PODMAN-20260406-XXXX-001",
      "title": "short descriptive title",
      "location": "file:function:line",
      "source_phase": "P3",
      "disposition": "accepted",
      "original_severity": "High",
      "reviewed_severity": "High",
      "detail_missing": false,
      "cvss_metrics": {
        "attack_vector": {
          "value": "Network",
          "abbreviation": "AV:N",
          "justification": "finding-specific rationale referencing trigger scenario or access level"
        },
        "attack_complexity": {
          "value": "Low",
          "abbreviation": "AC:L",
          "justification": "finding-specific rationale"
        },
        "privileges_required": {
          "value": "None",
          "abbreviation": "PR:N",
          "justification": "finding-specific rationale"
        },
        "user_interaction": {
          "value": "None",
          "abbreviation": "UI:N",
          "justification": "finding-specific rationale"
        },
        "scope": {
          "value": "Unchanged",
          "abbreviation": "S:U",
          "justification": "finding-specific rationale"
        },
        "confidentiality": {
          "value": "High",
          "abbreviation": "C:H",
          "justification": "finding-specific rationale"
        },
        "integrity": {
          "value": "High",
          "abbreviation": "I:H",
          "justification": "finding-specific rationale"
        },
        "availability": {
          "value": "High",
          "abbreviation": "A:H",
          "justification": "finding-specific rationale"
        }
      },
      "cvss_vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
      "cvss_base_score": 9.8,
      "rh_severity": "Critical",
      "severity_emoji": "🔴",
      "rh_severity_rationale": "Remote unauthenticated attacker achieves arbitrary code execution without user interaction — matches the Critical rubric criterion.",
      "scoring_notes": null
    }
  ],
  "rejected_findings": [
    {
      "finding_id": "PODMAN-20260406-XXXX-002",
      "title": "finding title",
      "disposition": "rejected",
      "exclusion_reason": "Excluded from CVSS scoring: finding was rejected by reviewer."
    }
  ],
  "cost": {
    "input_tokens": 0,
    "output_tokens": 0,
    "total_tokens": 0,
    "cost_usd": null
  },
  "total_cost": {
    "input_tokens": 0,
    "output_tokens": 0,
    "total_tokens": 0,
    "cost_usd": null,
    "phases_included": [],
    "phases_missing_cost": []
  }
}
```

**`summary_table`**: columns are CVSS Score | Red Hat Severity | ID | Name, sorted by `cvss_base_score` descending (ties: finding ID ascending). Includes all `scored_findings` entries. Does NOT include `rejected_findings`. Prefix the Red Hat Severity cell with the severity emoji (e.g., `🔴 Critical`, `🟠 High`, `🟡 Medium`, `🔵 Low`, `🟢 Informational`).

**`cost`**: populate from API usage metadata for this phase: set `input_tokens` and `output_tokens` from usage data, set `total_tokens` to their sum, set `cost_usd` to the estimated cost in USD. If your runtime does not expose usage metadata, set `cost_usd` to `null`.

**`total_cost`**: aggregate the `cost` blocks from all phase files:
1. Collect the `cost` object from each of: `phase1-recon.json`, `phase2-prior-vulns.json`, `phase3-hunt.json`, `phase4-final.json`, `review.json`, `phase6-reproducers.json`, and the cvss phase's own `cost` block computed above.
2. For each phase: if the file was missing, or the `cost` key was absent, add that phase key (`"phase1"`, `"phase2"`, `"phase3"`, `"phase4"`, `"review"`, `"reproducers"`, or `"cvss"`) to `phases_missing_cost` and exclude it from numeric sums.
3. Sum `input_tokens`, `output_tokens`, and `total_tokens` across all phases with valid `cost` blocks. For `cost_usd`, sum only the non-null values; if all are null, set `total_cost.cost_usd` to `null`.
4. Set `phases_included` to the list of phase keys that contributed valid `cost` data.

Output the JSON block then write it to `$AUDIT_DIR_NAME/cvss.json`.

After the JSON block, add a brief plain-text summary of the **top 3 highest-scored findings**: include finding ID, name, CVSS score, Red Hat severity, and one sentence on the primary risk.
