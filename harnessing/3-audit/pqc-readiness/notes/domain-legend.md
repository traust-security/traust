### What the domains mean

| Domain | Question it answers | Scale |
|---|---|---|
| **VULN** (Vulnerability) | Is this repo using crypto a quantum computer could break? | 0 = fully exposed · 100 = no quantum-vulnerable crypto |
| **AGIL** (Agility) | How easy is it to swap the crypto when needed? | 0 = hardcoded everywhere · 100 = fully configurable |
| **PQCA** (PQC Adoption) | Has this repo already adopted post-quantum crypto? | 0 = no PQC · 100 = fully adopted |
| **HNDL** (Harvest risk) | Could traffic recorded today be decrypted by a future quantum computer? | 0 = high-value long-lived data exposed · 100 = no risk |

**Overall** combines these (VULN 40%, AGIL 25%, PQCA 20%, HNDL 15%) into
a 0–100 score — higher = more ready. The score thresholds remain 80 and 50.
Readiness applies these buckets **in order, first match wins**:

1. **not-applicable** — verified no-crypto coverage, or a software-bill-of-materials-only assessment with every scored check not applicable.
2. **blocked-external** — the dominant blocking path is vendored or externally terminated, or a delegated library has no PQC roadmap.
3. **ready** — score ≥80, no 2030-deadline items, and the PQC-adoption check passes.
4. **partial** — score 50–79, or every deadline item satisfies the assessment's explicit provenance/agility conditions.
5. **not-ready** — score <50, or a first-party deadline item fails the specified agility checks.

Earlier matches take precedence even when a later condition also holds.
After that selection, a score ≥80 with a fleet-wide first-party deadline
item failing those same agility checks is overridden to **partial**, with
a fleet-impact caveat. These readiness conditions do not estimate effort:
unknown effort size remains unknown, and external blocking is recorded
independently. Neither an effort size nor its absence determines a bucket.
