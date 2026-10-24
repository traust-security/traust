### What the domains mean

| Domain | Question it answers | Scale |
|---|---|---|
| **VULN** (Vulnerability) | Is this repo using crypto a quantum computer could break? | 0 = fully exposed · 100 = no quantum-vulnerable crypto |
| **AGIL** (Agility) | How easy is it to swap the crypto when needed? | 0 = hardcoded everywhere · 100 = fully configurable |
| **PQCA** (PQC Adoption) | Has this repo already adopted post-quantum crypto? | 0 = no PQC · 100 = fully adopted |
| **HNDL** (Harvest risk) | Could traffic recorded today be decrypted by a future quantum computer? | 0 = high-value long-lived data exposed · 100 = no risk |

**Overall** combines these (VULN 40%, AGIL 25%, PQCA 20%, HNDL 15%) into
a 0–100 score — higher = more ready. Buckets: **ready** (≥80, no urgent
items) · **partial** (50–79) · **not-ready** (<50 or significant-effort
items) · **blocked-external** (waiting on vendor/upstream) ·
**not-applicable** (no crypto).
