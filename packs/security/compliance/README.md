# Compliance framework data (canonical spine + baselines)

Vendored, license-verified framework data for the `/compliance-check`
skill (plan: `../../plans/compliance-check-plan.md`, epic XWING-397).
Everything here is **derived from public-domain OSCAL sources** —
`provenance.json` records the upstream URL, upstream sha256, retrieval
date, and derivation rule for every file. Nothing in this directory may
contain PCI DSS standard text (harness content guard rule 4) or any
restrictively-licensed framework prose.

| File | Contents | Source |
|---|---|---|
| `spine-800-53-rev5.json` | canonical control spine: 1,196 controls+enhancements (id, title, family, withdrawn flag) | NIST SP 800-53 rev 5 OSCAL catalog (usnistgov/oscal-content, CC0/US-Gov public domain) | <!-- estate-data-ok: public NIST SP 800-53 rev5 catalog size -->
| `profile-800-53b-moderate.json` | 287 control selections | NIST SP 800-53B Moderate baseline OSCAL profile |
| `profile-800-53b-high.json` | 370 control selections | NIST SP 800-53B High baseline OSCAL profile |
| `provenance.json` | upstream URLs, sha256s, retrieval dates, derivation rules | — |

## FedRAMP overlay gap (open item, Phase 0 finding 2026-07-19)

The authoritative FedRAMP rev 5 OSCAL baselines (GSA/fedramp-automation)
were **decommissioned during the FedRAMP 20x transition** — the repo and
automate.fedramp.gov are gone; only community mirrors remain
(e.g. 18farchive/fedramp-automation), which do not meet the provenance
bar for compliance data. Interim posture:

- FedRAMP Moderate/High assessments run against the **NIST 800-53B
  Moderate/High selections** (what the FedRAMP baselines are built on),
  labeled as such in every report — never presented as the FedRAMP
  baselines themselves.
- The FedRAMP-specific overlays (parameter values, selected additions)
  should be acquired through an authoritative channel: Red Hat's own
  FedRAMP program teams (ROSA-GC / ARO ATOs hold the official baseline
  documents). Until then, FedRAMP-only deltas report `not_assessed
  (fedramp overlay unavailable)`.

## Refresh procedure

Re-download from the URLs in `provenance.json`, verify the upstream
sha256 changed intentionally (NIST revision), re-derive with the same
rules, update `provenance.json` retrieval date. Frameworks are data:
consumers (the Phase 1 mapping registry, the Phase 3 skill) never
hardcode control lists.
