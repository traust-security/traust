---
description: "Assess a repository’s post-quantum cryptography readiness using collected facts and migration criteria."
---

Run the PQC readiness assessment skill for the repository or worklist given in $ARGUMENTS.

Follow harnessing/3-audit/pqc-readiness/SKILL.md exactly: Layer-1 deterministic facts produced and recorded by Core through `traust pqc prescan` (registered pinned pqc-scan + HP supplement rules for source, or SBOM-only package evidence), then bounded Layer-2 scoring against the NIST IR 8547 tables, schema-validated to 0 errors. Validate an existing facts export with `traust reporting validate <file> --schema pqc-facts`; do not duplicate prescan's recording step.
