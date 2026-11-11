---
description: "Determine which portfolio repositories are affected by a CVE using dependency and reachability evidence."
---

Determine per-repo CVE affectedness across the portfolio using the impact-analysis skill. Load the skill at .claude/skills/impact-analysis/SKILL.md and follow it: python3 -m traust.cli impact analyze walks the commits' recorded SBOMs for blast radius, deep-scans with language-specific analyzers (Go: govulncheck symbol reachability; Python/Rust/JS/Java: SBOM pin + source-import manifest tier; C/C++: header grep), and records a schema-validated artifact per commit in traust-core, consumed by /triage Phase 2f, /verify-remediation --impact-filter, /fleet-fix worklists, and /file-security-defect citations. `$ARGUMENTS` is the CVE ID plus optional `--symbols`, `--feature-desc`, `--repo-url`/`--sha` and `--scan` (module, range and packages come from the fetched advisory).
