---
description: "Build a portfolio security summary from current findings, risk, remediation, and audit coverage."
---

Build the cross-portfolio executive summary of security-audit findings using the executive-summary-findings skill. Load the skill at .claude/skills/executive-summary-findings/SKILL.md and follow its full procedure — running python3 -m traust.cli dashboard view executive-summary --out <dir> with the flags implied by $ARGUMENTS (open / summary / --product <slug> / --as-of <ISO time>), and reporting the headline severity totals, credential-leak count, top risk themes, and output file paths back to the user.
