---
description: "Show how open findings, remediation velocity, and accepted risk change over time."
---

Build the portfolio findings trends dashboard using the findings-trends skill. Load the skill at .claude/skills/findings-trends/SKILL.md and follow its full procedure — run python3 -m traust.cli dashboard view findings-trend --out <dir> with $ARGUMENTS (optional: --bucket month|week, --since <ISO time>, --product <slug>, --as-of <ISO time>), which replays every repo's recorded findings and decisions against time buckets and writes the view's {json,md,html} to --out. Then read the markdown back to the user: lead with the direction table (open findings, CVSS-sum risk index, remediation velocity, MTTR, new findings, regressions, FP rate, accepted risk index, ledger coverage), call out any worsening ⚠ metrics and the Accepted Risk Register (formally accepted findings — unfixed and unmitigated), and state the ledger-coverage caveat: ledger-less repos count as open by design.
