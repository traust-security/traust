---
description: "Refresh the campaign scoreboard and historical metrics for coverage, impact, validation, delivery, and maturity."
---

Rebuild the campaign metrics scoreboard using the traust-metrics skill. Load the skill at .claude/skills/traust-metrics/SKILL.md and follow its full procedure — run harnessing/traust-metrics/scripts/collect_harness_metrics.py with $ARGUMENTS (optional: --workspace-root <dir>, --out <file>), which harvests headline numbers from the executive summary, findings trends, validation/fuzz dashboard, threat register, progress-tracker control files, and the harness tree/git metadata, and writes progress-tracker/metrics/traust-metrics.md (preserving the manual talking-points block). Then read the scoreboard back to the user grouped by section (scale, impact, validation, delivery, maturity), flagging any MISSING or stale sources in the data-freshness table and any metric that moved sharply since the previous version of the file.
