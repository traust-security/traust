---
description: "Refresh the campaign scoreboard and historical metrics for coverage, impact, validation, delivery, and maturity."
---

Rebuild the campaign metrics scoreboard using the traust-metrics skill. Load the skill at .claude/skills/traust-metrics/SKILL.md and follow its full procedure — run python3 -m traust.cli dashboard view scoreboard with $ARGUMENTS (optional: --as-of <ISO time>, --out <dir>), which harvests headline numbers from traust-core's executive summary, findings trend and threat register views, and writes progress-tracker/metrics/dashboards/scoreboard/traust-metrics.{md,html,json}. Then read the scoreboard back to the user grouped by section (scale, impact, validation, delivery), flagging any metric that moved sharply since the previous version of the file.
