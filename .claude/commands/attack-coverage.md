---
description: "Summarize fleet MITRE ATT&CK coverage by observed, modeled, and derived evidence."
---

Build the fleet MITRE ATT&CK coverage roll-up using the attack-coverage skill. Load the skill at .claude/skills/attack-coverage/SKILL.md and follow its procedure — running traust dashboard view attack-coverage (with --out from $ARGUMENTS, default progress-tracker/metrics/dashboards/attack-coverage), then reporting the technique counts per evidence class (observed / modeled / derived), tactics covered, any dropped references, and the paths to attack-coverage.json (its navigator_layer) and attack-coverage.md back to the user.
