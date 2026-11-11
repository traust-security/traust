---
description: "Report stale artifacts, dependency drift, and overdue harness maintenance."
---

Run the staleness and drift report using the drift-watch skill. Load the skill at .claude/skills/drift-watch/SKILL.md and follow its procedure — run python3 -m traust.cli dashboard view freshness --out <dir>, read freshness.md back leading with stale then unavailable items, and offer (never auto-execute) the refresh commands. The view routes attention and never concludes; pending items are named with the phase that closes them.
