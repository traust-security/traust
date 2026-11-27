---
description: "Propagate an already-verified security fix to the release branches that still need it, and emit a backport report."
---

Backport the security fix $ARGUMENTS using the backport-fix skill. Load the skill at .claude/skills/backport-fix/SKILL.md and follow its full procedure — scan the release branches (fail-closed: needs-review branches are listed, never silently excluded), generate the per-branch configs, run the backport pipeline, then emit and validate the backport report. Delivery of the backported branches is a human decision: never push or open a PR from this command.
