---
description: "Summarize live-validation outcomes, coverage, and fuzz-discovered bugs across the portfolio."
---

Build the combined live-validation + fuzzing portfolio dashboard using the validation-fuzz-dashboard skill. Load the skill at .claude/skills/validation-fuzz-dashboard/SKILL.md and follow its full procedure — rendering traust-core's `validation-fuzz` insight view with `traust dashboard view validation-fuzz --out <dir>` (flags implied by $ARGUMENTS: open / summary / --product / --team-id), and reporting the confirmed/refuted/inconclusive verdict totals, validation coverage, fuzz-bug count, top targets by confirmed findings, and the output file paths back to the user.
