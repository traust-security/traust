---
description: "Generate and test remediation diffs for a systemic pattern across affected repositories for human review."
---

Remediate a systemic pattern fleet-wide using the fleet-fix skill. Load the skill at .claude/skills/fleet-fix/SKILL.md and follow its full procedure for the mode implied by $ARGUMENTS — identify the affected fleet, select/author the schema-validated transform spec (golden tests mandatory), apply via approved fleet-fix run orders (`traust remediation fleet-submit` / `fleet-claim`) producing diffs only, present the batch for human review, and open MRs only after explicit approval (remediate-finding fork flow). Report applied / no-match / unresolved counts and the burndown picture.
