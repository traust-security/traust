---
description: "Report overdue findings and remediation SLA compliance under the selected policy."
---

Build and report the owner-response SLA view using the sla-view skill. Load the skill at .claude/skills/sla-view/SKILL.md and follow its procedure — run python3 -m traust.cli dashboard view sla --out <dir> with the policy/as-of implied by $ARGUMENTS and read the profile asked for (default: the policy's default profile), and report overdue counts (criticals first), resolved-SLA compliance, the per-team overdue table, the transparency rows (unclocked / out-of-profile-scope), and the accountable contact per digest row when the Product Security registry resolves (an escalation path, never an owner). SLAs are policy data — a different SLA regime means a different --sla-policy file, never a code edit; the escalation digest is generated and requires human review before any routing.
