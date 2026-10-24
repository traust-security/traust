---
description: "Report security audit coverage measured in lines of code across the campaign."
---

Build the lines-of-code coverage dashboard for the security-audit campaign using the loc-dashboard skill. Load the skill at .claude/skills/loc-dashboard/SKILL.md and follow its full procedure — running python3 -m traust.cli dashboard view loc --out <dir> with the flags implied by $ARGUMENTS (open / summary / --product <slug>), and reporting the headline LoC figures and output file paths back to the user.
