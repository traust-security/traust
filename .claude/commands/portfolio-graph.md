---
description: "Build or query the portfolio dependency graph to trace shared components and vulnerability impact."
---

Build, refresh, or query the portfolio source-code graph using the portfolio-graph skill. Load the skill at .claude/skills/portfolio-graph/SKILL.md and follow it: `python3 -m traust.cli impact sbom` records a commit's dependencies in traust-core (syft over the checkout), `python3 -m traust.cli dashboard view dependency-reach` lists the top shared packages, and the blast radius comes from traust-core (`python3 -m traust.cli portfolio dependents --name <package> [--ecosystem <eco>] [--version <v>]`). `$ARGUMENTS` may be a query (e.g. "blast-radius golang.org/x/net") or a commit to record.
