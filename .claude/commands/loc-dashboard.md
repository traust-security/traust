---
description: "Report security audit coverage measured in lines of code across the campaign."
---

Build the lines-of-code coverage dashboard using the loc-dashboard skill. Load .claude/skills/loc-dashboard/SKILL.md and follow its full procedure: run `python3 -m traust.cli dashboard view loc --out <dir>` with the product/team scope, as-of/comparison times and explicitly requested first-party divisor from $ARGUMENTS. Read the generated `lines-of-code.json` and report measured LoC, repository counts, unmeasured reasons and output paths; unknown measurements are not zero. For `explore`, run `python3 -m traust.cli dashboard explore-loc --out <dir>/loc-explorer.html`, open that page and import the matching JSON export. For an executive-summary missing-language diagnostic, pass this same-scope JSON to /executive-summary-findings; never use rendered prose as a counting source.
