---
description: "Deduplicate findings, verify their evidence, rank confirmed risks, and route them to owners."
---

Triage the security findings at $ARGUMENTS using the triage skill. Load .claude/skills/triage/SKILL.md and follow its complete procedure and output contract; pass all arguments unchanged, including `--prepared-input` for a read-only native Core TriageInput file. That mode never calls intake, prepare or record: the external SDK caller records the original output. Write `<findings-dir>/<repo>-triage.{json,md}` as the skill specifies, and require its final shared canonical-write gate before completion. Checkpointing, verifier voting, kind/verdict semantics and historical compatibility are owned by the skill, not this wrapper.
