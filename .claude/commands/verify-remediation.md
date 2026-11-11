---
description: "Check patched code against prior audit findings and report resolution evidence and regressions."
---

Verify previous security findings against patched source using the verify-remediation skill. Load .claude/skills/verify-remediation/SKILL.md and follow its complete procedure, passing $ARGUMENTS unchanged. Both the normal report/repository inputs and explicit `--native-input FILE --repo PATH --output FILE [--source-report FILE]` mode are owned by that skill. Native mode consumes the read-only executor input, authors original_id directly from assigned Core finding UUIDs with real source/patch evidence, validates the original verification output through the shared contract, and leaves Core access/recording to the external SDK caller. Never convert report IDs afterward or manufacture metadata/evidence.
