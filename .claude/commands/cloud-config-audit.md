---
description: "Assess infrastructure-as-code security with offline scanning and evidence-based finding review."
---

Run the cloud config audit skill for the IaC checkout given in $ARGUMENTS.

Follow harnessing/3-audit/cloud-config-audit/SKILL.md exactly: Layer-1 deterministic facts via the pinned Checkov engine fully offline (traust cloud-config run — no cloud API calls, no platform key, secrets framework skipped), then bounded Layer-2 disposition (dedupe, cited suppressions, rubric-based severity, CWE + control_refs mapping), schema-validated to 0 errors via traust cloud-config check, then recorded via traust cloud-config record. Declared configuration only — the report never claims observation.
