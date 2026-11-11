---
description: "Assess tenant isolation across a service’s interfaces and report evidence-backed hardening gaps."
---

Run the tenant-isolation review skill for the multi-tenant service named in $ARGUMENTS.

Follow harnessing/3-audit/isolation-review/SKILL.md exactly: resolve the service's repo set via `traust isolation repos` (traust-core's products), build the customer-facing interface inventory from graph data plus existing audit/threat-model findings, rate per-interface complexity, score the five isolation-hardening dimensions with cited evidence, and emit the report under analysis-results/isolation/<service-slug>/ — `traust reporting record --kind isolation-review` must accept it. PEACH is cited by reference only; never reproduce or adapt its text.
