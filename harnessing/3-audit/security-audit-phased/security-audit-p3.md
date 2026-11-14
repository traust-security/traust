---
description: "Hunt systematically for security weaknesses using the phased audit’s reconnaissance and prior findings."
---

Perform Phase 3 (Systematic Weakness Hunt) of the security code audit in progress.

Read the following files from the current working directory before starting:
- `$AUDIT_DIR_NAME/phase1-recon.json` — Phase 1 reconnaissance
- `$AUDIT_DIR_NAME/phase2-prior-vulns.json` — Phase 2 pattern analysis

The source code and prior vulnerability reports are in this conversation.

**Beyond the taxonomy — enforcement-asymmetry hunt (mandatory, runs
alongside the CWE walk):** the highest-yield misses of checklist-driven review are not a
CWE class. Additionally do the following:
- Read the codebase's authorization/enforcement layer end-to-end; for
  every guarded reference to an asset class, enumerate sibling
  references and flag any missing the guard its neighbors carry.
- For every security guard you document ("X is never allowed"), verify
  it on every alternate path to the same sink (create/update/copy/
  retarget; direct/bulk/scheduled/workflow; REST/websocket/callback).
- Before rating any unchecked-sink finding, enumerate ALL emitters to
  that sink — the worst emitter sets the impact.

Work through every CWE category in the taxonomy. For each:
- State whether it is **applicable** to this codebase and language. If not, say why briefly and skip.
- If applicable, **actively search** — do not scan passively. Construct hypothetical attack scenarios and test whether the code defends against them.
- Pay close attention to the **high-priority areas** from Phase 1 and the **patterns** from Phase 2.

**Trust boundary gate — apply to every potential finding before reporting:**
A vulnerability is the ability of a lower-trust context to influence a higher-trust context without adequate validation. Before reporting any finding, determine the minimum privilege an attacker needs to trigger it. If the trigger scenario requires the attacker to already have root, kernel access, or write access to privileged paths, **do not report it** — an attacker with root has simpler paths to damage. Only report findings where a lower-privilege attacker achieves a higher-privilege impact across a real trust boundary. Use the `privilege_contexts` from Phase 1 to inform this assessment.

**Delegated-control check:** When a security control (signature verification, access check, input validation) is performed by a component that already has equal or greater capabilities than what bypassing the control would grant, that control is internal consistency — not a trust boundary. If component A loads and runs component B, and A's own code verifies B, then a compromised A already has code execution and does not need to subvert its own verification. The real trust boundary is whoever verified A. Do not report "A verifies B using A's own code" as a finding when A already controls B's lifecycle.

**Do-not-report classes** (shared with `/vuln-scan`; record as one-line negative results, never as findings):

- volumetric DoS / rate-limiting / resource-exhaustion — BUT unbounded recursion, algorithmic-complexity blowup, or ReDoS driven by untrusted input ARE reportable
- memory-safety findings in memory-safe languages outside unsafe/FFI
- XSS in React/Angular/Vue unless via a raw-HTML escape hatch (`dangerouslySetInnerHTML`, `v-html`, `bypassSecurityTrustHtml`)
- findings whose only locations are test files, fixtures, build scripts, docs, or notebooks
- missing hardening / best-practice gaps with no concrete exploit path
- env vars and CLI flags as the attack vector (operator-controlled — fails the trust-boundary gate above)
- regex injection, log spoofing, missing audit logs, and open redirect as standalone findings — EXCEPT open redirect that leaks credentials, tokens, or session material
- outdated third-party dependency versions (dependency inventory material, not weakness-hunt findings)

Before filing any missing-authn/authz/validation finding, also perform a **compensating-control sweep**: trace one layer above and below the cited code (callee-side checks, ingress validators, sibling middleware, shipped deployment manifests in the repo) and grep the enforcement primitive by name before asserting absence — the single largest measured false-positive class is a control that existed one layer away.

CWE categories to cover (from the taxonomy):
1. Memory Safety — Buffer & String
2. Integer & Numeric Errors
3. Pointer & Memory Lifetime
4. Cryptography
5. Algorithm & Logic Correctness
6. Resource & Lifetime Management
7. Input Validation & Access Control
8. Patch Quality & Protection Mechanisms
9. Tenant Isolation (PEACH)

**Category 9 — Tenant Isolation (PEACH):** Applicable only if `phase1-recon.json → tenant_isolation.applicable` is `true`; otherwise mark `applicable: false` with `skip_reason: "single-tenant"`. For each interface recorded in Phase 1, hunt for violations of the five hardening parameters against the boundary that interface relies on: **PEACH-P** privilege (tenant/host least-privilege, per-op authz includes tenant ID), **PEACH-E** encryption (per-tenant unique keys at rest and in transit), **PEACH-A** authentication (per-tenant unique validated credential to the control plane; self-signed rejected), **PEACH-C** connectivity (default-deny between tenant hosts; hub-and-spoke via control plane; no arbitrary egress), **PEACH-H** hygiene (no cross-tenant secrets, lateral-movement tooling, or other tenants' logs reachable from a tenant). The trust-boundary gate for this category is *tenant → other tenant* or *tenant → control plane*: only report if a tenant-privilege attacker crosses into another tenant's data or into shared control-plane authority. Record the violated parameter ID(s) in each finding's `peach_references` array. Methodology: the PEACH framework by Wiz, Inc. (<https://github.com/wiz-sec-public/peach-framework>); this description is original text.

**Deterministic facts seed the hunt.** When Phase 1 recorded pre-scan
outputs (`khs.json`, `opengrep.json` in the audit dir), start each
category from its matching facts under the same judge protocol as
`/secure-code-audit`'s *Deterministic semantic pre-scan*: judge each fact
in repository context, promote with the fact's `file:line` citation, or
dismiss with a one-line rationale recorded in this phase's JSON
(`scanner_correlation`-shaped: tool, rule/check id, location, promoted or
dismissed). Facts never conclude — categories the scanners don't cover
proceed fully manually, and manual review continues past the facts in
covered categories.

The output must conform to this structure:

Use the following ID format for each finding: `{DIRECTORY}-{YYYYMMDD}-{RUNTOKEN}-{NNN}`, where `DIRECTORY` is the uppercase name of the source directory being audited (e.g. `PODMAN`), `YYYYMMDD` is today's audit date, `RUNTOKEN` is the unique token for this audit run, and `NNN` is a 3-digit sequence starting at `001` and incrementing per finding. The run token for this audit is `$RUN_TOKEN`. If this placeholder was not substituted (i.e. it appears literally as `$RUN_TOKEN`), generate a random 4-character uppercase hex string (e.g. `B2D9`) and use it consistently for all findings in this session. Example: `PODMAN-20260406-$RUN_TOKEN-001`.

```json
{
  "category_results": [
    {
      "category": "Memory Safety — Buffer & String",
      "applicable": true,
      "skip_reason": null,
      "findings": [
        {
          "id": "PODMAN-20260406-$RUN_TOKEN-001",
          "title": "short descriptive title",
          "severity": "Critical|High|Medium|Low|Informational",
          "severity_emoji": "🔴|🟠|🟡|🔵|🟢 (emoji matching severity — 🔴 Critical · 🟠 High · 🟡 Medium · 🔵 Low · 🟢 Informational)",
          "cwe": "CWE-ID",
          "cwe_name": "full CWE name",
          "cwe_chain": ["CWE-ID", "CWE-ID"],
          "location": "file:function:line",
          "description": "what is wrong and why — specific to this code, not generic",
          "trigger_scenario": "concrete step-by-step attacker scenario with specific inputs and preconditions",
          "impact": "worst realistic exploitable impact",
          "evidence": "quoted source code showing the vulnerability",
          "relationship_to_prior": "Novel finding. | Recurrence of [prior]. | Variant of [prior].",
          "recommended_fix": "specific actionable remediation",
          "minimum_access_required": "unauthenticated_remote|authenticated_remote|local_unprivileged|local_root",
          "trust_boundary_crossing": "which trust boundary is crossed, or 'none — same trust level'",
          "peach_references": ["PEACH-P", "PEACH-E", "PEACH-A", "PEACH-C", "PEACH-H (omit field entirely for non-tenant-isolation findings)"],
          "confidence": "High|Medium|Low"
        }
      ]
    }
  ],
  "summary": "prose summary: total findings by severity, most significant results, patterns that emerged",
  "cost": {
    "input_tokens": 0,
    "output_tokens": 0,
    "total_tokens": 0,
    "cost_usd": null
  }
}
```

Include one entry in `category_results` for every category, even if findings is empty or the category is skipped.

**Cost reporting**: Before writing the JSON file, populate the `cost` field from your API usage metadata for this phase: set `input_tokens` and `output_tokens` from the usage data, set `total_tokens` to their sum, and set `cost_usd` to the estimated cost in USD. If your runtime does not expose usage metadata, set `cost_usd` to `null`.

Write the JSON object to `$AUDIT_DIR_NAME/phase3-hunt.json`.

After writing the file, output a brief human-readable note on the most critical findings before the reviewer proceeds to Phase 4.
