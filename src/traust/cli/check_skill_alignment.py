#!/usr/bin/env python3
"""Cross-skill alignment guard — catch a skill drifting from the contracts
the other skills rely on, before it is committed.

The harness's skills interlock through shared conventions (single-source
report structure, deterministic pre-scan recording, judge protocols,
census-owned liveness, swappable rule packs). Every documented consistency
regression entered through one skill restating or half-adopting a
convention the others had moved past. This checker makes the contracts
mechanical. Data-driven rules; each has an EXEMPTIONS map (path → reason)
so legitimate exceptions are explicit and printed, never silent.

Rules:
  A1 script-refs      Every `scripts/*.py|sh` or `harnessing/*/*.py|sh`
                      referenced from a skill markdown file must exist —
                      a skill instructing a tool that is not in the tree
                      is misalignment with reality.
  A2 opengrep-contract A skill that RUNS run_opengrep.py must carry the
                      recording conventions: `deterministic_steps` plus
                      the judge protocol (scanner_correlation or the
                      promote-or-dismiss reference).
  A3 khs-contract     A skill that runs scan_k8s_hardening.py must carry
                      `deterministic_steps` (exempt: consumers that write
                      no audit report, e.g. threat-model bootstrap state).
  A4 profile-link     A skill that sets metadata.audit_profile must link
                      docs/report-structure.md instead of restating it.
  A5 liveness-source  A skill mentioning repo_status/liveness must name
                      the census artifact (repo-liveness.json) as its
                      source — consumers read the artifact, never
                      re-query GitHub.
  A6 name-matches-dir SKILL.md frontmatter `name:` must equal its
                      directory name (catches copy-pasted skill
                      scaffolding).
  A7 wiring           Every harnessing/<skill>/SKILL.md must have
                      .claude/skills/<skill> and .crush/skills/<skill>
                      symlinks, a .claude/commands/<skill>.md wrapper and
                      its .crush/commands/<skill>.md link — all tracked
                      (exempt: sub-command-only skills).
  A9 artifact-graph   Every hyphenated data artifact a skill emits
                      (backticked filename in an Output section or on a
                      produce-verb line) must be consumed by at least one
                      other skill — unless terminal-classed (dashboards,
                      rollups, summaries) or exempted with a reason.
                      Catches under-wired skills (the operator-priv-profile
                      / impact-analysis gap).
  A12 model-registry  Concrete model identifiers (claude-*, gpt-*,
                      gemini-*, …) may appear ONLY in
                      config/model-registry.yaml — skills and scripts name
                      tier classes and resolve via
                      `traust_engine.registry.models` (lock-in and spend
                      policy live in data, not prose).
  A10 integrations    A skill emitting non-terminal artifacts must carry
                      an Integrations/Downstream section documenting who
                      consumes them.
  A8 checkov-contract A skill that RUNS run_checkov.py must carry the
                      recording conventions: `deterministic_steps` plus
                      the declared-configuration labeling (a
                      declared-only assessment never claims
                      observation).
  A11 broad-allowlist An allowed-tools entry may not grant a whole
                      interpreter or shell (`Bash(python3:*)`,
                      `Bash(bash:*)`, `Bash(*)`, …). An unscoped
                      interpreter is arbitrary code execution — a skill
                      that reads untrusted target checkouts can be
                      steered by scanned content into running it. Scope
                      each script the skill actually runs
                      (`Bash(python3 *<script>.py:*)`). Pre-existing
                      harness-internal tooling skills are grandfathered
                      via printed exemptions; new entries fail.
  A14 anchored-script An allowed-tools interpreter grant may not
                      start its script pattern with a bare `*` — any
                      path ending in that filename matches, including
                      one planted in a hostile checkout. Anchor to the
                      harness tree (`*traust/scripts/<name>.py`). A11
                      catches the unscoped interpreter; A14 catches the
                      unanchored script.
  A17 locations-note  A SKILL.md that names `analysis-results/` or
                      `progress-tracker/` carries the note that those are
                      the default layout resolved through `locations.yaml`
                      in $TRAUST_CONFIG_HOME — a reader outside this
                      deployment cannot otherwise tell a default from a
                      hardcode (52/56 docs named them, 2026-09-07).
  A16 layer-writes    Ledger layers are written through the SDK, never by
                      _write_layer_file or a direct write_text — a direct
                      write bypasses the Backend.mutate lock that keeps
                      mutate+stamp+sign atomic.
  A18 composition-root Engine and config-home resolution happen ONLY in
                      `src/traust/context.py`, the app's single composition
                      root. `HarnessEngine.load()`/`HarnessEngine(...)`
                      elsewhere re-resolves config on its own terms and
                      loses the fail-loud `SystemExit(2)` contract that 93
                      call sites depend on; a direct
                      `deployment_config_dir()` bypasses `traust.paths`.
                      Importing HarnessEngine for a type annotation is
                      fine — this matches the CALL. Zero violations at
                      landing: a ratchet, not a cleanup.
  A13 skills-doc-sync A staged harnessing/*/SKILL.md change must be
                      accompanied by a regenerated docs/skills.md, so
                      the skills reference cannot silently lag the skill
                      (the 2026-07-25 docs sweep found ~25% of entries
                      lagging). Active only under the pre-commit hook
                      (HARNESS_PRE_COMMIT=1); a genuinely doc-irrelevant
                      change (typo, comment) is waived with
                      SKILLS_DOC_WAIVER=<reason> on the commit command.
  A15 baseline-owner  ONLY /secure-code-audit, /secure-rpm-audit and
                      /secure-container-audit may write an audit baseline
                      (`*-{security,rpm,container}-audit.json`). Every
                      other skill or script writes a LEDGER LAYER, never
                      the baseline. Mutating a baseline changes the claim
                      set with no event recording it, which breaks the
                      disposition ledger's core tenet (events, not state
                      — docs/disposition-ledger.md §2.2) and bypasses the
                      rescan router's authority over when a new baseline
                      is cut. Found 2026-08-17: findings had been
                      appended into baselines by three non-audit
                      producers, undetected because the write was named
                      "the sanctioned-append flow" in code while the docs
                      called the baseline immutable — and no gate checked
                      it. Burn-down tracked in
                      progress-tracker/plans/baseline-immutability-plan.md.

The U-series comes from the skill-usability reorganization plan
(progress-tracker/plans/skill-usability-reorganization-plan.md §8), whose
rules are numbered U1–U17 there. They land in this checker rather than a
separate check_skill_ux.py so they inherit its four invocation points —
pre-commit, gates:mr-tree, the pinned-gate job, and the test suite — and
so a taxonomy failure reaches the author at commit time. The Un ids are
kept as-is for traceability back to the plan.

  U3 tier            Every SKILL.md declares `metadata.harness.tier`, one
                      of primary | secondary | tertiary | ci. The tier
                      records whether a skill should exist — primary does
                      work only an LLM can do; secondary stands in for
                      capability the surrounding tooling does not provide;
                      tertiary is an org-specific island or not an LLM's
                      job; ci is the harness's own gates — and it governs
                      the investment each one earns
                      (docs/skills.md#tiers, plan §1). Takes NO
                      exemptions, deliberately: the fix is one
                      frontmatter line, and a partial taxonomy is worse
                      than none, because indexes and tier queries built
                      on it would silently under-report (plan §10, "U3 is
                      enum-strict from day one, so partial adoption fails
                      loudly").

Usage:
    python3 -m traust.cli.check_skill_alignment [--root .]

Exit 0 = aligned, 1 = misalignment found (each finding printed). Wired
into .githooks/pre-commit; also runs in the test suite and via the
/check-alignment skill.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path

from traust.paths import (
    HARNESS_ROOT,
    skill_dirs,
    skill_md_paths,
    skill_scripts,
)

REPO = HARNESS_ROOT

SCRIPT_REF_RE = re.compile(r"(?:scripts|harnessing/[a-z0-9-]+)/[A-Za-z0-9_./-]+\.(?:py|sh)\b")

# --- A15: only the three secure*audit skills own an audit baseline.
BASELINE_OWNER_SKILLS = frozenset(
    {"secure-code-audit", "secure-rpm-audit", "secure-container-audit"}
)
BASELINE_FILE_RE = re.compile(r"-(?:security|rpm|container)-audit\.json")
# A write whose target is a baseline-bearing identifier. Catches the shared
# `_write(audit_path, audit)` form both routers use, plus direct writes.
BASELINE_WRITE_PY_RE = re.compile(
    r"(?:_write|write_json)\(\s*(?:audit|baseline)\w*"
    r"|(?:audit|baseline)\w*\.write_text\("
    r"|json\.dump\([^,]+,\s*open\(\s*(?:audit|baseline)\w*"
)
# Prose instructing or describing a baseline mutation.
#
# Widened 2026-08-18 by the B9 audit, which found SEVEN non-owner skills carrying
# baseline-write prose that this gate passed clean. Every miss was a phrasing
# detail, not a new idea:
#   * verb inflection — "appends" (only append/appended were covered)
#   * interposed words — "append **it** to the baseline"
#   * "to the baseline" as well as "into the baseline"
#   * adjectival forms — "the **amended** *-security-audit.json finding"
#   * possessives — "routes every regression into the **repo's** baseline"
# A15 passing while the rule was broken in seven places is how B7's
# baseline-written findings accumulated: the gate checked a phrasing, not a claim.
_BASELINE_VERB = (
    r"(?:amend|append|add|writ|merg|rout|fold|insert|inject|updat)"
    r"(?:e|es|ed|ing|en|s)?"
)
_BASELINE_TARGET = (
    r"(?:the\s+|its\s+|their\s+|repo's\s+|original\s+|originating\s+"
    r"|existing\s+)*(?:baseline|audit report"
    r"|\S*-(?:security|rpm|container)-audit\.json)"
)
BASELINE_WRITE_MD_RE = re.compile(
    rf"{_BASELINE_VERB}\b[^.\n]{{0,90}}?\b(?:in)?to\s+{_BASELINE_TARGET}"
    rf"|\bamended\s+`?\S*-(?:security|rpm|container)-audit\.json"
    rf"|{_BASELINE_VERB}\s+{_BASELINE_TARGET}\b[^.\n]{{0,40}}"
    rf"\b(?:finding|findings|entry|entries)\b",
    re.IGNORECASE,
)
# Sentences that state the rule rather than break it must not trip the gate.
BASELINE_WRITE_MD_NEG_RE = re.compile(
    r"never\s+(?:writ|append|add|the\s+baseline)|not\s+writ|is never written"
    r"|may\s+(?:not|never)|must\s+(?:not|never)|only\s+/secure|gate\s+A15"
    r"|stops?\s+writing|instead\s+of\s+(?:the\s+)?baseline|no longer"
    # Remedial phrasings: a sentence contrasting the event-carried flow WITH the
    # baseline write is stating the rule. Found by the gate flagging this very
    # change's own wording ("rather than a write to the baseline audit").
    r"|rather\s+than\s+(?:a\s+)?(?:writ|append|the\s+baseline)"
    r"|carr(?:y|ies|ied)\s+on\s+(?:its|the|a)\s+(?:ledger\s+)?event",
    re.IGNORECASE,
)
RUNS_OPENGREP_RE = re.compile(r"run_opengrep\.py")
RUNS_KHS_RE = re.compile(r"scan_k8s_hardening\.py")
RUNS_CHECKOV_RE = re.compile(r"run_checkov\.py")
DECLARED_RE = re.compile(r"declared[ -](configuration|layer)", re.IGNORECASE)
JUDGE_RE = re.compile(
    r"scanner_correlation|promote-or-dismiss|"
    r"promoted \*and\* dismissed|judge protocol",
    re.IGNORECASE,
)
PROFILE_RE = re.compile(r'audit_profile[":\s]+"?(code|rpm|container)"?')
LIVENESS_RE = re.compile(r"repo_status|source_repo_status|repo liveness", re.IGNORECASE)
FRONTMATTER_RE = re.compile(r"\A---\n(.*?\n)---", re.DOTALL)
# A11: an allowed-tools list entry granting a whole interpreter/shell (or
# Bash on anything) instead of a specific script. Anchored to list-entry
# lines so prose/comments *about* the pattern never match.
BROAD_ALLOW_RE = re.compile(
    r"^\s*-\s*Bash\(\s*(?:\*|(?:python3?|sh|bash|zsh|ksh|fish|node|deno|"
    r"bun|perl|ruby|php|npx|pip3?|uv|uvx|osascript|xargs|eval|exec)"
    r"\s*(?::\s*\*)?)\s*\)\s*$",
    re.MULTILINE,
)

# path (repo-relative) → reason. Exemptions are printed on every run so
# they stay reviewed, not forgotten.
# --- A9/A10: artifact producer/consumer graph -------------------------
# Backticked artifact filenames in SKILL.mds (data artifacts, not repo
# files). Placeholders (<repo>, <cve>, *) normalize to '*' so producer
# and consumer spellings match.
ARTIFACT_TOKEN_RE = re.compile(
    r"`([^`\s]*[*>a-z0-9][-a-z0-9_.<>*]*\.(?:json|jsonl|md|ya?ml|csv|html))`", re.IGNORECASE
)
# repo files / meta files are not data artifacts
ARTIFACT_SKIP_RE = re.compile(
    r"(^|/)(SKILL|README|AGENTS|PROCESS|CHANGELOG|TRIAGE|PATCHES)\.|"
    r"contracts/|traust-ledger/|scripts/|docs/|config/|tests/|tables/|notes/|\.schema\.json$|"
    r"^(go|package|pom|cargo|pipfile|requirements|pyproject|makefile)",
    re.IGNORECASE,
)
# human-terminal artifacts (dashboards, rollups, exec summaries) need no
# machine consumer
# Shrunk 2026-07-31 (wiring F1): `-plan\.`, `queue`, `owners`,
# `-repos\.` and `manifest` auto-exempted real pipeline artifacts
# (attack-plan.yaml, countersign-queue, owners.csv, *-repos.csv,
# findings.db) that all HAVE consumers — they must prove their
# wiring like everything else.
ARTIFACT_TERMINAL_RE = re.compile(
    r"dashboard|rollup|summary|one-pager|navigator-layer|drift-report|"
    r"census|trends|-stats|tracker|worklist|metrics|-analysis\.md",
    re.IGNORECASE,
)
PRODUCE_LINE_RE = re.compile(
    r"emit|write|produce|generat|land |lands |output|saves?\b|-> |→", re.IGNORECASE
)
OUTPUT_HEADING_RE = re.compile(r"^#{1,4}\s*.*(output|emits|artifacts?)\b", re.IGNORECASE)
MODEL_ID_RE = re.compile(
    r"\b(claude-(?:mythos|opus|sonnet|haiku|fable)[a-z0-9.-]*|"
    r"gpt-[45][a-z0-9.-]*|gemini-[0-9][a-z0-9.-]*|o[13](?:-mini|-pro)?)\b"
)
# attribution/license prose legitimately names products, not model IDs
MODEL_ID_SKIP_LINE_RE = re.compile(
    r"claude\.com|anthropic\.com|claude-code|LICENSES/|NOTICE|"
    r"defending-code-reference",
    re.IGNORECASE,
)

INTEGRATIONS_HEADING_RE = re.compile(
    r"^#{1,4}\s*.*(integration|downstream|consum)", re.IGNORECASE | re.MULTILINE
)


def _artifact_key(token: str) -> str:
    base = token.rsplit("/", 1)[-1].lower()
    return re.sub(r"<[^>]*>|\*+", "*", base)


def _keys_match(a: str, b: str) -> bool:
    if a == b:
        return True
    import fnmatch

    return fnmatch.fnmatch(a, b) or fnmatch.fnmatch(b, a)


# Structured declaration lines inside an Integrations section. When a
# skill carries these, they are AUTHORITATIVE: heuristic verb/arrow
# production detection is suppressed for that skill (P1 of the A9/A10
# rework, docs-verification 2026-07-31 wiring F1 — arrows in
# track-findings' verdict-mapping table credited it as producer of five
# artifacts it consumes, while secure-code-audit's real emission under
# "### Report File Name" was never recorded).
_EMITS_LINE_RE = re.compile(r"^\*\*Emits\b[^:]*:?\*\*|^\*\*Emits\b[^:]*:", re.IGNORECASE)
_CONSUMES_LINE_RE = re.compile(r"^\*\*Consumes\b[^:]*:?\*\*", re.IGNORECASE)


def _skill_artifacts(text: str) -> tuple[set, set]:
    """Return (produced_keys, mentioned_keys) for one SKILL.md."""
    verb_produced, output_produced, mentioned = set(), set(), set()
    declared_emits, declared_consumes = set(), set()
    has_declarations = False
    in_output_section = False
    para_mode = None  # "emits" | "consumes" | None — sticky across a paragraph
    for line in text.splitlines():
        if re.match(r"^#{1,4}\s", line):
            in_output_section = bool(OUTPUT_HEADING_RE.match(line))
            para_mode = None
        if not line.strip():
            para_mode = None
        if _EMITS_LINE_RE.match(line.strip()):
            para_mode, has_declarations = "emits", True
        elif _CONSUMES_LINE_RE.match(line.strip()):
            para_mode, has_declarations = "consumes", True
        for m in ARTIFACT_TOKEN_RE.finditer(line):
            tok = m.group(1)
            if ARTIFACT_SKIP_RE.search(tok):
                continue
            key = _artifact_key(tok)
            if len(key.replace("*", "")) < 6:
                continue  # too generic to graph
            if "-" not in key and para_mode is None:
                # harness artifacts are hyphenated (<slug>-<kind>);
                # hyphen-free names are state/scratch/config files —
                # UNLESS explicitly declared (PATCHES.json was silently
                # dropped by this filter; wiring F1)
                continue
            mentioned.add(key)
            if para_mode == "emits":
                declared_emits.add(key)
                continue
            if para_mode == "consumes":
                declared_consumes.add(key)
                continue
            if re.search(r"(emitted|produced|written|generated)\s+by", line, re.IGNORECASE):
                continue  # "emitted by /X" is consumption, not production
            if in_output_section:
                output_produced.add(key)
            elif PRODUCE_LINE_RE.search(line):
                verb_produced.add(key)
    if has_declarations:
        # Declarations are authoritative: the verb/arrow heuristic is
        # suppressed (that is what mis-credited consumers as producers);
        # Output-section detections are kept, and anything the skill
        # declares it merely consumes is never its production.
        produced = (declared_emits | output_produced) - declared_consumes
    else:
        produced = verb_produced | output_produced
    return produced, mentioned


EXEMPTIONS: dict[tuple[str, str], str] = {
    # --- cross-repo consumers (open-source-upstream-plan.md Phase 4) -------
    # These artifacts DO have consumers; the consumers are the campaign skills
    # that live in the internal extension repo, not in this one. Surfaced when
    # validate-core-ocp and validate-operator-live moved out — the plan
    # anticipated needing this category and called it an "explicit cross-repo
    # exemption". Reinstate as normal wiring if a skill here starts consuming
    # them, and delete these entries when the extension repo is real so an
    # unused exemption cannot hide a genuinely orphaned output.
    (
        "A1",
        "harnessing/5-validate/validate-findings/SKILL.md",
    ): "cross-repo: cites validate-core-ocp/scripts/gen_targets.py, now in "
    "the internal extension repo (upstream plan Phase 4)",
    (
        "A9",
        "validate-findings:install-failure.yaml",
    ): "cross-repo: consumed by deploy-operator, which moved to the internal "
    "extension repo 2026-09-07 (its only callers were already there)",
    (
        "A9",
        "validate-findings:validation-priority-list.md",
    ): "cross-repo: VALIDATION-PRIORITY-LIST.md drives the campaign skills "
    "in the internal extension repo",
    (
        "A9",
        "validate-findings:*-attack-plan.yaml",
    ): "cross-repo: the globbed form; the campaign run drivers that consumed "
    "it are in the internal extension repo (the bare `attack-plan.yaml` "
    "key below predates the move and stays for the un-globbed emission)",
    (
        "A9",
        "crypto-analysis:*-crypto-analysis.json",
    ): "governance report consumed by humans/compliance collection; "
    "skill-graph consumer lands with the compliance-collector wiring",
    (
        "A9",
        "crypto-analysis:*-crypto-audit.json",
    ): "collector output consumed by pqc-readiness via crypto_probe "
    "imports and runtime-probe reconciliation, referenced there by "
    "tier name rather than filename",
    (
        "A9",
        "isolation-review:*-isolation-review.json",
    ): "service-level PEACH deliverable; consumed by progress-tracker "
    "rollups and service owners, not by another skill (threat-register "
    "join is a planned Phase 1+ item)",
    (
        "A9",
        "isolation-review:*-isolation-review.md",
    ): "human companion of the isolation-review JSON",
    (
        "A9",
        "mine-ledger:tp-corpus.jsonl",
    ): "rule-authoring specification corpus consumed by the opengrep-pack "
    "test-and-calibrate workflow (human loop, by design)",
    (
        "A9",
        "validate-findings:attack-plan.yaml",
    ): "execution plan produced AND consumed inside the same validation "
    "run (plan → execute); the slug-prefixed portfolio copy "
    "(*-attack-plan.yaml) is the artifact validate-operator-live "
    "references — surfaced when the terminal-filter shrink removed "
    "the -plan. auto-exemption (2026-07-31 A9/A10 rework)",
    (
        "A9",
        "security-audit-phased:phase4-final.json",
    ): "terminal report of the phased lane; enters the pipeline via /triage generic JSON ingest",
    (
        "A9",
        "threat-model:*-threat-model.json",
    ): "the contract artifact, whose consumer is the STORAGE LAYER rather "
    "than a skill: store_ingest routes it as the `threat-model` family and "
    "traust_contracts.v1.storage projects it into `threat`, read through "
    "the `threat_current` / `threat_exposure` views. A9 can only see "
    "skill-to-skill wiring, and requiring one here would push the estate "
    "back to re-parsing prose — the thing the schema exists to end. A "
    "database adopter reads the views with no skill in the path. Delete "
    "this entry if a skill starts reading the JSON directly",
    (
        "A9",
        "vuln-scan:*-vuln-findings.md",
    ): "human companion of *-vuln-findings.json (consumed by /triage and /patch)",
    (
        "A9",
        "vuln-scan:*-diff-packet.json",
    ): "diff-mode scratch evidence bundle produced AND consumed inside "
    "the same skill (Step 0b build_diff_packet.py -> cluster "
    "briefs); never a campaign artifact",
    (
        "A7",
        "security-audit-phased",
    ): "phase prompts are the commands (security-audit-init etc.); the "
    "skill dir intentionally has no same-name wrapper",
    (
        "A2",
        "harnessing/check-licensing/SKILL.md",
    ): "mentions run_opengrep.py only as the swappable-input example in "
    "the never-vendor constraint; runs no scan and writes no report",
    (
        "A8",
        "harnessing/drift-watch/SKILL.md",
    ): "names run_checkov.py only as the checkov-pin check target; "
    "runs no scan and writes no report",
    (
        "A8",
        "harnessing/triage/SKILL.md",
    ): "names run_checkov.py only in the deterministic-tooling coverage "
    "map (which path each scanner's output takes into triage); "
    "runs no scan and writes no cloud-config report",
    # (A11 grandfather set RETIRED 2026-07-31 P1-W4: census,
    # corpus-intake, insecure-patterns and repo-graph now carry
    # per-script anchored grants.)
    # (recall-benchmark entry REMOVED 2026-07-31: it was misclassified —
    #  the skill clones third-party repos, i.e. target-facing, which this
    #  block's preamble explicitly excludes. Grants now anchored per
    #  script; assessment 2026-07-31 scan-C1.)
    # (A11 git-grant migration queue RETIRED 2026-07-31 P1-W4: all 8
    # holders migrated to subcommand-scoped grants; -C-shaped skills
    # keep a documented Bash(git -C:*) residual pending command-shape
    # rework — see sandbox-adoption-plan.)
    # --- A14 anchor burn-down (P1-W4): `python3 *<name>.py` patterns
    # predate the rule. Anchoring to *traust/… breaks
    # invocations that cd into the harness first, so each skill's
    # invocation shapes are verified before its grants move — remove
    # the entry with the migration. Burn-down, never permanent. ---
    (
        "A14",
        "harnessing/check-harness-docs/SKILL.md",
    ): "P1-W4 anchor queue — verify invocation shapes, then anchor",
    (
        "A14",
        "harnessing/check-skill-security/SKILL.md",
    ): "P1-W4 anchor queue — verify invocation shapes, then anchor",
    (
        "A14",
        "harnessing/countersign/SKILL.md",
    ): "P1-W4 anchor queue — verify invocation shapes, then anchor",
    (
        "A14",
        "harnessing/dependency-watch/SKILL.md",
    ): "P1-W4 anchor queue — verify invocation shapes, then anchor",
    (
        "A14",
        "harnessing/fleet-fix/SKILL.md",
    ): "P1-W4 anchor queue — verify invocation shapes, then anchor",
    (
        "A14",
        "harnessing/impact-analysis/SKILL.md",
    ): "P1-W4 anchor queue — verify invocation shapes, then anchor",
    (
        "A14",
        "harnessing/patch/SKILL.md",
    ): "P1-W4 anchor queue — verify invocation shapes, then anchor",
    (
        "A14",
        "harnessing/remediate-finding/SKILL.md",
    ): "P1-W4 anchor queue — verify invocation shapes, then anchor",
    (
        "A14",
        "harnessing/secure-code-audit/SKILL.md",
    ): "P1-W4 anchor queue — verify invocation shapes, then anchor",
    (
        "A14",
        "harnessing/threat-model/SKILL.md",
    ): "P1-W4 anchor queue — verify invocation shapes, then anchor",
    (
        "A14",
        "harnessing/threat-register/SKILL.md",
    ): "P1-W4 anchor queue — verify invocation shapes, then anchor",
    (
        "A14",
        "harnessing/track-findings/SKILL.md",
    ): "P1-W4 anchor queue — verify invocation shapes, then anchor",
    (
        "A14",
        "harnessing/validate-findings/SKILL.md",
    ): "P1-W4 anchor queue — verify invocation shapes, then anchor",
    (
        "A14",
        "harnessing/vuln-scan/SKILL.md",
    ): "P1-W4 anchor queue — verify invocation shapes, then anchor",
    # --- A14: python -m grants from the scripts/ extraction (2026
    # refactor). Same burn-down queue as P1-W4; anchor after verifying
    # invocation shapes. ---
    (
        "A14",
        "harnessing/census/SKILL.md",
    ): "refactor queue — python -m grants pending A14 anchor pass",
    (
        "A14",
        "harnessing/check-alignment/SKILL.md",
    ): "refactor queue — python -m grants pending A14 anchor pass",
    (
        "A14",
        "harnessing/check-licensing/SKILL.md",
    ): "refactor queue — python -m grants pending A14 anchor pass",
    (
        "A14",
        "harnessing/cloud-config-audit/SKILL.md",
    ): "refactor queue — python -m grants pending A14 anchor pass",
    (
        "A14",
        "harnessing/crypto-analysis/SKILL.md",
    ): "refactor queue — python -m grants pending A14 anchor pass",
    (
        "A14",
        "harnessing/drift-watch/SKILL.md",
    ): "refactor queue — python -m grants pending A14 anchor pass",
    (
        "A14",
        "harnessing/financial-tracking/SKILL.md",
    ): "refactor queue — python -m grants pending A14 anchor pass",
    (
        "A14",
        "harnessing/mine-ledger/SKILL.md",
    ): "refactor queue — python -m grants pending A14 anchor pass",
    (
        "A14",
        "harnessing/portfolio-graph/SKILL.md",
    ): "refactor queue — python -m grants pending A14 anchor pass",
    (
        "A14",
        "harnessing/refresh-dashboards/SKILL.md",
    ): "refactor queue — python -m grants pending A14 anchor pass",
    (
        "A14",
        "harnessing/secure-container-audit/SKILL.md",
    ): "refactor queue — python -m grants pending A14 anchor pass",
    (
        "A14",
        "harnessing/triage/SKILL.md",
    ): "refactor queue — python -m grants pending A14 anchor pass",
    (
        "A14",
        "harnessing/verify-remediation/SKILL.md",
    ): "refactor queue — python -m grants pending A14 anchor pass",
}


# A11 structural leg (P1 gate rework 2026-07-31): binaries whose
# UNSCOPED grant is arbitrary code execution or unbounded reach.
# Version-suffixed and path-prefixed spellings normalize to these
# (python3.11, /usr/bin/python3) — the old regex missed both, plus
# flow-style and quoted YAML list entries entirely.
_BROAD_HEADS = frozenset(
    {
        "*",
        "python",
        "python2",
        "python3",
        "sh",
        "bash",
        "zsh",
        "ksh",
        "fish",
        "dash",
        "node",
        "deno",
        "bun",
        "perl",
        "ruby",
        "php",
        "npx",
        "pip",
        "pip3",
        "uv",
        "uvx",
        "osascript",
        "xargs",
        "eval",
        "exec",
        "env",
        "find",
        "make",
        "open",
        "git",
    }
)
_GRANT_RX = re.compile(r"^Bash\(\s*(.*?)\s*(?::\s*(\*|[^)]*))?\)$")


def _normalize_head(word: str) -> str:
    """Strip path prefix and interpreter version suffix:
    /usr/bin/python3.11 → python3, pip3.12 → pip3."""
    base = word.rsplit("/", 1)[-1]
    m = re.match(r"^(python[23]?|pip3?)(?:\.\d+)?$", base)
    return m.group(1) if m else base


def _parse_frontmatter(text: str):
    """(frontmatter dict | None, error | None) — fail-closed YAML parse."""
    fm = FRONTMATTER_RE.match(text)
    if not fm:
        return None, None  # no frontmatter block at all
    try:
        import yaml

        data = yaml.safe_load(fm.group(1))
    except Exception as e:
        return None, f"frontmatter is not parseable YAML ({type(e).__name__})"
    if not isinstance(data, dict):
        return None, "frontmatter is not a YAML mapping"
    return data, None


def _broad_allow_failures(text: str, rel: str, used: list[str]) -> list[str]:
    """A11/A14 over the PARSED allowed-tools list — structural, so
    flow-style lists, quoted entries, version-suffixed interpreters and
    path-prefixed binaries can't slip past a line-anchored regex."""
    data, err = _parse_frontmatter(text)
    if err:
        return [
            f"A11 {rel}: {err} — a gate that cannot read the "
            "allowlist must fail, not pass (P1 gate rework)"
        ]
    if not data:
        return []
    tools = data.get("allowed-tools")
    if tools is None:
        return []
    if not isinstance(tools, list):
        return [f"A11 {rel}: allowed-tools is not a list — unreadable allowlists fail closed"]
    fails = []
    broad, wildcard = [], []
    for entry in tools:
        if not isinstance(entry, str):
            broad.append(repr(entry))
            continue
        m = _GRANT_RX.match(entry.strip())
        if not m:
            continue  # non-Bash grant (Read, Task, mcp__…)
        body = m.group(1).strip()
        words = body.split()
        if not words:
            broad.append(entry)
            continue
        head = _normalize_head(words[0])
        if head in _BROAD_HEADS and len(words) == 1:
            broad.append(entry)
        # A14: interpreter grant whose script pattern starts with a bare
        # wildcard — `python3 *foo.py` matches ANY path ending foo.py,
        # including one inside a hostile checkout. Anchor to the harness
        # tree: `python3 *traust/scripts/foo.py`.
        elif (
            head.startswith(("python", "node", "ruby", "perl", "php"))
            and len(words) > 1
            and words[1].startswith("*")
            and "traust/" not in words[1]
        ):
            wildcard.append(entry)
    if broad and not _exempt("A11", rel, used):
        entries = ", ".join(f"`{b}`" for b in broad)
        fails.append(
            f"A11 {rel}: allowed-tools grants {entries} — an unscoped "
            f"interpreter/vcs/build tool is arbitrary code execution, "
            f"and a skill that reads untrusted target content can be "
            f"steered into running it. Scope each entry to a "
            f"subcommand or script, e.g. `Bash(git log:*)` or "
            f"`Bash(python3 *traust/scripts/x.py:*)`."
        )
    if wildcard and not _exempt("A14", rel, used):
        entries = ", ".join(f"`{w}`" for w in wildcard)
        fails.append(
            f"A14 {rel}: interpreter grant(s) {entries} start the "
            f"script pattern with a bare `*` — any path ending in that "
            f"filename matches, including one planted in a hostile "
            f"checkout. Anchor the pattern to the harness tree "
            f"(`*traust/scripts/<name>.py`)."
        )
    return fails


# --- U3: the tier taxonomy (skill-usability plan §1/§3.2) -------------
# Taxonomy rides in `metadata` because the Agent Skills spec closes the
# top-level frontmatter set and names `metadata` as the extension point
# (string keys → string values), so the key is dotted rather than nested.
TIERS = ("primary", "secondary", "tertiary", "ci")


def _u3_tier_failures(text: str, rel: str) -> list[str]:
    """U3 — `metadata.harness.tier` present and drawn from the enum.

    No EXEMPTIONS by design (see the module docstring): the fix is one
    frontmatter line, so there is no exception a reviewer would accept,
    and an unlabeled skill silently drops out of every tier-derived
    index and query rather than announcing itself."""
    data, err = _parse_frontmatter(text)
    if err:
        return [f"U3 {rel}: {err} — a gate that cannot read the frontmatter must fail, not pass"]
    # `isinstance(meta, dict)` is load-bearing, not defensive: frontmatter is
    # author-controlled, so `metadata:` can arrive as a scalar, a list, or
    # empty (None). Indexing it blind raises AttributeError, which is not
    # failing closed — it is a traceback with no actionable message that also
    # takes every other rule's findings down with it.
    meta = (data or {}).get("metadata")
    tier = meta.get("harness.tier") if isinstance(meta, dict) else None
    if tier not in TIERS:
        # No `isinstance(tier, str)` test: TIERS holds only strings, so the
        # membership check already rejects every non-string YAML scalar.
        shown = repr(tier) if tier is not None else "missing"
        return [
            f"U3 {rel}: metadata.harness.tier is {shown} — must be one "
            f"of {' | '.join(TIERS)}. Add it as one line under a "
            f"`metadata:` block; what each tier commits you to is in "
            f"docs/skills.md#tiers. This rule takes no exemption."
        ]
    return []


# A skill lives at harnessing/<skill>/, or — for a workflow skill — one level
# deeper under its stage directory, harnessing/<N>-<stage>/<skill>/ (harness
# skill-usability plan 1.2). EXEMPTIONS keys are written in the flat spelling,
# and so are the script paths the findings corpus recorded, so both are matched
# by dropping the stage segment rather than by rewriting every key. Doing it
# here matters for `gates:pinned`, which runs the TARGET branch's copy of this
# checker against an MR tree: without it, the branch that moves the skills
# fails on ~43 exemption keys that describe nothing but their own old paths.
_STAGE_SEG_RE = re.compile(r"(harnessing/)[0-9]+-[a-z0-9-]+/")


def _unstaged(path: str) -> str:
    """The flat spelling of `path`, with any stage directory removed."""
    return _STAGE_SEG_RE.sub(r"\1", path)


def _exempt(rule: str, path: str, used: list[str]) -> bool:
    spellings = (path, _unstaged(path))
    for (r, p), _reason in EXEMPTIONS.items():
        if r == rule and any(p == s or p in s for s in spellings):
            tag = f"{r} {p}"
            if tag not in used:
                used.append(tag)
            return True
    return False


def a13_skills_doc_sync_failures(repo: Path = REPO) -> list[str]:
    """A13 — staged SKILL.md changes must carry a staged docs/skills.md
    update (or an explicit waiver). Only active under the pre-commit hook
    (HARNESS_PRE_COMMIT=1) so plain tree checks and test runs on a dirty
    working tree are unaffected."""
    if os.environ.get("HARNESS_PRE_COMMIT") != "1":
        return []
    if os.environ.get("SKILLS_DOC_WAIVER"):
        return []
    try:
        staged = subprocess.run(
            ["git", "-C", str(repo), "diff", "--cached", "--name-only"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.splitlines()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return []
    skill_mds = [s for s in staged if re.fullmatch(r"harnessing/(?:[^/]+/)?[^/]+/SKILL\.md", s)]
    if skill_mds and "docs/skills.md" not in staged:
        names = ", ".join(sorted(s.split("/")[-2] for s in skill_mds))
        return [
            f"A13: staged SKILL.md change(s) ({names}) without a staged "
            f"docs/skills.md update — docs/skills.md is generated: run "
            f"python3 -m traust.cli.build_skills_reference and "
            f"stage it, or waive a change that does not touch frontmatter or "
            f"the Integrations section with SKILLS_DOC_WAIVER=<reason>"
        ]
    return []


#: Ledger layers are written only through the SDK. Both spellings below bypass the
#: `Backend.mutate` lock that makes mutate + stamp + sign atomic.
LAYER_WRITE_RE = re.compile(
    r"_write_layer_file\s*\(|"
    r"\.write_text\s*\(.*?\)\s*(?:#.*)?$",
    re.MULTILINE,
)
#: Deliberately narrow. An earlier spelling matched `layer_path`, which flagged
#: `build_attack_coverage.py` writing an **ATT&CK Navigator** layer — a different
#: thing entirely. A rule that cries wolf gets waived, so it matches only names that
#: can be a disposition layer.
LAYER_PATH_HINT_RE = re.compile(r"findings-layer|LAYER_SUFFIX|_findings_layer")


#: A18 — engine resolution. Matches the CALL, never the import: 8 modules import
#: `HarnessEngine` purely to annotate a parameter, which is correct and must stay
#: clean. `HarnessEngine(` catches construction that skips `load()` entirely.
A18_ENGINE_CALL_RE = re.compile(r"\bHarnessEngine\s*(?:\.\s*load\s*)?\(")
#: A18 — config-home resolution. `traust.paths` re-exports this symbol (an import
#: and an `__all__` entry, neither a call), so the module list below allows it.
A18_CONFIG_HOME_CALL_RE = re.compile(r"\bdeployment_config_dir\s*\(")
#: The composition root itself, plus the sanctioned config-path resolver.
A18_ENGINE_ROOTS = ("src/traust/context.py",)
A18_CONFIG_HOME_ROOTS = ("src/traust/context.py", "src/traust/paths.py")


_A17_TREES = ("analysis-results/", "progress-tracker/")
_A17_MARK = "`locations.yaml`"


def a17_locations_note_failures(repo: Path = REPO, used: list | None = None) -> list[str]:
    """A17 locations-note — a SKILL.md that names a workspace tree says so.

    52 of 56 skill docs write `analysis-results/…` or `progress-tracker/…`
    literally (measured 2026-09-07). The code underneath resolves those roots
    through `locations.yaml` in $TRAUST_CONFIG_HOME, so the literals are the
    documented DEFAULT layout — but a reader outside this deployment cannot
    tell a default from a hardcode. Any skill doc that names either tree must
    carry the one-paragraph note saying the paths resolve through
    `locations.yaml`. Publish-time pass for the open-source split; this rule
    is the ratchet that keeps the next skill honest.
    """
    used = used if used is not None else []
    failures: list[str] = []
    root = repo / "harnessing"
    if not root.is_dir():
        return failures
    for path in sorted(root.rglob("SKILL.md")):
        rel = path.relative_to(repo).as_posix()
        if _exempt("A17", rel, used):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        named = [t for t in _A17_TREES if t in text]
        if named and _A17_MARK not in text:
            failures.append(
                f"A17: {rel} names a workspace tree ({', '.join(named)}) without "
                f"the locations note — add the standard paragraph saying these "
                f"paths are the default layout resolved through `locations.yaml` "
                f"in $TRAUST_CONFIG_HOME (docs/setup.md, Storage locations)"
            )
    return failures


def a16_layer_write_boundary_failures(repo: Path = REPO, used: list | None = None) -> list[str]:
    """A16 — ledger layers are written through the SDK, never directly.

    `traust-engine` 0.9.6 collapsed four write mechanisms into one: every layer
    mutation goes through `LedgerClient`, where mutate + stamp + sign happen inside a
    single `Backend.mutate` lock. A direct write bypasses that lock, skips
    finalization, and reintroduces the split that left **112 signed corpus layers
    unsigned on 2026-08-31** while every one of them was reported as written and
    successful (progress-tracker `traust-ledger-code-fitness-plan.md`).

    The count is zero as of harness 0.331.7 — Shaun's Phase 2 removed the last
    caller. This rule is a ratchet, not a cleanup: it exists so the next one fails
    the commit instead of being found by accident, which is how this defect was
    found three times.

    Scoped to writes that look like they touch a layer (`LAYER_PATH_HINT_RE` on the
    same line), so ordinary `write_text` on reports and dashboards is unaffected.
    """
    used = used if used is not None else []
    failures: list[str] = []
    roots = [repo / "src" / "traust", repo / "harnessing"]
    for root in roots:
        if not root.is_dir():
            continue
        for path in sorted(root.rglob("*.py")):
            rel = path.relative_to(repo).as_posix()
            if "/tests/" in f"/{rel}" or path.name.startswith("test_"):
                continue
            if path.name == "check_skill_alignment.py":
                continue  # this rule names the forbidden spellings to detect them
            if _exempt("A16", rel, used):
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            lines = text.splitlines()
            for n, line in enumerate(lines, 1):
                if line.lstrip().startswith("#"):
                    continue
                # A layer path is usually bound a line or two above the write
                # (`lp = ...-findings-layer.json` then `lp.write_text(...)`), which
                # is how finding_identity.py and backfill_report_digest.py were
                # written. Same-line matching missed exactly that shape, so look
                # back a short window for the binding.
                is_layer_write = False
                if ".write_text(" in line:
                    # The receiver must be BOUND to a layer path, not merely near
                    # one. Two shapes defeated earlier attempts: the binding sits
                    # several lines above the write (finding_identity.py,
                    # backfill_report_digest.py), and `emit_triage_ledger_events`
                    # derives the refuted-register name with
                    # `.replace("-findings-layer.json", …)` — near a layer, writing
                    # something else.
                    recv = line.split(".write_text(")[0].strip().split()[-1]
                    recv = recv.split("=")[-1].strip()
                    binds = [
                        ln
                        for ln in lines[max(0, n - 25) : n]
                        if recv and re.search(rf"\b{re.escape(recv)}\s*=", ln)
                    ]
                    target = binds[-1] if binds else line
                    is_layer_write = bool(
                        LAYER_PATH_HINT_RE.search(target)
                        and not (".replace(" in target and "-findings-layer.json" in target)
                    )
                if "_write_layer_file" in line or is_layer_write:
                    failures.append(
                        f"A16: {rel}:{n} writes a ledger layer directly — route it "
                        f"through LedgerService/LedgerClient so mutate+stamp+sign "
                        f"stay atomic (see traust-ledger-code-fitness-plan.md §2)"
                    )
    return failures


def a18_composition_root_failures(repo: Path = REPO, used: list | None = None) -> list[str]:
    """A18 — the engine is resolved in exactly one place.

    `src/traust/context.py` is the app's single composition root: it calls
    `HarnessEngine.load()` once, converts `DeploymentConfigMissing` into a
    one-line `SystemExit(2)`, and hands the engine (or one ops namespace) to
    its callers. 93 modules call `load_engine()` and 96 call
    `add_config_home_arg()` — so every lane inherits the same config
    precedence (CLI flag > AUDIT_RESULTS_ROOT > `locations.yaml`) and the same
    fail-loud behaviour, pinned by `tests/test_context.py`.

    A second caller re-resolves config on its own terms: it gets a traceback
    instead of exit 2, or a different precedence, and the guarantee stops being
    a guarantee. The invariant was stated in the module docstring from the
    start and has held across all 93 sites by discipline alone — nothing
    checked it. This rule is the ratchet, in the shape A16 established: it
    lands at zero and exists so the 94th site fails the commit instead of
    being noticed later.

    Deliberately matches the CALL, not the import. `from traust_engine import
    HarnessEngine` appears in 8 modules that only annotate a parameter with it;
    banning the import would flag all 8 and get the rule waived.
    """
    used = used if used is not None else []
    failures: list[str] = []
    roots = [repo / "src" / "traust", repo / "harnessing"]
    for root in roots:
        if not root.is_dir():
            continue
        for path in sorted(root.rglob("*.py")):
            rel = path.relative_to(repo).as_posix()
            if "/tests/" in f"/{rel}" or path.name.startswith("test_"):
                continue
            if path.name == "check_skill_alignment.py":
                continue  # this rule names the forbidden spellings to detect them
            if _exempt("A18", rel, used):
                continue
            try:
                lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
            except OSError:
                continue
            for n, line in enumerate(lines, 1):
                if line.lstrip().startswith("#"):
                    continue
                if rel not in A18_ENGINE_ROOTS and A18_ENGINE_CALL_RE.search(line):
                    failures.append(
                        f"A18: {rel}:{n} resolves the engine outside the composition "
                        f"root — call `traust.context.load_engine()` so the "
                        f"SystemExit(2) contract and config precedence stay in one "
                        f"place (src/traust/context.py)"
                    )
                if rel not in A18_CONFIG_HOME_ROOTS and A18_CONFIG_HOME_CALL_RE.search(line):
                    failures.append(
                        f"A18: {rel}:{n} resolves the config home directly — go "
                        f"through `config_path()` / `traust.paths`, which raises "
                        f"DeploymentConfigMissing instead of falling back "
                        f"(config/README.md)"
                    )
    return failures


def a15_baseline_ownership_failures(repo: Path = REPO, used: list | None = None) -> list[str]:
    """Only the three secure*audit skills may write an audit baseline.

    Everything else writes a ledger layer. See the rule note in the module
    docstring for why, and baseline-immutability-plan.md for the burn-down.
    """
    used = used if used is not None else []
    failures: list[str] = []

    for path in skill_md_paths(repo):
        name = path.parent.name
        if name in BASELINE_OWNER_SKILLS:
            continue
        rel = path.relative_to(repo).as_posix()
        text = path.read_text(encoding="utf-8", errors="ignore")
        m = BASELINE_WRITE_MD_RE.search(text)
        if m and BASELINE_WRITE_MD_NEG_RE.search(text[max(0, m.start() - 160) : m.end() + 160]):
            m = None  # the sentence states the rule, it does not break it
        if m and not _exempt("A15", rel, used):
            line = text[: m.start()].count("\n") + 1
            failures.append(
                f"A15 {rel}:{line}: instructs writing an audit baseline "
                f"({m.group(0)[:48]!r}…) — only /secure-code-audit, "
                f"/secure-rpm-audit and /secure-container-audit may do "
                f"that; emit a ledger event instead"
            )

    owner_dirs = {d for d in skill_dirs(repo) if d.name in BASELINE_OWNER_SKILLS}
    py_files = [*repo.glob("src/traust/**/*.py"), *skill_scripts(repo)]
    for path in sorted(set(py_files)):
        rel = path.relative_to(repo).as_posix()
        # The audit skills own the baseline, so their own scripts are not
        # violations. Matched by parent directory rather than by a
        # `harnessing/<name>/` substring, which stops matching once the
        # skill sits under a stage directory.
        if any(d in path.parents for d in owner_dirs):
            continue
        # The gate itself names these patterns; do not self-flag.
        if path.name == "check_skill_alignment.py":
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        if not BASELINE_FILE_RE.search(text):
            continue
        for i, line in enumerate(text.splitlines(), 1):
            if BASELINE_WRITE_PY_RE.search(line) and not _exempt("A15", rel, used):
                failures.append(
                    f"A15 {rel}:{i}: writes an audit baseline "
                    f"({line.strip()[:56]!r}) — non-audit producers append "
                    f"a ledger event, never the baseline"
                )
    return failures


def _tracked_paths(repo: Path) -> set[str] | None:
    """`git ls-files` as a set of repo-relative paths, or None when the tree is
    not a git checkout (test fixtures) so the tracked-ness check is skipped."""
    if not (repo / ".git").exists():
        return None
    try:
        out = subprocess.run(
            ["git", "-C", str(repo), "ls-files"], capture_output=True, text=True, check=False
        )
    except OSError:
        return None
    if out.returncode != 0:
        return None
    return set(out.stdout.split("\n"))


def alignment_failures(repo: Path = REPO, exemptions_used: list | None = None) -> list[str]:
    failures: list[str] = []
    failures.extend(a13_skills_doc_sync_failures(repo))
    failures.extend(a16_layer_write_boundary_failures(repo, exemptions_used))
    failures.extend(a17_locations_note_failures(repo, exemptions_used))
    failures.extend(a15_baseline_ownership_failures(repo, exemptions_used))
    failures.extend(a18_composition_root_failures(repo, exemptions_used))
    used = exemptions_used if exemptions_used is not None else []
    skills = skill_dirs(repo)

    md_files = [md for d in skills for md in sorted(d.glob("*.md"))]
    for path in md_files:
        rel = path.relative_to(repo).as_posix()
        text = path.read_text(encoding="utf-8", errors="ignore")

        # A1 — referenced scripts exist (repo-relative or skill-relative)
        for ref in sorted(set(SCRIPT_REF_RE.findall(text))):
            clean = re.sub(r"[.,)`]+$", "", ref)
            if (
                not (repo / clean).exists()
                and not (path.parent / clean).exists()
                and not _exempt("A1", rel, used)
            ):
                failures.append(f"A1 {rel}: references `{ref}` which does not exist")

        # A2/A3 apply to report-producing skills — the recording
        # conventions live in report metadata; state files, patch
        # results, and passing mentions are out of scope.
        produces_report = bool(PROFILE_RE.search(text)) or "metadata.tools" in text
        # A2 — opengrep contract
        if RUNS_OPENGREP_RE.search(text) and produces_report:
            missing = []
            if "deterministic_steps" not in text:
                missing.append("deterministic_steps recording")
            if not JUDGE_RE.search(text):
                missing.append("judge protocol (scanner_correlation / promote-or-dismiss)")
            if missing and not _exempt("A2", rel, used):
                failures.append(f"A2 {rel}: runs run_opengrep.py without {' or '.join(missing)}")

        # A3 — KHS contract
        if (
            RUNS_KHS_RE.search(text)
            and produces_report
            and "deterministic_steps" not in text
            and not _exempt("A3", rel, used)
        ):
            failures.append(
                f"A3 {rel}: runs scan_k8s_hardening.py without deterministic_steps recording"
            )

        # A8 — checkov contract (declared-layer scanner: recording plus
        # honesty labeling travel with the tool)
        if RUNS_CHECKOV_RE.search(text):
            missing = []
            if "deterministic_steps" not in text:
                missing.append("deterministic_steps recording")
            if not DECLARED_RE.search(text):
                missing.append("declared-configuration labeling")
            if missing and not _exempt("A8", rel, used):
                failures.append(f"A8 {rel}: runs run_checkov.py without {' or '.join(missing)}")

        # A4 — audit profiles link the shared structure doc
        if (
            PROFILE_RE.search(text)
            and "report-structure.md" not in text
            and not _exempt("A4", rel, used)
        ):
            failures.append(
                f"A4 {rel}: sets an audit_profile but never links "
                f"docs/report-structure.md (single source of structure)"
            )

        # A5 — liveness consumers name the artifact
        if (
            LIVENESS_RE.search(text)
            and "repo-liveness" not in text
            and not _exempt("A5", rel, used)
        ):
            failures.append(
                f"A5 {rel}: mentions repo status/liveness without naming "
                f"the census artifact (repo-liveness.json) as the source"
            )

        # A12 — model identifiers live only in the registry
        for i, line in enumerate(text.splitlines(), 1):
            m = MODEL_ID_RE.search(line)
            if m and not MODEL_ID_SKIP_LINE_RE.search(line) and not _exempt("A12", rel, used):
                failures.append(
                    f"A12 {rel}:{i}: hardcoded model id '{m.group(0)}' — "
                    f"name a tier class and resolve via "
                    f"config/model-registry.yaml "
                    f"(traust_engine.registry.models)"
                )

        # A11 — no broad interpreter grants in allowed-tools
        failures.extend(_broad_allow_failures(text, rel, used))

    # A11 also guards command wrappers, which can carry their own
    # allowed-tools frontmatter
    for path in sorted(repo.glob(".claude/commands/*.md")):
        rel = path.relative_to(repo).as_posix()
        text = path.read_text(encoding="utf-8", errors="ignore")
        failures.extend(_broad_allow_failures(text, rel, used))

    tracked = _tracked_paths(repo)
    for d in skills:
        name = d.name
        md = d / "SKILL.md"
        rel = md.relative_to(repo).as_posix()
        text = md.read_text(encoding="utf-8", errors="ignore")
        # A6 — frontmatter name matches directory
        m = re.search(r"^name:\s*(\S+)", text, re.MULTILINE)
        if not m or m.group(1) != name:
            failures.append(
                f"A6 {rel}: frontmatter name "
                f"'{m.group(1) if m else '(missing)'}' != directory "
                f"'{name}'"
            )
        # U3 — tier declared (before A7's exemption `continue`, so a
        # wiring-exempt skill is still required to carry a tier)
        failures.extend(_u3_tier_failures(text, rel))
        # A7 — discovery wiring
        if _exempt("A7", name, used):
            continue
        for wiring in (
            f".claude/skills/{name}",
            f".crush/skills/{name}",
            f".claude/commands/{name}.md",
            f".crush/commands/{name}.md",
        ):
            if not (repo / wiring).exists():
                failures.append(f"A7 {rel}: missing wiring `{wiring}`")
            elif tracked is not None and wiring not in tracked:
                # `.crush/.gitignore` is `*`: a link created on disk but never
                # `git add -f`ed passes here and is absent from every clone.
                # Found by the 2026-09-08 export dry-run (two skills).
                failures.append(
                    f"A7 {rel}: wiring `{wiring}` exists but is untracked — `git add -f` it"
                )

    # A9/A10 — artifact producer/consumer graph. A skill that emits a
    # data artifact should have a consumer somewhere in the harness (A9),
    # and must document its integrations (A10) — under-wired skills like
    # early operator-priv-profile / impact-analysis are exactly this gap.
    skills_art = {}
    for d in skills:
        md = d / "SKILL.md"
        text = md.read_text(encoding="utf-8", errors="ignore")
        skills_art[d.name] = (_skill_artifacts(text), text, md.relative_to(repo).as_posix())
    for name, ((produced, _), text, rel) in sorted(skills_art.items()):
        nonterminal = {k for k in produced if not ARTIFACT_TERMINAL_RE.search(k)}
        for key in sorted(nonterminal):
            if _exempt("A9", f"{name}:{key}", used) or _exempt("A9", name, used):
                continue
            consumed = any(
                other != name and any(_keys_match(key, mk) for mk in mentioned)
                for other, ((_, mentioned), _t, _r) in skills_art.items()
            )
            if not consumed:
                failures.append(
                    f"A9 {rel}: emits `{key}` which no other skill "
                    f"consumes — wire a consumer, mark it terminal, or "
                    f"add a reviewed exemption"
                )
        # A10 requires a REAL Integrations/Downstream heading — the old
        # substring fallback ("integrat" anywhere) let census and
        # threat-register pass on incidental prose (wiring F1)
        if (
            nonterminal
            and not INTEGRATIONS_HEADING_RE.search(text)
            and not _exempt("A10", name, used)
        ):
            failures.append(
                f"A10 {rel}: emits data artifacts but has no "
                f"Integrations/Downstream section (a real heading — "
                f"prose mentioning 'integration' no longer counts) "
                f"documenting who consumes them"
            )
    return failures


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Cross-skill alignment guard (pre-commit gate).")
    ap.add_argument("--root", default=str(REPO))
    args = ap.parse_args(argv)
    repo = Path(args.root).resolve()

    used: list[str] = []
    failures = alignment_failures(repo, used)
    print(f"Skill-alignment check for {repo}")
    for u in used:
        print(f"    (exempt) {u}")
    if not failures:
        print("✓ all skills aligned with the shared contracts")
        return 0
    print(f"\n✗ {len(failures)} misalignment(s):")
    for f in failures:
        print(f"    - {f}")
    print(
        "\nFix the skill (or add a reviewed EXEMPTIONS entry with a "
        "reason) — see docs and the /check-alignment skill."
    )
    return 1


if __name__ == "__main__":
    import sys

    from traust.cli.__main__ import main

    raise SystemExit(main(["check", "skill-alignment", *sys.argv[1:]]))
