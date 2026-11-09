# backport-fix mock kit — end-to-end pipeline dry-runs

Runs the **entire backport-fix pipeline with every real harness script**,
mocking only the Amalgamator LLM engine. No credentials, no network, no
tokens spent, finishes in seconds. Self-checking: each runner asserts the
expected input/output placement at every stage and exits non-zero on any
mismatch — this is the skill's integration test.

This kit found real contract breaks on its first run (schema enum missing
the real pipeline outcomes; local-mode patch collection truncating
collected patches) — run it after any change to the generator, runner,
deliver, emitter, or schema.

## Prerequisites

- `python3` with `pyyaml` + `jsonschema` importable
  (`pip install pyyaml jsonschema`, or use a venv on `PATH`)
- `git`
- Optional, enables the strongest checks: the Amalgamator checkout as a
  workspace sibling (`../../amalgamator` relative to this repo, override
  with `AMALGAMATOR_ROOT=/path`). With it present (plus
  `claude-agent-sdk`+`colorama` importable), the generated configs are
  validated by the **real** `auto_bug_fix.config_loader`, and Seam B runs
  the **real** `backport_scanner` (deterministic tiers only). Without it,
  those stages skip with a notice.

## Run

```bash
bash harnessing/7-remediate/backport-fix/test-data/mock/run_mock_seam_a.sh   # impact-analysis seam
bash harnessing/7-remediate/backport-fix/test-data/mock/run_mock_seam_b.sh   # remediation seam
```

Each takes an optional work-dir argument (default: `mktemp -d`). Expected
final line: `MOCK SEAM A: PASS` / `MOCK SEAM B: PASS`.

`MOCK_REQUIRE_REAL=1` turns any skipped optional stage into a failure — use it
when you want a full-coverage run (amalgamator sibling + `claude-agent-sdk` /
`colorama` present) rather than a degraded PASS. Delivery runs with
`--offline`, so neither seam touches the network.

## What each seam verifies

| Stage | Seam A (impact) | Seam B (remediation) |
|---|---|---|
| input contract | real-shape impact JSON (bare `fixed_version`, `products[]`) | triage + audit fixtures mirroring the real cri-o `f001` finding → `make_remediation.py` → remediation JSON, validated against the `remediation` contract schema (traust-contracts) |
| branch selection | version-based scan over 6 branch archetypes (needs-fix / different-z-stream already-fixed / module-absent / path-replace ambiguous ×2 / vanity-replacement fixed) | **real `backport_scanner`**: cherry-picked branch proven ALREADY_FIXED via patch-id; vulnerable branch AMBIGUOUS without the LLM tier → promoted by explicit `--branches` (the documented policy) |
| fix commit | bump-commit locator on `origin/main` | `fork.fix_commit` from the remediation; `prepare_backport_fork.sh` short-circuit (commit reachable → no token needed) |
| config contract | real `load_pipeline_config` accepts every YAML | same; also asserts `issue_id: backport-cri-o-f001-release-a` (finding_id-derived slug) |
| run + collect | mock engine, mixed outcomes (success / pipeline_stop / pipeline_escalation); summary+patch+dossier collected from the run dir; `run_summary.json` counts asserted | success path; patch collection asserted |
| delivery | dry-run plans exactly one immutable `ex-wing/…` ref; stop/escalation gated out; `delivery.json` asserted | planned ref asserted to be `ex-wing/backport-cri-o-f001-release-a-<sha10>` |
| report + publish | emitted from the impact artifact (`--impact`, no remediation JSON); schema-**valid**; `remediations/example-product/myrepo/` receives report + patch + delivery record; CVE `finding_refs`, fix commit and source branch (read back from the per-branch `config.yaml`) asserted | same via `--remediation`, plus `finding_refs == ["cri-o-triage.json#f001"]` asserted |
| security property | the mock engine **refuses to run if `GITHUB_TOKEN` is in its environment** — proving run_backport.sh's token stripping with a dummy token exported | same |
| invocation binding | collection only accepts a run dir newer than this config's marker and named after its YAML, so a branch that produced nothing cannot inherit another branch's summary/patch | same |

## The mock engine (`mock_amalgamator/`)

A fake `auto_bug_fix` package (put its directory on `PYTHONPATH`) faithful
to the real pipeline's observable contract: positional config argument,
CWD-relative `runs/<yaml>_<ts>/` output, per-target subdir with
`candidate.patch`/`dossier.md`/tracker JSON, parent `summary.json` in the
real multi-target shape, `amalgamator/<issue_id>` preservation branches in
the source clone, exit 0 only on all-success. Per-branch outcomes are set
via `MOCK_OUTCOMES="release-2=pipeline_stop,…"` (unlisted branches
succeed).

## Notes

- Zero LLM usage by construction: the runners `unset` every LLM credential
  first; Seam B's real scanner therefore classifies the vulnerable branch
  AMBIGUOUS (its deterministic tiers can prove "already fixed" via
  patch-id but cannot prove "vulnerable") — real credential-less Seam B
  runs need explicit `--branches`, exactly as demonstrated.
- Neither seam needs a hand-written artifact: Seam A emits straight from
  the impact analysis (`emit_backport_report.py --impact`), and Seam B's
  remediation JSON is produced by `make_remediation.py` from the fixture's
  triage + audit pair — so the kit also covers the "generate one from a
  finding" path rather than asserting against a hardcoded blob.
- The mock engine honors the generated configs' `repository.workdir`
  (`/tmp/bugfix-backport-*`), mirroring the real pipeline; those
  directories are left behind like real runs leave theirs.
