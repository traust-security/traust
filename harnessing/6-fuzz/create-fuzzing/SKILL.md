---
name: create-fuzzing
description: >-
  Use when the user asks to write, scaffold, run, or extend a fuzz harness for a parser/decoder/templater identified in a security-audit report — Go-native by default, plus Python (atheris), JavaScript/TypeScript (Jazzer.js), Rust (cargo-fuzz), and Java (jazzer, manual run) via the language field in targets.json and templates under harnesses/_templates/. Adds a target to targets.json, authors a harness dropped into the audited repo's tree, drives `make clone install build fuzz-<id>`, and triages any crashers into follow-up findings. Offline only: no cluster, cloud creds, or service mocks.
metadata:
  harness.tier: "primary"
---

# Fuzz Harnesses

> **Paths.** `analysis-results/…` and `progress-tracker/…` in this skill are the
> default workspace layout. They resolve through `locations:` in `traust.yaml` in
> `$TRAUST_CONFIG_HOME` (`docs/setup.md`, Storage locations); substitute your
> configured roots.


Author and run **offline Go-native fuzz tests** against pure-function attack
surface (parsers, decoders, templaters, regex matchers) that a
`secure-code-audit` report has flagged as fuzz-worthy. Every harness is a
white-box `*_fuzz_test.go` copied *into* the target repo's own package tree so
it can reach unexported identifiers, driven by the Go 1.18+ native fuzzer
(`go test -fuzz`).

This skill wraps the existing tooling in this directory — `targets.json`,
`Makefile`, `harnesses/<id>/*_fuzz_test.go`, and the batch-plan docs. Read
[README.md](README.md) alongside this file for the full layout and design
notes.

## Input

`$ARGUMENTS` is one of:

1. **A repository URL or `<org>/<repo>`** — scaffold new harnesses for that
   repo. Look up its audit report under
   `analysis-results/findings/**/<repo>/<repo>-security-audit.{json,md}` to
   find recommended fuzz entry points (findings whose `remediation` mentions
   fuzzing, or the report's remediation-roadmap "add fuzz harness" items).
   **Also check the refuted register** —
   `traust findings refuted --repo-url <repository-URL>` returns core's
   false positives, including human-reviewed dismissals. A retained
   `<repo>-refuted-register.json` is historical evidence, not a current
   projection; do not regenerate it or treat absence as no refutations.
   Entries in fuzzable classes (parsers, decoders,
   memory safety, injection) are PRIORITY targets, because a reproducing
   crash overrides the FP assertion via evidence-class precedence
   (`fp_overridden`). An FP is a falsifiable claim, not an exclusion.
2. **A finding ID** (e.g. `KUBE_RBAC_PROXY-9cb7556-019`) — scaffold a harness
   for that specific finding's entry point.
2b. **An impact-analysis artifact**
   (`analysis-results/impact/<cve>-impact-analysis.json`, from
   `/impact-analysis`) — scaffold harnesses for the repos classified
   `affected`. This is the assurance-promotion path: `affected` is
   call-graph reachability (machine static, evidence class 3); a
   reproducing input is execution evidence (class 1) that flips the
   finding to `confirmed` in the disposition ledger. Target the entry
   point from the repo's `evidence.govulncheck_trace` — the first
   in-repo frame is the natural harness entry — and seed the corpus
   with advisory-shaped input (`metadata.feature_description` names the
   vulnerable capability). Set the target's `audit_ref` to the CVE ID.
   Prioritize by severity and by
   `attacker_influence: plausible` where triage has judged the trace.
3. **A target ID already in `targets.json`** — skip authoring; just
   `make clone install build fuzz-<id>` and triage results.
4. **Nothing** — run the whole current batch: `make clone install build` then
   `make FUZZTIME=<duration> fuzz-all` (or `BATCH=<n> fuzz-all`).

## Non-Go languages (C4)

Go stays the default (`language` absent = `go`; nothing changes for
existing targets). For other ecosystems, set `"language"` on the target
and author from the matching template in `harnesses/_templates/`:

| language | engine | template | run |
|---|---|---|---|
| `python` | atheris (Apache-2.0) | `python_fuzz.py` | `make fuzz-<id>` — per-clone `.fuzzvenv`, FUZZTIME-bounded |
| `javascript` | Jazzer.js (Apache-2.0) | `js_fuzz.js` | `make fuzz-<id>` — `npx jazzer`, FUZZTIME-bounded |
| `rust` | cargo-fuzz + libFuzzer | `rust_fuzz.rs` | `make fuzz-<id>` — requires nightly toolchain; dest under `fuzz/fuzz_targets/` |
| `java` | jazzer (JVM), **pinned v0.30.0** (sha256-verified download; Apache-2.0 verified at the tag — docs/external-dependencies.md) | `JavaFuzz.java` | `make fuzz-<id>` — builds the target (maven `package` or gradle `assemble`), assembles the classpath, runs the pinned jazzer against the manifest's `.fuzz` class, FUZZTIME-bounded |

Same rules as Go targets: harnesses live in `analysis-results/fuzz-harnesses/<id>/` and are
copied into the clone by `make install` (dest inside the target tree so
imports resolve); expected parse errors are swallowed in the harness —
crashes, hangs, and memory blowups are the findings; crashers are
triaged identically (reproducer + follow-up finding + rollup entry, with
the target's `language` carried through). Engine licenses are verified
in `docs/external-dependencies.md`; the engines are dependencies of the
*generated harnesses in target repos*, never of this repository.

## Preconditions

Working directory must be this skill's directory:

```bash
cd traust/harnessing/6-fuzz/create-fuzzing
```

Requires: `go` ≥ 1.22, `jq`, `git`, network access for `make clone` only.

## Workflow

### 1. Locate or add the target

Check whether `$ARGUMENTS` already has an entry:

```bash
jq -r '.targets[] | select(.id=="<id>" or (.repo | contains("<repo>")))' targets.json
```

If **absent**, append a new object to `.targets[]` in `targets.json`:

```json
{
  "id": "<repo-name>",
  "repo": "https://github.com/<org>/<repo>",
  "module": "<go module path from go.mod>",
  "commit": "<7-or-40-char SHA from the audit report's metadata.commit, or HEAD>",
  "product_reach": <int — number of products shipping this repo, from repo-graph>,
  "audit_ref": "<finding ID that recommended fuzzing>",
  "batch": <next batch number>,
  "harnesses": [
    {
      "file": "<id>/<name>_fuzz_test.go",
      "dest": "<pkg-path>/<name>_fuzz_test.go",
      "fuzz": "Fuzz<Name>",
      "pkg": "./<pkg-path>"
    }
  ]
}
```

Optional per-target keys the Makefile honours: `clone_alias` (share a clone
across targets), `workdir` (subdir containing `go.mod`), `goos` (skip on other
host OS).

### 2. Author the harness

Create `analysis-results/fuzz-harnesses/<id>/<name>_fuzz_test.go`. Rules:

- **`package` must match the target package** (white-box, so unexported
  identifiers are reachable). `dest` in `targets.json` places the file
  in-tree.
- **Seed corpus via `f.Add(...)`.** Prefer real fixtures the repo already
  ships (`docs/samples/*.yaml`, `testdata/*`). Otherwise hand-roll
  minimal-valid + minimal-invalid + known-hostile (YAML anchor bomb, deeply
  nested JSON, oversized varint, `../` path, `%n` format string) seeds.
- **No network, cluster, or cloud at fuzz time.** Substitute
  `k8s.io/client-go/dynamic/fake`, `discovery/fake`, in-memory `io.Reader`,
  synthetic `net.Addr`. If the entry point insists on I/O, drive the layer
  *below* it.
- **Prefer exported entry points**; if the target is unexported, keep the
  harness as thin as possible around it so upstream refactors surface as a
  compile error, not a silent no-op.
- Header comment: drop-in `dest` path, `go test -fuzz` invocation, target
  file:line, and the crash classes you expect.

See `analysis-results/fuzz-harnesses/kube-rbac-proxy/config_fuzz_test.go` for a reference harness
and `BATCH-*.md` for pattern guidance (sprig/`text/template` DoS,
`strings.Split(...)[N]` index panics, differential invariants).

### 3. Compile-check

```bash
make clone           # check out repos at pinned commits via the checkout service (idempotent)
make install build   # copy harnesses in-tree and go test -run '^$' compile-check
```

`make build` must pass before fuzzing. A compile error means the pinned
commit's internals moved — re-scout the entry point and update the harness,
do **not** bump `commit` to HEAD just to make it compile.

### 4. Fuzz

```bash
make FUZZTIME=10m fuzz-<id>          # one target
make FUZZTIME=1h BATCH=<n> fuzz-all  # a whole batch
```

Crashers land in
`clones/<id>/<pkg>/testdata/fuzz/<FuzzName>/<hash>`.

### 5. Triage crashers

For each crasher:

1. `go test -run <FuzzName>/<hash> ./<pkg>` to reproduce deterministically.
2. Minimise the input (the Go fuzzer usually already has).
3. Classify: panic (index-OOB, nil deref, type assertion), hang/timeout
   (CWE-770 resource exhaustion), or invariant violation (differential).
4. Copy the reproducer into `analysis-results/findings/**/<id>/fuzz-corpus/<FuzzName>/`.
5. **File a follow-up finding** through the fuzz report in step 6 or
   `/file-security-defect`. Keep the link to the source audit through the
   target's `audit_ref` (step 6); never amend the baseline audit (gate A15).
6. **Record it in traust.** A crasher that only exists as
   prose in a batch summary is not recorded — traust is the register of
   what we know about a finding, and for months it held none of these.

   Write the run as a fuzz report (traust-contracts `fuzz-report.schema.json`:
   the target's harnesses with their outcomes, every crasher, measured
   coverage, the surfaces left unfuzzed and why) and record it on the fuzzed
   commit:

   ```bash
   traust reporting record <fuzz-report.json> --kind fuzz \
       --repo-url <repository-URL> --sha <target commit>
   ```

   One finding per crasher: its reproducer digest and path are in the report,
   which the `fuzz` assessment holds. Where the target's `audit_ref` names a
   recorded finding, set the crasher's `finding_id` and it confirms that
   finding; otherwise intake mints a new one. The
   baseline audit report is never written (gate A15), and recording the same
   report again adds no finding.

   A fuzz crasher is evidence class 1 because the triggering input is kept, so
   the claim is replayable. The converse is the part that gets misread: a
   fuzz run that finds nothing records no crasher here. Absence of a crash is not
   evidence of correctness.

   Findings belong to the repository, not to a product layer, so a repo
   shipped by several products needs no per-product choice.

### 6. Report (batch mode)

When running a full batch, `run-sweep.sh` and `gen-reports.sh` produce a
per-batch summary under this directory. Update the relevant `BATCH-<n>-PLAN.md`
with results (hit / miss / compile-gap per target) so the next batch's
selection can learn from it. The campaign rollup is
`traust dashboard view validation-fuzz --out <dir>`, built from the recorded
fuzz reports.

## Output

| Artefact | Path |
|---|---|
| New/updated manifest entry | `targets.json` |
| Harness source | `analysis-results/fuzz-harnesses/<id>/*_fuzz_test.go` — the CORPUS, not this repo: a harness is test code written ABOUT an audited repository, the same category as a finding about it. `file:` in `targets.json` is relative to that root (`HARNESSES` in the Makefile) |
| Reproducers | `analysis-results/findings/**/<id>/fuzz-corpus/<FuzzName>/<hash>` |
| Crashers (git-ignored) | `clones/<id>/<pkg>/testdata/fuzz/<FuzzName>/` |
| Fuzz report | recorded in traust as a `fuzz` assessment of the target commit (`traust reporting record --kind fuzz`) |
| Follow-up finding | a finding of that assessment, one per crasher (gate A15 — never the baseline) |
| Campaign summary + rollup | `traust dashboard view validation-fuzz --out <dir>` — `.md`, `.html` and the `.json` model dashboards consume, derived from the recorded reports |

The fuzz report is validated against its contract schema when it is recorded
(a crasher must name a harness the report lists). The originating audit report
is not modified (gate A15).

## Integrations

- **Inputs:** audit reports' fuzz-worthy entry points, core refuted findings
  (`traust findings refuted`, maintained by triage and track-findings decisions;
  FP falsification targets), and `/impact-analysis` artifacts (form 2b
  — the class-3→class-1 promotion path).
- **Outputs consumed by:** the recorded follow-up finding
  (with reproducer evidence) flows through `/track-findings` as
  execution evidence; the `validation-fuzz` view feeds
  `/validation-fuzz-dashboard`; crashers override FP assertions via
  evidence-class precedence in the disposition ledger.

## Spend declaration

After this skill's report/artifact is written, declare the run's spend
(contract: docs/model-routing.md):

```bash
python3 -m traust.cli registry models spend --skill create-fuzzing \
    --model <resolved model id> [--tokens-in <N>] [--tokens-out <N>]
```

Token counts are OPTIONAL and best-effort: pass them when the
orchestrator has them (Task results carry per-subagent usage),
otherwise omit them — an agent cannot observe its own usage mid-run.
**This row is a routing marker, not a cost claim**; actual per-lane
cost is attributed from session transcripts by
python3 -m traust.cli metrics attribute-spend. Never skip the row. Do not
pass `--repo`, `--loc`, `--batch` or `--note`: core's spend event has no
field for them, so the declaration refuses them and records nothing.
