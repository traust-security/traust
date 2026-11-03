# CLI Command Reference

<!-- The group/operation table below is verified against the live GROUPS
     registry by the "CLI reference drift" check in check_docs_consistency.py.
     Add a group or operation in code and this table fails the docs gate
     until it matches — do not hand-wave it. -->

The harness CLI is grouped: **`traust <group> <operation>`**, or
`python3 -m traust.cli <group> <operation>` from the harness venv. Both are the
same entry point (`[project.scripts] traust = "traust.cli.__main__:main"`).

```bash
traust check skill-alignment
python3 -m traust.cli check skill-alignment      # equivalent
```

## Command groups

17 groups (plus the deprecated `tools` group below).

| Group | Description | Operations |
|---|---|---|
| `adapters` | Scanner adapters (deterministic pre-scans) | `below-range`, `checkov`, `crypto-audit`, `crypto-probe`, `gitleaks`, `govulncheck`, `joern`, `llm-app`, `opengrep`, `osv`, `yara` |
| `admin` | Operator tooling | `attest-target`, `checkpoint`, `countersign`, `query-index`, `scan-internal-refs`, `toolchain` |
| `build` | Deterministic builders | `cumulative`, `rescan-worklist`, `skills-reference`, `symbol-index` |
| `check` | Deterministic gates | `citations`, `content-licenses`, `docs-consistency`, `estate-data`, `drift`, `fix-propagation`, `location-paths`, `reference-integrity`, `report-digests`, `skill-alignment`, `skill-security` |
| `compliance` | Compliance reporting | `dashboard`, `scope` |
| `corpus` | Corpus management | `finding-identity`, `findings-db`, `precedent`, `resolve`, `summary` |
| `dashboard` | Dashboard rebuilds | `refresh` |
| `feeds` | Feed management | `fetch`, `reconcile-cve-provenance` |
| `impact` | Impact analysis | `analyze`, `calibrate-rule-pack`, `cluster-state-diff`, `resolve-advisory-symbols`, `sweep` |
| `ledger` | Ledger emission | `doc-variance`, `emit-triage`, `emit-validation`, `emit-verification`, `pull` |
| `metrics` | Metrics & spend | `attribute-spend`, `collect-spend`, `history`, `sla`, `spend` |
| `portfolio` | Portfolio graph | `artifacts`, `build`, `deps-multi`, `freshness`, `interfaces`, `parsers`, `query`, `stats`, `symbols` |
| `registry` | Model/product registry | `models`, `products` |
| `reporting` | Report validation & rendering | `lint`, `rate-threats`, `render`, `sarif`, `validate` |
| `route` | Finding routing | `impact-findings`, `regressions` |
| `sweep` | Class-generalization sweep | `benchmark`, `collect`, `draft`, `emit`, `mine`, `rule-lane`, `sweep` |
| `util` | Utility commands | `elf`, `redact`, `safe-exec` |

## Check scope and configuration

`traust check estate-data --staged` reads Git index contents, including migration
portability markers. Unstaged edits or a removed working copy cannot hide staged
measurements. Rename destinations are checked, including files moved into
migrations. Whole-tree scans also check untracked migrations; invalid UTF-8 cannot
hide a missing portability marker.

`traust check skill-security` checks sandbox routing for each detected build.
Both `traust util safe-exec run` and `python3 -m traust.cli util safe-exec run`
are accepted. Prose, comments, imports, an unrelated wrapped build, or
`safe-exec check` do not route a direct build.
Python analysis follows execution-call bindings and command values in statement
order: imports (including relevant wildcard exports), callable/string/argv
assignments, and `split()` / `shlex.split()` values. Conditional and loop joins
retain possible unsafe origins; a later import or a mutually exclusive branch
cannot retroactively route an earlier call.

Import bindings within the analyzed file respect module, function, class and closure
boundaries. Explicit
global/nonlocal writes, callable defaults and deferred generators retain their
evaluation scope. Docstrings, printed examples, argument-parser help and proven
argument data are not commands or file-wide routing exemptions.

Literal argv is checked by the actual executable, including explicit OS
exec/spawn paths; build words passed to `echo` are data. Actual shell/Python
wrapper payloads are checked as code with their quoting and option semantics.
An unresolved execution command uses non-inert source provenance conservatively.
Same-file function/lambda returns follow the effective callable, including supported
local replacement/forwarding decorators and known instance, static and class methods.
Aliases, argument binding, live closure cells and class attribute lookup retain their
definition/invocation context; unrelated or overwritten returns are not swept into sinks.
Known-length starred arguments retain their exact positions. An unresolved `*args`
is an unknown-length positional span, not one argument: every parameter it can fill
retains possible element provenance instead of silently selecting a harmless default.
Fixed prefixes, keyword-only bindings and keyword/arity constraints remain distinct;
variadic forwarding and awaited calls retain that uncertainty.
Calling an async function produces a coroutine, not its body value or side effects;
those become available only when awaited. Generator objects likewise do not expose
their explicit return value as a command.

This is bounded static analysis, not whole-program evaluation. Imported user-helper
definitions, opaque decorators, reflective descriptors and externally unknown method
receivers remain unresolved; follow-up is tracked in
[S10 callable-resolution issue #360](https://github.com/traust-security/traust/issues/360).
Shell-file checks retain their conservative per-command routing policy.

`traust check docs-consistency --root <path>` uses the selected checkout's skills
for the model-class index. Its config/docs estate checks skip deployment vocabulary
when no vocabulary file is configured. An existing but invalid
`internal-vocabulary.yaml` fails the gate, and universal credential/network rules
remain active even when the deployment rules cannot load.
Vocabulary validation also runs when the selected checkout has no `config/` or
`docs/` directory; absent content cannot make broken configuration look clean.

`traust check drift --config-home <path>` resolves inventory and results from that
configuration, including roots outside the workspace. Graph, impact, language
coverage/cache, benchmark and product-map checks use those selected roots, not a
conventional sibling copy. An explicit `--workspace` selecting a different
workspace uses that workspace's conventional `inputs/`, `analysis-results/` and
`progress-tracker/` roots instead.

`traust feeds fetch --config-home <path> --feed <name>` validates names and resolves
feed configuration from the explicit home before fetching, regardless of
`TRAUST_CONFIG_HOME`. Without the flag, the environment/default home still applies.
Feed drift enumerates and classifies sources from its own selected engine/home,
including optionality and ownership-reference rows. A fetch from another home
earlier in the same process cannot change those rows or their cache freshness.
An absent cache reports pending rows for the actual configured sources.

`traust admin attest-target --url <url>` treats an HTTP response below 500,
including a 4xx rejection, as reachability evidence and records the URL. This does
not attest authorization or application correctness. HTTP 5xx and transport
failures leave the target unattested.

## Deprecated forms

Two older spellings still work and must not be used in docs, skills, or
command wrappers:

| Form | Example | Use instead |
|---|---|---|
| Pre-grouping module invocation | `python3 -m traust.cli.check_skill_alignment` | `python3 -m traust.cli check skill-alignment` |
| `tools` group alias | `python3 -m traust.cli tools check-skill-alignment` | `python3 -m traust.cli check skill-alignment` |

The dot-separated form keeps working because each `src/traust/cli/<module>.py`
carries an `__main__` delegate that forwards to the grouped parser — which is
exactly why a stale example drifts silently. `src/traust/cli/groups/tools.py`
self-describes as "deprecated aliases for migrated command groups".

Both are enforced: the **CLI invocation syntax** check in
[`check_docs_consistency.py`](../src/traust/cli/check_docs_consistency.py) fails
the docs gate on any dot-separated invocation in `README.md`, `AGENTS.md`,
`PROCESS.md`, `docs/*.md`, `config/*`, `harnessing/*/SKILL.md`, or
`.claude/commands/*.md`.

> Not every `traust.cli.*` module is a CLI. `traust.cli.budget_shadow`, for
> instance, has no argparse or `__main__` — refer to it as a module path, never
> as `python3 -m`.

See [tooling-and-structure-files.md](tooling-and-structure-files.md) for what
each packaged CLI does, and [skills.md](skills.md) for the skills that call them.
