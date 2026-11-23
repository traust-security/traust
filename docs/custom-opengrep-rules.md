# Custom Opengrep rules

Use Traust's Python CLI to admit **both adopter-authored and ledger-mined rules**.
Admission automatically runs Opengrep's own validation and fixture tests before
publishing an accepted pack. It needs no CI job or database. Admission is not
activation: review semantics and calibrate on representative recorded scans first.
Portfolio/ledger mining and `/mine-ledger` remain available alongside custom rules.

## 1. Install and create a private candidate

From the installed harness environment (see [setup](setup.md)):

```bash
python3 -m traust.cli admin toolchain setup --tool opengrep
mkdir -p custom-rules
cat > custom-rules/adopter-shell-command.yaml <<'YAML'
rules:
  - id: adopter-python-shell-command
    languages: [python]
    severity: WARNING
    message: Review shell=True command construction for untrusted input.
    metadata:
      cwe: ["CWE-78"]
    pattern: subprocess.run($CMD, shell=True, ...)
YAML
cat > custom-rules/adopter-shell-command.py <<'PY'
import subprocess


def vulnerable(user_input):
    # ruleid: adopter-python-shell-command
    subprocess.run("echo " + user_input, shell=True, check=True)


def safe(user_input):
    # ok: adopter-python-shell-command
    subprocess.run(["echo", user_input], shell=False, check=True)
PY
```

Keep the `.yaml` rule and same-basename `.py` fixture together. For other
languages use the appropriate fixture extension and valid source syntax. Each
unique rule ID needs meaningful positive (`ruleid:`) and negative (`ok:`)
assertions immediately before the relevant lines. Test equivalent safe, fixed or
guarded behavior, not unrelated no-op code. Fixture source is **parsed and
matched, not executed**; the vulnerable example above is not run.

This minimal rule detects a shell-enabled call shape, not input provenance. It
can flag trusted constant commands and miss other shell APIs. Native matching
does not prove exploitability, guard correctness or business impact; human
semantic review and precision/recall calibration remain necessary.

## 2. Admit through the mandatory publisher

```bash
python3 -m traust.cli sweep intake-rules ./custom-rules --into ./accepted-rules-v1
```

`intake-rules SOURCE... --into NEW_DEST` is the single publisher for mined and
adopter packs. Sources can be local rule files with their paired fixtures, local
directories containing complete packs, or commit-pinned HTTPS Git sources in
`https://HOST/OWNER/REPO@<40-hex-commit-SHA>` form. Git sources use the repository's
`rules/` subtree convention; include paired fixtures there. Branches, moving tags
and unpinned URLs are not accepted. Multiple sources must have unique rule IDs.

Traust snapshots the submitted bytes privately, checks the complete pack and
requires **both** native `opengrep validate` and
`opengrep test --json --strict`. Every rule needs complete positive and negative
receipts and exact expected matches: missing cases, unexpected matches, engine
errors or incomplete test coverage refuse publication. There is no skip flag.
`check-rules` is optional diagnosis only:

```bash
python3 -m traust.cli sweep check-rules ./custom-rules
```

It does not publish or replace admission. A CI result or a later scan cannot
replace this mandatory pre-publication gate either.

Read the intake JSON's `admitted`, `quality_checks`, `applied` and `refused`:

- Exit **0**: published checked bytes; `admitted: true` and `destination` identify
  the new accepted directory.
- Exit **1**: refused admission; no accepted destination is created.
- Exit **2**: typed error; no accepted destination is created.

Private drafts are not accepted packs. Never manually install them. Existing
destinations are never overwritten: fix candidates and publish upgrades into a
**new directory**, such as `./accepted-rules-v2`, then review and activate that
version explicitly. Keep the accepted rules and fixtures together and unchanged.

## 3. Activate and scan

After review and calibration, use the `destination` from successful intake in your
deployment's `$TRAUST_CONFIG_HOME/traust.yaml` (merge into its existing `locations`
mapping). Point to the accepted directory, never the private candidate directory:

```yaml
locations:
  opengrep_adopter_rules: /absolute/path/to/accepted-rules-v1
```

Relative paths resolve beside `traust.yaml`, not beside the scan checkout. Use a
path available to the Traust process running Opengrep, including server/runner
deployments. This
location is **additive** to baseline rules and enabled supplements. It participates
in both default Opengrep facts scans and the registered Opengrep scanner used by
normal audit/scanner artifact generation; it is not a facts-only integration.
An audit that invokes that registered scanner receives the custom matches in its
`AdapterResultArtifact` for normal downstream triage, not as automatic finding
verdicts. No extra audit flag or separate registration is needed.

For a local demonstration, scan a copy of the example as source code:

```bash
mkdir -p checkout
cp custom-rules/adopter-shell-command.py checkout/example.py
python3 -m traust.cli adapters opengrep ./checkout --out ./opengrep-facts.json
```

For a real assessment, replace `./checkout` with a source checkout you are
authorized to assess. The configured pack loads automatically; do not also pass
that same pack through `--add-rules`. An explicit `--rules` replacement does not
load the configured adopter pack. Each scan checks the actual rule bytes again.
Language-inapplicable rules are normal skips, not refusals.

Facts reports preserve healthy baseline/supplement matches but explicitly mark
refused additions or incomplete required coverage as degraded. Inspect `outcome`,
`errors` and `additive_rules` (including `refused` and `skipped`); exit 0 means a
report was written, not complete coverage. Target parse/timeout warnings remain
visible in `errors`. In contrast, registered scanner artifacts cannot represent
partial coverage: configured adopter-rule refusal or incomplete required coverage
raises a typed scanner failure and prevents artifact generation, matching enabled
supplements' fail-closed policy. Rules are never silently omitted from a
supposedly complete audit artifact.

For selective per-rule supplemental activation, see the comments in
[the allowlist template](../config/rule-pack-allowlist.example.yaml). The same
complete-pack admission and human calibration requirements apply.
