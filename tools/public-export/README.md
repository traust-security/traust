# `tools/public-export/`: publishing a tree, not runtime config

Inputs to publishing a traust tree publicly. Nothing at run time reads them.

| File | What it is |
|---|---|
| `internal-vocabulary.example.yaml` | the template for your organization vocabulary: the rules naming your hosts, tools, trackers and products that the pre-publication scrub adds to its universal rules |

```bash
cp tools/public-export/internal-vocabulary.example.yaml ~/my-export/internal-vocabulary.yaml
$EDITOR ~/my-export/internal-vocabulary.yaml
traust admin scan-internal-refs --vocabulary ~/my-export/internal-vocabulary.yaml --fail-on review <repo>
```

`HARNESS_INTERNAL_VOCABULARY=<file>` does the same as `--vocabulary`, and also turns on the
estate-marker checks for shipped `config/` and `docs/` in `traust check docs-consistency`.
For that docs gate, only an unset or blank variable is the unconfigured checkout case:
estate-marker checks are skipped, but the shipped config-file allowlist is still enforced.
A configured path that is missing, not a file, malformed or unreadable fails the gate,
even if the selected root has no `config/` or `docs/` directory. Universal block/review
rules still run over any config and docs present after a configured load failure.
Diagnostics identify the vocabulary path, never its private rule payload or the raw
loader exception; inspect the private file locally. The standalone export scanner
always requires a valid vocabulary, even when none is configured. Its validation errors
identify rule positions and invalid fields without echoing rule content.

Each rule requires nonempty string `id`, `tier` and `pattern` fields; `tier` must be one
of the scanner's supported tiers and `pattern` must compile as a regular expression.
`why` must be a string when supplied: omission or an empty string falls back to the
rule ID, while explicit `false`, `0`, `null`, lists and mappings are invalid.
Keep your copy out of this tree: a vocabulary names what must not ship, so publishing
it publishes the list.

The export itself (which repositories, which paths are stripped, how pins and links are
rewritten) is a deployment one-shot and lives with the deployment's own tooling, with its
`export.yaml`.
