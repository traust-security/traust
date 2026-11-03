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
For that docs gate, an unset variable or an absent file is the unconfigured checkout case:
estate-marker checks are skipped, but the shipped config-file allowlist is still enforced.
An existing malformed or unreadable vocabulary fails the gate, and universal block/review
rules still run over config and docs. The standalone export scanner requires a valid
vocabulary even when the file is absent. Keep your copy out of this tree: a vocabulary
names what must not ship, so publishing it publishes the list.

The export itself (which repositories, which paths are stripped, how pins and links are
rewritten) is a deployment one-shot and lives with the deployment's own tooling, with its
`export.yaml`.
