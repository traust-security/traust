# Work-routing characterization corpus

The legacy daily router's answers, kept as the expected outputs for the security
pack's router (`traust.ops.router`, checked by `tests/test_security_router.py`).

- `python_decisions.json`: 93 decision-table and 20 risk-tier cases.
- `python_primary.json`: 30 event-lane and 159 primary-selection cases.

Both files were exported from the legacy Python worklist (`build_rescan_worklist.py`);
their `source` blocks name the revision and whole-file SHA-256 they came from. That
router was retired on 2026-11-03 (it read a `findings.db` projection nothing builds),
so the corpus is now fixed history: change it only for an intentional routing-policy
change, reviewed case by case, never to make a failure disappear.

`baseline.json` records each file's SHA-256 and case counts, and
`test_the_corpus_is_the_recorded_history` checks them: an edit to an expected answer fails
until the manifest is updated with it, in the same reviewed change.
