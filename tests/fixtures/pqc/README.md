# PQC fixtures

`widget-pqc-readiness.json`: a Layer-2 report in the shape the skill emits, copied from traust-core `tests/fixtures/pqc/` (repository, commit, paths and vendor are placeholders).

`vendor-claims.json` is traust-core's `tests/fixtures/pqc/vendor-claims.json`: six vendors of
the curated registry `build_pqc_vendor_tracker.py` read, reshaped to the contracts
`pqc-vendor-claims` document and sanitized (no internal owners, repositories or products).
