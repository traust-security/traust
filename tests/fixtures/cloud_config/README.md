# Cloud-config audit fixtures

Copied from traust-engine `tests/fixtures/cloud_config/` (`cc1b5b2`) and traust-core's (`cb9bf23`):
`checkov-3.3.6.json` is actual `checkov 3.3.6` output over the public-safe sample in `source/`,
its scan root rewritten to `/work/clone-a/myrepo`; legacy `run_checkov.py` (traust `a2dc012`)
normalizes it to 33 facts with snapshot id `68045f8c…0dea`. `myrepo-cloud-config-audit.json` is
a Phase 2 report over those facts. No estate data.
