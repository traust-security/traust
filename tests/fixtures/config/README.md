# Test fixture: an estate-neutral `TRAUST_CONFIG_HOME`

`tests/conftest.py` copies this directory into a private config home and writes its
`traust.yaml` (locations under the test's temp trees), so the suite runs without any
operational configuration. The other file is its `model-registry.yaml`.
Nothing here is deployment data and nothing here ships in the wheel. When a template changes
upstream, refresh the copy here.
