"""Phase 3 tests: the compliance runner."""

import importlib.util
import json
import sys

import pytest

from traust.paths import skill_dir

yaml = pytest.importorskip("yaml")
pytest.importorskip("jsonschema")

from tests.compliance_paths import compliance_fixtures_dir


def _check_fixtures_dir():
    return compliance_fixtures_dir() / "fixtures"


def _load(name):
    _paths = {
        "run_compliance_check": (
            skill_dir("compliance-check") / "scripts" / "run_compliance_check.py"
        ),
    }
    spec = importlib.util.spec_from_file_location(name, _paths.get(name, "traust.cli.{name}"))
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


rcc = _load("run_compliance_check")
# The IaC-declaration adapters and their four tests moved to the internal
# extension repo on 2026-09-07 (tests/test_compliance_iac_adapters.py there):
# they are the deployment's seam, not the runner.


def _run(tmp_path, *extra):
    out = tmp_path / "out"
    argv = [
        "--frameworks",
        "all",
        "--target-kind",
        "both",
        "--repos",
        "org/demo",
        "--environment",
        "lab",
        "--collector",
        "cloud_inventory="
        + str(_check_fixtures_dir() / "chk-encryption-at-rest/good/snapshot.json"),
        "--collector",
        "scan_k8s_hardening="
        + str(_check_fixtures_dir() / "chk-no-privileged-workloads/good/snapshot.json"),
        "--findings-db",
        str(tmp_path / "absent.db"),
        "--out-dir",
        str(out),
        *extra,
    ]
    rc = rcc.main(argv)
    base = rcc.artifact_base("lab", "all")
    doc = json.loads((out / f"{base}.json").read_text())
    return rc, doc, out


def test_all_expands_and_skips_with_reasons(tmp_path):
    rc, doc, _ = _run(tmp_path, "--trust-categories", "security")
    assert rc == 0
    skipped = doc["metadata"]["skipped_frameworks"]
    assert "pci-dss-v4" in skipped and "CDE" in skipped["pci-dss-v4"]
    assert "gdpr-technical" in skipped
    ran = {f["id"] for f in doc["metadata"]["frameworks"]}
    assert {"nist-800-53-rev5", "fedramp-high", "fedramp-moderate", "soc2-tsc"} <= ran


def test_soc2_without_categories_skipped(tmp_path):
    _rc, doc, _ = _run(tmp_path)
    assert "soc2-tsc" in doc["metadata"]["skipped_frameworks"]


def test_product_only_skips_environment_frameworks(tmp_path):
    out = tmp_path / "o2"
    rcc.main(
        [
            "--frameworks",
            "all",
            "--target-kind",
            "product",
            "--repos",
            "org/demo",
            "--personal-data-stores",
            "s1",
            "--out-dir",
            str(out),
        ]
    )
    base = rcc.artifact_base("org/demo", "all")
    doc = json.loads((out / f"{base}.json").read_text())
    sk = doc["metadata"]["skipped_frameworks"]
    for fw in ("fedramp-high", "fedramp-moderate", "gdpr-technical"):
        assert fw in sk and "deployed-environment" in sk[fw]


def test_gate_passes_and_bundle_verifies(tmp_path):
    rc, doc, out = _run(tmp_path, "--trust-categories", "security")
    assert rc == 0  # runner already ran the gate incl. evidence dir
    # every satisfied/not_satisfied evidence sha exists in the bundle
    for r in doc["results"]:
        for ev in r.get("evidence") or []:
            assert (out / "evidence" / f"{ev['sha256']}.json").is_file()
            assert "_value" not in ev


def test_caveats_injected(tmp_path):
    _, doc, _ = _run(tmp_path, "--trust-categories", "security")
    by_id = {f["id"]: f for f in doc["metadata"]["frameworks"]}
    assert "point-in-time" in by_id["soc2-tsc"]["caveat"]
    assert "800-53B" in by_id["fedramp-moderate"]["caveat"]


def test_missing_collector_yields_not_assessed(tmp_path):
    out = tmp_path / "o3"
    rc = rcc.main(
        [
            "--frameworks",
            "nist-800-53-rev5",
            "--target-kind",
            "both",
            "--environment",
            "lab",
            "--out-dir",
            str(out),
        ]
    )
    assert rc == 0
    base = rcc.artifact_base("lab", "nist-800-53-rev5")
    doc = json.loads((out / f"{base}.json").read_text())
    det = [r for r in doc["results"] if r["classification"] == "deterministic"]
    assert det and all(r["verdict"] == "not_assessed" for r in det)
    assert all("collector unavailable" in r["reason"] for r in det)


def test_unknown_framework_rejected(tmp_path):
    with pytest.raises(SystemExit):
        rcc.main(
            ["--frameworks", "iso-27001", "--target-kind", "product", "--out-dir", str(tmp_path)]
        )


def test_oscal_uuids_content_derived(tmp_path):
    _, _, out1 = _run(tmp_path, "--trust-categories", "security", "--oscal")
    base = rcc.artifact_base("lab", "all")
    o = json.loads((out1 / f"{base}.oscal.json").read_text())
    obs = o["assessment-results"]["results"][0]["observations"]
    assert obs and all(len(x["uuid"]) == 36 for x in obs)
    import uuid as _u

    for x in obs:  # uuid5 = version 5
        assert _u.UUID(x["uuid"]).version == 5


# ---------------- environment extractor ----------------

CLUSTER_YML = """---
$schema: /openshift/cluster-1.yml
labels: {service: insights, env: stage}
name: crcs02ue1
serverUrl: https://api.crcs02ue1.example:6443
internal: false
spec: {product: osd, region: us-east-1}
"""


# ---------------- IaC collector ----------------


AI_CLUSTER = """---
$schema: /openshift/cluster-1.yml
name: c1
labels: {env: production}
spec: {product: rosa, region: eu-west-2}
"""
AI_NS = """---
$schema: /openshift/namespace-1.yml
name: svc
cluster: {$ref: /openshift/c1/cluster.yml}
externalResources:
- provider: aws
  provisioner: {$ref: /aws/acct/account.yml}
  resources:
  - {provider: s3, identifier: b1, defaults: /terraform/resources/s3.yml}
  - {provider: rds, identifier: d1, defaults: /terraform/resources/rds.yml,
     region: us-west-2}
"""


def test_findings_db_views_repo_prefix_isolation(tmp_path):
    # 'org/ap' must not match 'https://github.com/org/api': the views feed
    # control assertions, so a prefix match counts a foreign repo's findings.
    import sqlite3

    db = tmp_path / "findings.db"
    con = sqlite3.connect(db)
    con.execute("CREATE TABLE repos (repo_key TEXT, repo_url TEXT)")
    con.execute(
        "CREATE TABLE v_open (finding_id TEXT, severity TEXT, primary_cwe TEXT,"
        " validity TEXT, repo_key TEXT)"
    )
    con.executemany(
        "INSERT INTO repos VALUES (?, ?)",
        [
            ("org/ap", "https://github.com/org/ap"),
            ("org/api", "https://github.com/org/api"),
        ],
    )
    con.executemany(
        "INSERT INTO v_open VALUES (?, ?, ?, ?, ?)",
        [
            ("F-1", "critical", "CWE-1395", "confirmed", "org/ap"),
            ("F-2", "critical", "CWE-1395", "confirmed", "org/api"),
        ],
    )
    con.commit()
    con.close()

    views = rcc.findings_db_views(db, ["org/ap"])

    ids = {r["id"] for r in views["open_critical_dependency_findings"]}
    assert ids == {"F-1"}, f"foreign findings leaked into the view: {ids}"
