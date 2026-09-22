#!/usr/bin/env python3
"""End-to-end efficacy benchmark for /compliance-check (Phase 8).

The per-check fixture gate (tests/test_compliance_fixtures.py) proves
each check fires correctly IN ISOLATION; the idempotence gate
(calibrate_compliance.py) proves determinism. Neither tests the
PIPELINE: collector assembly → registry → multi-check controls →
crosswalked frameworks → coverage honesty on a composed target with
mixed states. This scorer does, against a seeded target whose expected
verdicts are true BY CONSTRUCTION (the answer key is authored with the
snapshots, never bootstrapped from running the tool — bootstrapping
would pin current behavior, which is a regression test, not efficacy).

Three failure classes, in order of severity:
  GUESSING      an expected-not_assessed honesty probe got a verdict —
                the assessor invented evidence; worst possible failure
  WRONG VERDICT computed verdict != constructed truth
  INCOHERENCE   declared crosswalk pairs disagree

Fixture: progress-tracker/configs/compliance/efficacy/seeded-target/
(snapshots + org-parameters + expected-verdicts.yaml). The findings-db
leg materializes from findings-rows.json into a temp sqlite so no
binary is committed.

Usage:
    python3 score_compliance_efficacy.py [--fixture <dir>]
        [--out-dir <dir>] [--keep-work]
Exit 0 = every expectation met; 1 = any failure (CI-able).
"""

from __future__ import annotations

import argparse
import datetime
import json
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path

from traust.context import add_config_home_arg, load_engine, progress_tracker_dir
from traust.paths import HARNESS_ROOT, skill_dir

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None


def build_findings_db(rows_path: Path, db_path: Path):
    rows = json.loads(rows_path.read_text(encoding="utf-8"))
    con = sqlite3.connect(db_path)
    con.execute("CREATE TABLE repos (repo_key TEXT PRIMARY KEY, repo_url TEXT)")
    con.execute(
        "CREATE TABLE v_open (finding_id TEXT, severity TEXT, "
        "primary_cwe TEXT, validity TEXT, repo_key TEXT)"
    )
    con.executemany("INSERT INTO repos VALUES (:repo_key, :repo_url)", rows["repos"])
    con.executemany(
        "INSERT INTO v_open VALUES (:finding_id, :severity, :primary_cwe, :validity, :repo_key)",
        rows["v_open"],
    )
    con.commit()
    con.close()


def run_assessment(fixture: Path, work: Path) -> dict:
    key = yaml.safe_load((fixture / "expected-verdicts.yaml").read_text(encoding="utf-8"))
    run = key["run"]
    db = work / "findings.db"
    build_findings_db(fixture / "findings-rows.json", db)
    cmd = [
        sys.executable,
        str(skill_dir("compliance-check") / "scripts" / "run_compliance_check.py"),
        "--frameworks",
        run["frameworks"],
        "--target-kind",
        run["target_kind"],
        "--environment",
        run["environment"],
        "--repos",
        *run["repos"],
        "--findings-db",
        str(db),
        "--org-parameters",
        str(fixture / "org-parameters.yaml"),
        "--collector",
        f"cloud_inventory={fixture / 'cloud-inventory.json'}",
        "--collector",
        f"scan_k8s_hardening={fixture / 'khs.json'}",
        "--cde-boundary",
        run["cde_boundary"],
        "--personal-data-stores",
        run["personal_data_stores"],
        "--trust-categories",
        run["trust_categories"],
        "--out-dir",
        str(work),
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(f"runner failed:\n{proc.stderr[-2000:]}")
    arts = list(work.glob("*compliance-assessment.json"))
    if len(arts) != 1:
        raise RuntimeError(f"expected 1 artifact, found {len(arts)}")
    return key, json.loads(arts[0].read_text(encoding="utf-8"))


def verdict_map(artifact: dict) -> dict[str, str]:
    out = {}
    for fw_block in artifact.get("results") or []:
        fw = fw_block.get("framework")
        for r in fw_block.get("controls") or []:
            out[f"{fw}:{r.get('control_id')}"] = r.get("verdict")
    # tolerate flat results shape
    if not out:
        for r in artifact.get("results") or []:
            if isinstance(r, dict) and r.get("framework"):
                out[f"{r['framework']}:{r.get('control_id')}"] = r.get("verdict")
    return out


def score(key: dict, artifact: dict) -> dict:
    got = verdict_map(artifact)
    failures = []
    checked = 0
    for fw, controls in (key.get("expected") or {}).items():
        for cid, want in controls.items():
            ref = f"{fw}:{cid}"
            checked += 1
            actual = got.get(ref)
            if actual is None:
                failures.append(
                    {
                        "class": "MISSING",
                        "control": ref,
                        "expected": want,
                        "got": "(no result emitted)",
                    }
                )
            elif actual != want:
                cls = "GUESSING" if ref in (key.get("honesty_probes") or []) else "WRONG_VERDICT"
                failures.append({"class": cls, "control": ref, "expected": want, "got": actual})
    for a, b in key.get("crosswalk_coherence") or []:
        if got.get(a) != got.get(b):
            failures.append(
                {
                    "class": "INCOHERENCE",
                    "control": f"{a} <> {b}",
                    "expected": "agreement",
                    "got": f"{got.get(a)} vs {got.get(b)}",
                }
            )
    order = {"GUESSING": 0, "WRONG_VERDICT": 1, "MISSING": 2, "INCOHERENCE": 3}
    failures.sort(key=lambda f: order.get(f["class"], 9))
    return {
        "artifact": "compliance-efficacy-report",
        "generated_at": datetime.datetime.now(datetime.UTC).isoformat(timespec="seconds"),
        "harness_version": (HARNESS_ROOT / "VERSION").read_text().strip()
        if (HARNESS_ROOT / "VERSION").is_file()
        else "unknown",
        "controls_checked": checked,
        "crosswalk_pairs_checked": len(key.get("crosswalk_coherence") or []),
        "failures": failures,
        "verdict": "PASS" if not failures else "FAIL",
        "note": (
            "answer key is constructed truth "
            "(expected-verdicts.yaml); a failure means the "
            "pipeline is wrong OR a reviewed mapping change made "
            "the key stale — fix whichever in the same change"
        ),
    }


def render_md(rep: dict) -> str:
    L = [
        "# Compliance Efficacy Report (end-to-end seeded target)",
        "",
        f"_{rep['generated_at']} · harness {rep['harness_version']} · "
        f"{rep['controls_checked']} controls + "
        f"{rep['crosswalk_pairs_checked']} crosswalk pairs · "
        f"**{rep['verdict']}**_",
        "",
    ]
    if rep["failures"]:
        L += ["| Class | Control | Expected | Got |", "|---|---|---|---|"]
        L += [
            f"| {f['class']} | `{f['control']}` | {f['expected']} | {f['got']} |"
            for f in rep["failures"]
        ]
    else:
        L.append(
            "Every constructed expectation met — including the "
            "honesty probes (absent collector stayed "
            "`not_assessed`) and crosswalk coherence."
        )
    L.append("")
    return "\n".join(L)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    add_config_home_arg(ap)
    ap.add_argument("--fixture", type=Path, default=None)
    ap.add_argument("--out-dir", type=Path, default=None)
    ap.add_argument("--keep-work", action="store_true")
    args = ap.parse_args(argv)
    if yaml is None:
        sys.exit("PyYAML required")

    engine = load_engine(args.config_home)
    tracker = progress_tracker_dir(engine)
    fixture = args.fixture or (tracker / "configs" / "compliance" / "efficacy" / "seeded-target")
    out_dir = args.out_dir or (tracker / "metrics" / "dashboards" / "compliance")
    if not fixture.is_dir():
        sys.exit(f"fixture not found: {fixture}")

    with tempfile.TemporaryDirectory(prefix="compliance-efficacy-") as w:
        work = Path(w)
        key, artifact = run_assessment(fixture, work)
        rep = score(key, artifact)
        if args.keep_work:
            keep = out_dir / "efficacy-work"
            keep.mkdir(parents=True, exist_ok=True)
            for f in work.iterdir():
                if f.is_file():
                    (keep / f.name).write_bytes(f.read_bytes())

    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "compliance-efficacy.json").write_text(
        json.dumps(rep, indent=2) + "\n", encoding="utf-8"
    )
    (out_dir / "compliance-efficacy.md").write_text(render_md(rep), encoding="utf-8")
    print(
        f"{rep['verdict']}: {rep['controls_checked']} controls, "
        f"{len(rep['failures'])} failure(s) -> {out_dir}"
    )
    for f in rep["failures"][:10]:
        print(f"  {f['class']}: {f['control']} expected {f['expected']}, got {f['got']}")
    return 0 if rep["verdict"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
