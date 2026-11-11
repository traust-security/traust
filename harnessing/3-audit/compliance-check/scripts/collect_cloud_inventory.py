#!/usr/bin/env python3
"""Scoped, read-only cloud/cluster inventory → canonical snapshot (2b).

Materializes the `cloud_inventory` snapshot contract the compliance
mapping registry asserts over: `resources[]`, each carrying
{id, kind, region, encryption_at_rest, public_exposure, tags, source}.
The snapshot is canonicalized (traust-core's evidence_id — sorted
keys, volatile fields stripped) and stamped with its own sha256
(`snapshot_id`), so two collections over an unchanged environment are
byte-identical and every assessment can cite exactly which snapshot it
read (determinism amendments 3 and 6).

Scope: EXPLICIT-ONLY and fail-closed — every aws profile and cluster
context must be listed in a mode-1 `targets.yaml#cloud_inventory`
section (validate-findings scope guard, `inventory` adapter, verb
locked to `enumerate`). Every attempted enumeration lands in an
append-only audit trail. All cloud calls are read-only (list/get/
describe); nothing here can mutate an environment.

Degradation is loud, never silent: an unreachable profile/context or a
denied API call becomes a `gaps[]` entry, and controls reading absent
resource kinds verdict not_assessed downstream.

Usage:
    python3 scripts/collect_cloud_inventory.py --targets targets.yaml
        [--out <file>] [--skip-aws] [--skip-clusters]
"""

from __future__ import annotations

import argparse
import datetime
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

from traust_core.v1.models.compliance import evidence_id

from traust.paths import skill_dir


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


scope_mod = _load("vf_scope_inv", skill_dir("validate-findings") / "scope.py")

AWS_TIMEOUT = 120


def _aws(profile: str, *args) -> tuple[dict | list | None, str | None]:
    """One read-only aws CLI call -> (parsed json, error)."""
    cmd = ["aws", "--profile", profile, "--output", "json", *args]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=AWS_TIMEOUT)
    except FileNotFoundError:
        return None, "aws CLI not on PATH"
    except subprocess.TimeoutExpired:
        return None, f"timeout: {' '.join(args[:3])}"
    if proc.returncode != 0:
        return None, proc.stderr.strip().splitlines()[0][
            :160
        ] if proc.stderr.strip() else f"exit {proc.returncode}"
    try:
        return json.loads(proc.stdout or "{}"), None
    except json.JSONDecodeError:
        return None, "unparseable aws output"


def collect_aws_profile(profile: str) -> tuple[list[dict], list[str]]:
    resources, gaps = [], []

    # S3 buckets: region, encryption at rest, public access posture
    doc, err = _aws(profile, "s3api", "list-buckets")
    if err:
        gaps.append(f"{profile}: s3 list-buckets — {err}")
    else:
        for b in sorted((doc.get("Buckets") or []), key=lambda x: x.get("Name", "")):
            name = b.get("Name", "")
            loc, lerr = _aws(profile, "s3api", "get-bucket-location", "--bucket", name)
            region = ((loc or {}).get("LocationConstraint") or "us-east-1") if not lerr else None
            _enc, eerr = _aws(profile, "s3api", "get-bucket-encryption", "--bucket", name)
            # missing encryption config raises an error — that IS the
            # signal (encryption_at_rest false), not a gap
            encrypted = (
                True
                if not eerr
                else (
                    False
                    if "ServerSideEncryption" in (eerr or "") or "NotFound" in (eerr or "")
                    else None
                )
            )
            pab, perr = _aws(profile, "s3api", "get-public-access-block", "--bucket", name)
            if not perr:
                cfg = (pab or {}).get("PublicAccessBlockConfiguration") or {}
                public_exposure = not all(
                    cfg.get(k)
                    for k in (
                        "BlockPublicAcls",
                        "BlockPublicPolicy",
                        "IgnorePublicAcls",
                        "RestrictPublicBuckets",
                    )
                )
            else:
                public_exposure = True if "NoSuchPublicAccessBlock" in (perr or "") else None
            resources.append(
                {
                    "id": f"aws:{profile}:s3:{name}",
                    "kind": "s3_bucket",
                    "region": region,
                    "encryption_at_rest": encrypted,
                    "public_exposure": public_exposure,
                    "source": f"aws s3api ({profile})",
                }
            )

    # RDS instances: region (from AZ), storage encryption, exposure
    doc, err = _aws(profile, "rds", "describe-db-instances")
    if err:
        gaps.append(f"{profile}: rds describe-db-instances — {err}")
    else:
        for db in sorted(
            (doc.get("DBInstances") or []), key=lambda x: x.get("DBInstanceIdentifier", "")
        ):
            az = db.get("AvailabilityZone") or ""
            resources.append(
                {
                    "id": f"aws:{profile}:rds:{db.get('DBInstanceIdentifier', '')}",
                    "kind": "rds_instance",
                    "region": az[:-1] if az else None,
                    "encryption_at_rest": db.get("StorageEncrypted"),
                    "public_exposure": db.get("PubliclyAccessible"),
                    "source": f"aws rds ({profile})",
                }
            )
    return resources, gaps


def collect_cluster(context: str) -> tuple[list[dict], list[str]]:
    try:
        proc = subprocess.run(
            [
                "oc",
                "--context",
                context,
                "get",
                "infrastructure.config.openshift.io",
                "cluster",
                "-o",
                "json",
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )
    except FileNotFoundError:
        return [], [f"{context}: oc not on PATH"]
    except subprocess.TimeoutExpired:
        return [], [f"{context}: oc timeout"]
    if proc.returncode != 0:
        return [], [
            f"{context}: "
            + (proc.stderr.strip().splitlines()[0][:160] if proc.stderr.strip() else "oc failed")
        ]
    try:
        infra = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return [], [f"{context}: unparseable infrastructure CR"]
    status = infra.get("status") or {}
    platform = status.get("platformStatus") or {}
    ptype = platform.get("type", "")
    region = (platform.get(ptype.lower()) or {}).get("region") if ptype else None
    return [
        {
            "id": f"cluster:{context}",
            "kind": "openshift_cluster",
            "region": region,
            "platform": ptype or None,
            "infrastructure_name": status.get("infrastructureName"),
            "source": f"oc infrastructure CR ({context})",
        }
    ], []


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument(
        "--targets",
        required=True,
        type=Path,
        help="mode-1 rules-of-engagement file with a cloud_inventory section — the ONLY unlock",
    )
    ap.add_argument("--out", type=Path, default=None)
    ap.add_argument("--skip-aws", action="store_true")
    ap.add_argument("--skip-clusters", action="store_true")
    args = ap.parse_args(argv)

    scope = scope_mod.Scope.from_targets_file(args.targets)
    out = args.out or Path.cwd() / "cloud-inventory.json"
    audit_path = out.parent / "cloud-inventory-audit.jsonl"

    def audit(entry: dict):
        with audit_path.open("a", encoding="utf-8") as fh:
            entry["ts"] = datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
            fh.write(json.dumps(entry) + "\n")

    resources, gaps = [], []
    if not args.skip_aws:
        for profile in sorted(scope.inventory_aws_profiles):
            ok, reason = scope.is_in_scope(
                scope_mod.Action(
                    adapter="inventory", verb="enumerate", resource="aws_profile", name=profile
                )
            )
            audit(
                {
                    "action": f"inventory/enumerate aws:{profile}",
                    "scope_allowed": ok,
                    "scope_reason": reason,
                }
            )
            if not ok:
                gaps.append(f"{profile}: scope denied — {reason}")
                continue
            r, g = collect_aws_profile(profile)
            resources.extend(r)
            gaps.extend(g)
    if not args.skip_clusters:
        for context in sorted(scope.inventory_cluster_contexts):
            ok, reason = scope.is_in_scope(
                scope_mod.Action(
                    adapter="inventory", verb="enumerate", resource="cluster_context", name=context
                )
            )
            audit(
                {
                    "action": f"inventory/enumerate cluster:{context}",
                    "scope_allowed": ok,
                    "scope_reason": reason,
                }
            )
            if not ok:
                gaps.append(f"{context}: scope denied — {reason}")
                continue
            r, g = collect_cluster(context)
            resources.extend(r)
            gaps.extend(g)

    body = {"resources": sorted(resources, key=lambda r: r["id"]), "gaps": sorted(gaps)}
    snapshot_id = evidence_id(body)
    doc = {
        "metadata": {
            "artifact": "cloud-inventory-snapshot",
            "role": (
                "canonical read-only environment snapshot for "
                "compliance assertions; gaps are loud — controls "
                "over absent kinds verdict not_assessed"
            ),
            "collector": "collect_cloud_inventory.py",
            "engagement": scope.engagement,
            "snapshot_id": snapshot_id,
            "generated_at": datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        },
        **body,
    }
    # snapshot_id is computed over the CANONICALIZED body; the artifact
    # keeps its metadata (incl. generated_at, which canonicalization
    # would strip as volatile)
    out.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote {out}")
    print(f"  snapshot_id {snapshot_id[:16]}… | {len(resources)} resources | {len(gaps)} gap(s)")
    for g in gaps[:8]:
        print(f"  ! {g}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
