"""``traust config migrate <old home>``: one ``traust.yaml`` from a pre-traust.yaml config home.

Every file in the old home gets one verdict: carried into ``traust.yaml`` (and under which key),
dropped (why), an adopter fact to record (the exact command), kept as it is, or moved elsewhere.
Tool pins, safe-exec profiles and the feeds registry ship with traust-core: an old copy is never
carried, only reported when it differs from the shipped one.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

import yaml
from traust_core.v1.context import Config
from traust_core.v1.context.config import (
    CONFIG_FILE,
    SHIPPED_EXTERNAL_TOOLS,
    SHIPPED_FEEDS,
    SHIPPED_SAFE_EXEC_PROFILES,
)
from traust_core.v1.errors import ConfigError

from traust.cli._doors import parser

SHIPPED = {
    "external-tools.yaml": SHIPPED_EXTERNAL_TOOLS,
    "safe-exec-profiles.yaml": SHIPPED_SAFE_EXEC_PROFILES,
    "feeds.yaml": SHIPPED_FEEDS,
}
FACTS = {
    "org-parameters.yaml": "traust compliance policy org-parameters {path}",
    "adr-registry.yaml": "traust compliance policy adr-registry {path}",
    "benchmark-targets.yaml": "traust sweep benchmark-targets {path}",
    "sla-policy.yaml": "traust dashboard sla-policy {path}",
    "product-definitions-map.yaml": "traust registry product-map {path}",
}
KEPT = {
    "model-registry.yaml": "read from the config home as today",
    "pqc-priority.yaml": "read from the config home as today (the PQC sweep's chokepoints)",
}
RETIRED = {
    "corpus-config.yaml": "no reader",
    "hardening-risk-weights.json": "no reader",
    "storage.yaml": "the remote materialiser is gone; the record store is `database.url`",
    "agent-plugins.yaml": "its reader exists only on main",
    "reachability-watch.yaml": "its reader was retired",
    "rpm-distgit-watch.yaml": "its feeder was deleted",
    "jira-sync.yaml": "moves into traust-internal's file-security-defect skill",
    "escalation-contacts-share.yaml": "moves into traust-internal records/",
    "internal-vocabulary.yaml": "public-export tooling input: keep it beside your export and "
    "pass it with `traust admin scan-internal-refs --vocabulary` (tools/public-export/)",
    "export.yaml": "public-export tooling input, not runtime config (tools/public-export/)",
}
_LEDGER_KEYS = ("key_path", "required")


def _read(path: Path) -> dict[str, Any]:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as e:
        raise ConfigError(f"cannot read {path}") from e
    if not isinstance(data, dict):
        raise ConfigError(f"{path}: not a mapping")
    return data


def _present(values: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in values.items() if v not in (None, "", [], {})}


def migrate(old: Path) -> tuple[dict[str, Any], list[str]]:
    """The ``traust.yaml`` document for ``old`` and one report line per file in it."""
    doc: dict[str, Any] = _read(old / "core.yaml") if (old / "core.yaml").is_file() else {}
    report: list[str] = []
    for path in sorted(p for p in old.iterdir() if p.is_file()):
        name = path.name
        if name == CONFIG_FILE:
            raise ConfigError(f"{old} already has a {CONFIG_FILE}: nothing to migrate")
        if name == "core.yaml":
            report.append(f"core.yaml: carried as the base of {CONFIG_FILE}")
        elif name == "locations.yaml":
            locations = _present({k: v for k, v in _read(path).items() if k != "version"})
            doc["locations"] = {**locations, **doc.get("locations", {})}
            report.append("locations.yaml: carried as `locations:`")
        elif name == "ledger.yaml":
            signing = _read(path).get("signing") or {}
            ledger = {k: v for k, v in signing.items() if k in _LEDGER_KEYS}
            doc["ledger"] = {**ledger, **doc.get("ledger", {})}
            report.append(
                "ledger.yaml: signing key carried as `ledger:`; its dsn is `database.url`"
            )
        elif name == "ledger-signing-key.pub":
            doc.setdefault("ledger", {}).setdefault("public_key_path", str(path.resolve()))
            report.append(f"{name}: carried as `ledger.public_key_path`")
        elif name == "budget-policy.yaml":
            policy = _read(path).get("budget_policy") or {}
            usd = (policy.get("monthly_budget") or {}).get("usd_central")
            if usd:
                enforcement = policy.get("enforcement") or "none"
                doc.setdefault("budgets", []).append(
                    {"lane": "full-audit", "monthly_usd": str(usd), "enforcement": enforcement}
                )
            report.append(
                "budget-policy.yaml: the monthly ceiling carried as `budgets` (lane full-audit); "
                "per-run, per-batch and band figures have no reader and are not carried"
            )
        elif name == "execution-boundaries.yaml":
            doc["execution"] = {"sandbox": _read(path).get("sandbox") or "none"}
            report.append("execution-boundaries.yaml: carried as `execution.sandbox`")
        elif name == "remediation.yaml":
            raw = _read(path)
            fork_org = None if raw.get("fork_org") == "example-org" else raw.get("fork_org")
            hosts = raw.get("private_forge_hosts")
            remediation = _present({"fork_org": fork_org, "private_forge_hosts": hosts})
            doc["remediation"] = {**remediation, **doc.get("remediation", {})}
            report.append(
                "remediation.yaml: carried as `remediation:` (naming_prefix had no reader)"
            )
        elif name == "campaign.yaml":
            raw = _read(path)
            campaign = _present({k: raw.get(k) for k in ("tracking_reference", "display_name")})
            if campaign:
                doc["campaign"] = campaign
            report.append("campaign.yaml: carried as `campaign:`")
        elif name == "rule-pack-allowlist.yaml":
            doc.setdefault("overrides", {})["rule_pack_allowlist"] = str(path.resolve())
            report.append(f"{name}: carried as `overrides.rule_pack_allowlist`")
        elif name in SHIPPED:
            if name == "feeds.yaml":
                osv = (_read(path).get("sources") or {}).get("osv") or {}
                if osv.get("access") == "air-gapped":
                    doc["feeds"] = {"osv_access": "air-gapped"}
                    report.append(
                        "feeds.yaml: osv `access: air-gapped` carried as `feeds.osv_access`"
                    )
            same = path.read_bytes() == SHIPPED[name].read_bytes()
            report.append(
                f"{name}: dropped, traust-core ships it (not configurable)"
                + ("" if same else "; differs from the shipped copy: review")
            )
        elif name in FACTS:
            report.append(f"{name}: adopter fact, record it: {FACTS[name].format(path=path)}")
        elif name in KEPT:
            report.append(f"{name}: kept, {KEPT[name]}")
        elif name in RETIRED:
            report.append(f"{name}: not migrated, {RETIRED[name]}")
        else:
            report.append(f"{name}: not recognised: review")
    return doc, report


def main(argv: list[str] | None = None) -> int:
    ap = parser("config", "migrate", __doc__.splitlines()[0])
    ap.add_argument("old_home", type=Path, help="the config home to migrate")
    ap.add_argument("--out", type=Path, help=f"where to write (default: <old home>/{CONFIG_FILE})")
    args: argparse.Namespace = ap.parse_args(argv)
    old: Path = args.old_home.expanduser()
    if not old.is_dir():
        print(f"not a directory: {old}", file=sys.stderr)
        return 2
    out: Path = args.out or old / CONFIG_FILE
    if out.exists():
        print(f"{out} exists: refusing to overwrite", file=sys.stderr)
        return 2
    try:
        doc, report = migrate(old)
        out.write_text(yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")
        Config.from_file(out)
    except ConfigError as e:
        out.unlink(missing_ok=True)
        print(f"config migrate: {e}", file=sys.stderr)
        return 2
    print(f"wrote {out}")
    print("\n".join(f"  {line}" for line in report))
    print("then delete the carried and dropped files, and run `traust admin doctor`")
    return 0


if __name__ == "__main__":
    sys.exit(main())
