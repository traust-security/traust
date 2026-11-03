"""``traust check drift``: security-pack config pins and review dates against their source.

Home: traust-pack-security pack-config validation, interim in traust (plan: traust stops
importing traust-engine, step 3). Rule-pack pins (YARA, argus) and ADR register pins vs their
upstream HEAD, the vendored framework spine vs its oscal-content pin, and dated policy values
past their review window, and the doc-variance lane's declared doc versions vs the live
landing pages. The surviving rescan worklist retains its age backstop here; inventory
bootstrap reads current native inputs without a derived graph cache. Other freshness reads
use `traust dashboard view freshness`. Routes attention, never concludes: a pin or date
advances only by a deliberate config change.
"""

from __future__ import annotations

import argparse
import datetime
import importlib.util
import json
import os
import re
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Any

import yaml
from traust_core.v1.context import Services
from traust_core.v1.models.artifacts import (
    AdrRegistryArtifact,
    ArtifactDocument,
    OrgParametersArtifact,
    SlaPolicyArtifact,
)

from traust.context import SLA_POLICY, add_config_home_arg, analysis_results_dir, inputs_dir, load
from traust.paths import SECURITY_PACK_DIR

PROVENANCE_REVIEW_DAYS = 180
DOCS_MAP_STALE_DAYS = 30
RESCAN_WORKLIST_STALE_DAYS = 3
_HTTPS_ONLY = {**os.environ, "GIT_ALLOW_PROTOCOL": "https"}
MISSING = object()


def item(name: str, status: str, detail: str, refresh: str | None = None) -> dict:
    d = {"item": name, "status": status, "detail": detail}
    if refresh:
        d["refresh"] = refresh
    return d


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.UTC)


def _parse_iso(s: str) -> datetime.datetime | None:
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d"):
        try:
            return datetime.datetime.strptime(s.strip(), fmt).replace(tzinfo=datetime.UTC)
        except (ValueError, AttributeError):
            continue
    return None


def _remote_head(url: str, ref: str) -> str:
    """The upstream commit `ref` names; raises when the remote can't be read."""
    return subprocess.run(
        ["git", "ls-remote", "--", url, ref],
        capture_output=True,
        text=True,
        timeout=60,
        env=_HTTPS_ONLY,
    ).stdout.split()[0]


def _module_text(module: str) -> str | None:
    spec = importlib.util.find_spec(module)
    origin = Path(spec.origin) if spec and spec.origin else None
    return origin.read_text(encoding="utf-8") if origin and origin.is_file() else None


def _recorded(services: Services, kind: type[ArtifactDocument]) -> dict | None:
    doc = services.artifacts.latest(kind)
    return None if doc is None else json.loads(doc.payload)


def check_rescan_worklist(path: Path) -> list[dict]:
    """The daily router's output, including a missing worklist, against its three-day window."""
    refresh = f"traust build rescan-worklist --out {path}"
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return [item("rescan-worklist", "stale", f"worklist missing: {path}", refresh)]
    except (OSError, UnicodeError, json.JSONDecodeError) as e:
        return [item("rescan-worklist", "unavailable", f"cannot read {path}: {e}")]
    stamp = _parse_iso(doc.get("generated_at")) if isinstance(doc, dict) else None
    if stamp is None:
        return [item("rescan-worklist", "unavailable", f"no usable generated_at in {path}")]
    days = (_now() - stamp).total_seconds() / 86400
    stale = days > RESCAN_WORKLIST_STALE_DAYS
    return [
        item(
            "rescan-worklist",
            "stale" if stale else "fresh",
            f"{path} generated {stamp.isoformat()} ({days:.1f}d ago; "
            f"threshold {RESCAN_WORKLIST_STALE_DAYS}d)",
            refresh if stale else None,
        )
    ]


def check_adr_registry(services: Services) -> list[dict]:
    reg = _recorded(services, AdrRegistryArtifact)
    if reg is None:
        return [
            item(
                "adr-registry",
                "pending",
                "none recorded (traust compliance policy adr-registry <file>)",
            )
        ]
    out = []
    for r in reg["registers"]:
        name, url, pin = r.get("name"), r.get("repo"), r.get("pin")
        if not str(url).startswith("https://"):
            out.append(
                item(
                    f"adr-registry:{name}", "unavailable", f"non-https registry url refused: {url}"
                )
            )
            continue
        try:
            head = _remote_head(url, "HEAD")
        except (subprocess.SubprocessError, OSError, IndexError):
            out.append(item(f"adr-registry:{name}", "unavailable", f"cannot reach {url}"))
            continue
        if pin and head and not head.startswith(pin):
            out.append(
                item(
                    f"adr-registry:{name}",
                    "stale",
                    f"pinned {pin[:12]} but upstream HEAD {head[:12]} — "
                    "decisions may have been added/amended/superseded",
                    "review upstream changes, then advance the pin (deliberate config change)",
                )
            )
        else:
            out.append(
                item(f"adr-registry:{name}", "fresh", f"pin matches upstream HEAD ({head[:12]})")
            )
    return out


def _rules_pin(row: str, module: str, constant: str, branch: str, landed: str) -> list[dict]:
    """A rule pack pinned by `<constant>_SHA` / `<constant>_REPO` in `module` vs upstream
    `branch` HEAD; the pack ages faster than the tool provider that runs it."""
    text = _module_text(module)
    if text is None:
        return [item(row, "pending", f"{module} not installed")]
    m_sha = re.search(rf'{constant}_SHA\s*=\s*"([0-9a-f]{{40}})"', text)
    m_repo = re.search(rf'{constant}_REPO\s*=\s*"(https://[^"]+)"', text)
    if not (m_sha and m_repo):
        return [
            item(row, "unavailable", f"cannot parse {constant}_SHA/{constant}_REPO from {module}")
        ]
    pin, url = m_sha.group(1), m_repo.group(1)
    try:
        head = _remote_head(url, branch)
    except (subprocess.SubprocessError, OSError, IndexError):
        return [item(row, "unavailable", f"cannot reach {url}")]
    if head and head != pin:
        return [
            item(
                row,
                "stale",
                f"pinned {pin[:12]} but upstream {branch} HEAD {head[:12]} — {landed}",
                f"review upstream changes, then bump {constant}_SHA in {module} and the "
                "docs/external-dependencies.md verified date (deliberate config change — never "
                "auto-advanced)",
            )
        ]
    return [item(row, "fresh", f"pin matches upstream {branch} HEAD ({pin[:12]})")]


def check_yara_rules_pin() -> list[dict]:
    return _rules_pin(
        "yara-rules-pin",
        "traust_core.v1.providers.tools.yara",
        "RL_RULES",
        "develop",
        "new malware-family rules may have landed that scans won't match",
    )


def check_argus_rules_pin() -> list[dict]:
    # An opt-in crypto/PQC supplement, uncalibrated against the ledger: watched, never promoted.
    return _rules_pin(
        "argus-rules-pin",
        "traust_core.v1.providers.tools.opengrep",
        "ARGUS_RULES",
        "main",
        "new crypto/PQC rules may have landed that the opt-in supplement won't match",
    )


def check_framework_upstream(compliance: Path) -> list[dict]:
    row = "framework-spine:upstream"
    prov_p = compliance / "provenance.json"
    if not prov_p.is_file():
        return [item(row, "pending", "no compliance provenance yet")]
    try:
        prov = json.loads(prov_p.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return [item(row, "unavailable", "provenance.json unparseable")]
    pinned, url = prov.get("upstream_head"), prov.get("upstream")
    if not pinned or not url:
        return [item(row, "unavailable", "provenance lacks upstream/upstream_head")]
    try:
        head = _remote_head(url, "HEAD")
    except (subprocess.SubprocessError, OSError, IndexError):
        return [item(row, "unavailable", f"cannot reach {url}")]
    if not head.startswith(pinned):
        return [
            item(
                row,
                "stale",
                f"derived at {pinned[:12]} but oscal-content HEAD is {head[:12]} — check "
                "whether the SP800-53 rev5 files changed before re-deriving",
                "review upstream diff; if the rev5 files moved, re-derive "
                "per packs/security/compliance/README.md and update provenance",
            )
        ]
    return [item(row, "fresh", f"upstream HEAD matches the derivation pin ({head[:12]})")]


def _file(path: Path) -> Any:
    """The document at `path`; MISSING when absent, None when unreadable."""
    if not path.is_file():
        return MISSING
    try:
        text = path.read_text(encoding="utf-8")
        return json.loads(text) if path.suffix == ".json" else yaml.safe_load(text)
    except (OSError, json.JSONDecodeError, yaml.YAMLError):
        return None


def check_policy_provenance(compliance: Path, services: Services) -> list[dict]:
    """Review dates of the policy data: the recorded SLA policy (else the pack's default) and
    org parameters, and the pack's compliance spine and catalogs."""
    sla = _recorded(services, SlaPolicyArtifact) or _file(SLA_POLICY)
    targets: list[tuple[str, Any, Callable[[Any], Any]]] = [
        ("sla-policy", sla, lambda d: (d.get("source") or {}).get("retrieved")),
        ("compliance-spine", _file(compliance / "provenance.json"), lambda d: d.get("retrieved")),
        (
            "org-parameters",
            _recorded(services, OrgParametersArtifact) or MISSING,
            lambda d: d.get("declared_on"),
        ),
        # ids-only framework catalogs: no machine feed, so the review window IS the staleness
        *(
            (name, _file(compliance / file), lambda d: d.get("reviewed"))
            for name, file in (
                ("catalog-pci-dss", "catalog-pci-dss-v4.yaml"),
                ("catalog-soc2-tsc", "catalog-soc2-tsc.yaml"),
                ("catalog-gdpr", "catalog-gdpr-technical.yaml"),
            )
        ),
    ]
    out = []
    for name, doc, getter in targets:
        if doc is MISSING:
            out.append(item(f"provenance:{name}", "pending", "not recorded or absent"))
            continue
        dated = _parse_iso(getter(doc) or "") if isinstance(doc, dict) else None
        if dated is None:
            out.append(item(f"provenance:{name}", "unavailable", "no retrieval/declaration date"))
            continue
        days = (_now() - dated).total_seconds() / 86400
        status = "fresh" if days <= PROVENANCE_REVIEW_DAYS else "review_due"
        out.append(
            item(
                f"provenance:{name}",
                status,
                f"dated {dated.date().isoformat()} ({days:.0f}d ago; review "
                f"window {PROVENANCE_REVIEW_DAYS}d)",
                "re-verify values at the source and update the date"
                if status == "review_due"
                else None,
            )
        )
    return out


def _docs_live_versions(product: str) -> list[str] | None:
    """A product's documentation versions on its live docs.redhat.com landing page (stock curl:
    the CDN refuses other client shapes); None when it can't be read, never a guess."""
    url = f"https://docs.redhat.com/en/documentation/{product}"
    try:
        proc = subprocess.run(
            ["curl", "-sSL", "--fail", "--max-time", "30", url],
            capture_output=True,
            text=True,
            timeout=45,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    pattern = (
        rf'documentation/{re.escape(product)}/([0-9][0-9a-z.-]*|[0-9]-latest|latest|current)["/]'
    )
    return sorted(set(re.findall(pattern, proc.stdout))) or None


def _version_key(v: str) -> tuple[int, ...] | None:
    try:
        return tuple(int(x) for x in v.split("."))
    except ValueError:
        return None


def check_docs_product_map(inputs: Path) -> list[dict]:
    """The doc-variance lane's declared doc versions vs each product's live landing page: a
    version newer than the declared window, or a declared one gone, is drift."""
    p = inputs / "adhoc" / "docs-product-map.yaml"
    if not p.is_file():
        return [
            item(
                "docs-product-map",
                "pending",
                "map absent (doc-variance lane part 1)",
                "plans/doc-variance-plan.md",
            )
        ]
    try:
        doc = yaml.safe_load(p.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as e:
        return [item("docs-product-map", "drift", f"map unreadable: {e}")]
    out = []
    fetched = str(doc.get("fetched_at") or "")
    try:
        age = (_now().date() - datetime.date.fromisoformat(fetched[:10])).days
        if age > DOCS_MAP_STALE_DAYS:
            out.append(
                item(
                    "docs-product-map",
                    "stale",
                    f"version enumeration {age}d old (threshold {DOCS_MAP_STALE_DAYS}d)",
                    "re-enumerate versions from the live landing pages",
                )
            )
    except ValueError:
        out.append(item("docs-product-map", "drift", f"unparseable fetched_at: {fetched!r}"))
    for slug, entry in sorted((doc.get("products") or {}).items()):
        row = f"docs-versions:{slug}"
        declared = [str(v) for v in entry.get("versions") or []]
        live = _docs_live_versions(slug)
        if live is None:
            out.append(
                item(row, "unavailable", "live enumeration failed (network) — NOT treated as fresh")
            )
            continue
        top = max((k for k in map(_version_key, declared) if k), default=None)
        # Only FUTURE versions: older ones are historical docs, out of the lane's scope.
        newer = [v for v in live if top and (k := _version_key(v)) and k > top]
        gone = [v for v in declared if v not in live]
        if newer:
            out.append(
                item(
                    row,
                    "drift",
                    f"NEW doc version(s) beyond the declared window: {', '.join(newer)} — "
                    "variance tracking is not covering them",
                    "update docs-product-map.yaml versions (+ version_to_refs rule if the "
                    "branch convention differs)",
                )
            )
        if gone:
            out.append(
                item(
                    row,
                    "drift",
                    f"declared version(s) no longer on the landing page: {', '.join(gone)} "
                    "(retired docs?)",
                    "review the map row; mark records for those versions disposition=stale",
                )
            )
        if not newer and not gone:
            out.append(item(row, "fresh", f"{len(declared)} version(s) match live"))
    return out


def compliance_data_dir() -> Path:
    """The security pack's vendored framework data (NIST spine, baselines, catalogs)."""
    return SECURITY_PACK_DIR / "compliance"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    add_config_home_arg(ap)
    ap.add_argument("--worklist", type=Path, help="worklist override (the builder's --out)")
    args = ap.parse_args(argv)
    compliance = compliance_data_dir()
    core = load(args.config_home)
    inputs = inputs_dir(core)
    worklist = args.worklist or (
        analysis_results_dir(core) / "findings" / "_manifest" / "rescan-worklist.json"
    )
    services = core.services()
    items = [
        *check_framework_upstream(compliance),
        *check_policy_provenance(compliance, services),
        *check_adr_registry(services),
        *check_yara_rules_pin(),
        *check_argus_rules_pin(),
        *check_docs_product_map(inputs),
        *check_rescan_worklist(worklist),
    ]
    print(json.dumps({"items": items}, indent=2))
    return 0
