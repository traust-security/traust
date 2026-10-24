#!/usr/bin/env python3
"""pqc_facts.py — Layer-1 adapter for the PQC readiness campaign.

Runs the pinned pqc-scan binary with the merged rules dir (vendored defaults
+ HP supplement), then post-processes report.json into a deterministic
`*-pqc-facts.json`:

  * vendor / first-party path tagging
  * NIST IR 8547 mapping (quantum class -> SP 800-131A status -> 2030/2035
    clock) via notes/reference/ir8547-mapping.json
  * adapter-native provider/toolchain/policy/material facts the rule engine
    cannot express (go.mod toolchain, Dockerfile FROM, rpms.lock.yaml NEVRA,
    crypto-policies, GODEBUG kill-switches, long cert validity)
  * provenance pre-classification hints per fact
  * zero-hit sanity block (scan coverage stats so a rules-loading failure
    cannot masquerade as a clean repo)
  * reproducibility stamps (scanner commit, rules sha256, binary sha256)

Facts never contain verdicts. Same repo SHA -> byte-identical facts.

Kept until traust-engine registers core's PqcScanner (NEED(engine: pqc-scan provider)), when
`PqcService.prescan` replaces it; record its output with `traust pqc record --facts`.

Usage:
  pqc_facts.py --repo-dir DIR --repo-url URL --out FACTS.json \
      [--scanner BIN] [--rules-dir DIR] [--cbom-out CBOM.json]
  pqc_facts.py --from-sbom SBOM.json --repo-url URL --out FACTS.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any

import yaml  # PyYAML — already in harness deps
from traust_contracts.paths import schema_path

from traust.context import add_config_home_arg, load_engine

SCRIPT_DIR = Path(__file__).resolve().parent
SKILL_DIR = SCRIPT_DIR.parent
HERE = SKILL_DIR
ADAPTER_VERSION = "1.4.0"  # 1.4.0: HP_TLS_LISTENER_* census rules; HP_GOV_* facts first-party only
PQC_SCAN_COMMIT = "be5c760adb7d1d4d99e39d35d87d2956079db76e"
from traust_engine.adapters.crypto_probe import *  # noqa: F403, E402

VENDOR_RX = re.compile(
    r"(^|/)(vendor|node_modules|third_party|_vendor|3rdparty|third-party|"
    r"bundled|external|site-packages|\.gomodcache)(/|$)"
)
TESTDOC_RX = re.compile(
    r"(^|/)(tests?|testdata|testing|testfiles\w*|test_files|__tests__|"
    r"__fixtures__|__data__|spec|t|e2e|docs?|examples?|samples?|fixtures|"
    r"mocks?)(/|$)|_test\.(go|py|rb|js|ts)$|\.md$|\.rst$|\.adoc$"
    r"|(^|/)(\.coderabbit\.ya?ml|semgrep\.ya?ml|\.sourcery\.ya?ml)$"
)
CLOCK112_RX = re.compile(r"\b(2048|224)\b|3des|des3|tripledes", re.I)
VALIDITY_ADDDATE_RX = re.compile(r"AddDate\(\s*(\d+)\s*,")
VALIDITY_DAYS_RX = re.compile(r"-days\s+(\d{4,})")


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


class PathClass(StrEnum):
    VENDOR = "vendor"
    TEST_DOCS = "test_docs"
    FIRST_PARTY = "first_party"


@dataclass
class IR8547Mapping:
    qclass: str
    usage: str = "unknown"
    clock: dict[str, str] | None = None
    matched_prefix: str = ""
    qclass_resolved: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "qclass": self.qclass_resolved or self.qclass,
            "usage": self.usage,
            "clock": self.clock,
            "matched_prefix": self.matched_prefix,
        }
        if self.qclass_resolved:
            d["qclass_resolved"] = self.qclass_resolved
        return d


@dataclass
class Fact:
    rule_id: str
    file: str
    line: int | None = None
    detail: str = ""
    match: str = ""
    finding_id: str | None = None
    severity: str | None = None
    risk: str | None = None
    confidence: str | None = None
    provider: str | None = None
    pqc_capable: bool | None = None
    fips_mode: bool | None = None
    capability_hint: str | None = None
    # Assigned during post-processing
    ir8547: IR8547Mapping | None = None
    provenance_hint: str = ""
    path_class: PathClass = PathClass.FIRST_PARTY
    fact_id: str = ""

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "fact_id": self.fact_id,
            "rule_id": self.rule_id,
            "file": self.file,
            "line": self.line,
            "detail": self.detail,
        }
        if self.match:
            d["match"] = self.match
        if self.finding_id:
            d["finding_id"] = self.finding_id
        if self.severity:
            d["severity"] = self.severity
        if self.risk:
            d["risk"] = self.risk
        if self.confidence:
            d["confidence"] = self.confidence
        if self.provider:
            d["provider"] = self.provider
        if self.pqc_capable is not None:
            d["pqc_capable"] = self.pqc_capable
        if self.fips_mode:
            d["fips_mode"] = self.fips_mode
        if self.capability_hint:
            d["capability_hint"] = self.capability_hint
        if self.ir8547:
            d["ir8547"] = self.ir8547.to_dict()
        d["provenance_hint"] = self.provenance_hint
        d["path_class"] = self.path_class.value
        return d


@dataclass
class Coverage:
    assessment_basis: str
    scanned_files: int | None = None
    skipped_files: int | None = None
    rules_in_pack: int | None = None
    sbom: str | None = None
    components_seen: int | None = None
    no_crypto_detected_assertion: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"assessment_basis": self.assessment_basis}
        if self.assessment_basis == "sbom-only":
            d["sbom"] = self.sbom
            d["components_seen"] = self.components_seen
        else:
            d["scanned_files"] = self.scanned_files
            d["skipped_files"] = self.skipped_files
            d["rules_in_pack"] = self.rules_in_pack
            if self.no_crypto_detected_assertion:
                d["no_crypto_detected_assertion"] = self.no_crypto_detected_assertion
        return d


@dataclass
class FactsDocument:
    artifact: str = "pqc-facts"
    repository: str | None = None
    stamps: dict[str, str] = field(default_factory=dict)
    coverage: Coverage = field(default_factory=lambda: Coverage("source"))
    summary: dict[str, dict[str, int]] = field(default_factory=dict)
    facts: list[Fact] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "artifact": self.artifact,
            "repository": self.repository,
            "stamps": self.stamps,
            "coverage": self.coverage.to_dict(),
            "summary": self.summary,
            "facts": [f.to_dict() for f in self.facts],
        }


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def rules_pack_sha(rules_dir: Path) -> str:
    h = hashlib.sha256()
    for f in sorted(rules_dir.glob("*.yml")):
        h.update(f.name.encode())
        h.update(f.read_bytes())
    return h.hexdigest()


def load_tables() -> dict:
    return json.loads((HERE / "notes" / "reference" / "ir8547-mapping.json").read_text())


def load_version_matrix() -> dict:
    """Load the single-source-of-truth version matrix."""
    return yaml.safe_load((HERE / "notes" / "reference" / "pqc-version-matrix.yaml").read_text())


# ---------------------------------------------------------------------------
# IR 8547 mapping
# ---------------------------------------------------------------------------


def map_rule(rule_id: str, tables: dict, detail: str = "") -> IR8547Mapping:
    rm = tables["rule_map"]
    best = ""
    for prefix in rm:
        if prefix.startswith("_"):
            continue
        if rule_id.startswith(prefix) and len(prefix) > len(best):
            best = prefix
    if not best:
        return IR8547Mapping(qclass="unmapped")

    entry = rm[best]
    qclass = entry["qclass"]
    resolved = None

    if qclass == "shor_112bit_or_higher":
        resolved = "shor_112bit" if CLOCK112_RX.search(detail or "") else "shor_128bit_plus"

    return IR8547Mapping(
        qclass=qclass,
        usage=entry.get("usage", "unknown"),
        clock=tables["clocks"].get(resolved or qclass),
        matched_prefix=best,
        qclass_resolved=resolved,
    )


# ---------------------------------------------------------------------------
# Scanner execution
# ---------------------------------------------------------------------------


def run_scanner(scanner: Path, repo: Path, rules_dir: Path, outdir: Path) -> dict:
    cmd = [
        str(scanner),
        "scan",
        str(repo),
        "--rules-dir",
        str(rules_dir),
        "--format",
        "all",
        "--out-dir",
        str(outdir),
    ]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
    report = outdir / "report.json"
    if not report.exists():
        raise SystemExit(
            f"pqc-scan produced no report.json (rc={r.returncode}): {(r.stderr or r.stdout)[-400:]}"
        )
    return json.loads(report.read_text())


# ---------------------------------------------------------------------------
# PQC version capability check
# ---------------------------------------------------------------------------


def _parse_version_tuple(s: str) -> tuple[int, ...] | None:
    m = re.search(r"(\d+)\.(\d+)(?:\.(\d+))?", s)
    if not m:
        m = re.search(r"(\d+)", s)
        if not m:
            return None
    return tuple(int(g) for g in m.groups() if g is not None)


def _pqc_capable_version(
    provider: str, version: str | None, matrix: dict | None = None
) -> bool | None:
    """Determine PQC capability from provider + version.

    Reads thresholds from pqc-version-matrix.yaml (single source of truth).
    This is a PURE VERSION CHECK — it does not consider FIPS mode.  FIPS
    interaction is handled separately: the adapter emits a `fips_mode` flag
    on facts when FIPS is detected, and the Layer 2 agent applies the
    decision tree's fips_interaction rules to determine the effective posture.
    """
    if not version:
        return None
    actual = _parse_version_tuple(version)
    if not actual:
        return None

    if matrix is None:
        matrix = load_version_matrix()

    provider_key = provider
    if provider in ("openssl-libs", "openssl-fips-provider"):
        provider_key = "openssl"

    rt = (matrix.get("runtimes") or {}).get(provider_key)
    if not rt:
        return None

    kex = rt.get("pqc_kex_default")
    if not kex or not kex.get("version"):
        return None

    threshold = _parse_version_tuple(str(kex["version"]))
    if not threshold:
        return None

    max_len = max(len(actual), len(threshold))
    padded_actual = actual + (0,) * (max_len - len(actual))
    padded_threshold = threshold + (0,) * (max_len - len(threshold))
    return padded_actual >= padded_threshold


# ---------------------------------------------------------------------------
# Probe-to-rule mapping
# ---------------------------------------------------------------------------

_PROBE_TO_RULE: dict[str, str] = {
    "CRYPTO_GO_TOOLCHAIN": "HP_CHAIN_GO_TOOLCHAIN",
    "CRYPTO_BASE_IMAGE": "HP_CHAIN_BASE_IMAGE",
    "CRYPTO_OPENSSL_INSTALL": "HP_CHAIN_OPENSSL_INSTALL",
    "CRYPTO_NODE_VERSION": "HP_CHAIN_NODE_VERSION",
    "CRYPTO_JDK_VERSION": "HP_CHAIN_JDK_VERSION",
    "CRYPTO_RPM_NEVRA": "HP_CHAIN_RPM_NEVRA",
    "CRYPTO_GODEBUG_TLS_KILLSWITCH": "HP_ENV_GODEBUG_KILLSWITCH",
    "CRYPTO_POLICY_SET": "HP_POLICY_CRYPTO_POLICIES",
    "CRYPTO_SBOM_COMPONENT": "HP_SBOM_CRYPTO_COMPONENT",
    "CRYPTO_RUST_VERSION": "HP_CHAIN_RUST_VERSION",
    "CRYPTO_RUST_TLS_BACKEND": "HP_CHAIN_RUST_TLS_BACKEND",
    "CRYPTO_C_TLS_LIBRARY": "HP_CHAIN_C_TLS_LIBRARY",
    "CRYPTO_PYTHON_VERSION": "HP_CHAIN_PYTHON_VERSION",
    "CRYPTO_PYTHON_CRYPTO_DEP": "HP_CHAIN_PYTHON_CRYPTO_DEP",
    "CRYPTO_DOTNET_SDK": "HP_CHAIN_DOTNET_SDK",
    "CRYPTO_DOTNET_TFM": "HP_CHAIN_DOTNET_TFM",
    "CRYPTO_DOTNET_CRYPTO_PKG": "HP_CHAIN_DOTNET_CRYPTO_PKG",
    "CRYPTO_RUBY_VERSION": "HP_CHAIN_RUBY_VERSION",
    "CRYPTO_RUBY_CRYPTO_GEM": "HP_CHAIN_RUBY_CRYPTO_GEM",
    "CRYPTO_JVM_SECURITY_PROPERTY": "HP_POLICY_JVM_SECURITY",
    "CRYPTO_GO_FIPS_BACKEND": "HP_CHAIN_GO_FIPS_BACKEND",
    "CRYPTO_DOCKERFILE_DIRECTIVE": "HP_CHAIN_DOCKERFILE_DIRECTIVE",
    "CRYPTO_FIPS140_GODEBUG": "HP_ENV_FIPS140_MODE",
}


# ---------------------------------------------------------------------------
# Fact construction
# ---------------------------------------------------------------------------


def _classify_path(path: str) -> PathClass:
    if VENDOR_RX.search(path):
        return PathClass.VENDOR
    if TESTDOC_RX.search(path):
        return PathClass.TEST_DOCS
    return PathClass.FIRST_PARTY


def _provenance_hint(rule_id: str, path: str) -> str:
    if VENDOR_RX.search(path or ""):
        return "vendored"
    if rule_id.startswith("HP_GOV_PLATFORM_"):
        return "inherited-platform"
    if rule_id.startswith(("HP_GROUPS_", "HP_POLICY_", "HP_ENV_")):
        return "inherited-constrained"
    if rule_id.startswith(("DEP_", "HP_FW_", "JWT_LIB")):
        return "delegated-dependency"
    if rule_id.startswith("HP_CHAIN_"):
        return "provider-census"
    if rule_id.startswith("HP_PQC_"):
        return "adoption-signal"
    return "native-candidate"


def _parse_scanner_findings(report: dict) -> list[Fact]:
    """Convert raw scanner report findings into typed Facts."""
    facts: list[Fact] = []
    for finding in report.get("findings", []):
        loc = finding.get("location") or {}
        ev = finding.get("evidence") or {}
        match = ev.get("match") or finding.get("source_snippet") or ""
        facts.append(
            Fact(
                rule_id=finding.get("rule_id", ""),
                finding_id=finding.get("finding_id"),
                file=loc.get("file", ""),
                line=loc.get("line"),
                severity=finding.get("severity"),
                risk=finding.get("risk"),
                confidence=finding.get("confidence"),
                detail=(finding.get("description") or "")[:200],
                match=str(match)[:120],
            )
        )
    return facts


def _adapter_native_facts(repo: Path, tables: dict) -> list[Fact]:
    """Provider / policy / kill-switch / material facts via crypto_probe."""
    cap = tables["provider_capability"]
    general_facts = crypto_probe.probe_repo(repo)  # noqa: F405
    facts: list[Fact] = []

    fips_mode = any(
        gf.probe_id == "CRYPTO_FIPS140_GODEBUG"
        or (gf.probe_id == "CRYPTO_POLICY_SET" and "FIPS" in (gf.detail or "").upper())
        or (gf.probe_id == "CRYPTO_GO_FIPS_BACKEND")
        for gf in general_facts
    )

    for gf in general_facts:
        rule_id = _PROBE_TO_RULE.get(gf.probe_id)
        if not rule_id:
            continue

        fact = Fact(
            rule_id=rule_id,
            file=gf.file,
            line=gf.line,
            detail=gf.detail[:200],
            provider=gf.provider or None,
            pqc_capable=_pqc_capable_version(gf.provider, gf.version),
            fips_mode=True if fips_mode else None,
        )

        if gf.probe_id == "CRYPTO_BASE_IMAGE":
            for key, note in cap["base_image_hint"].items():
                if key in gf.detail:
                    fact.capability_hint = note
                    break

        facts.append(fact)

    # PQC-specific material facts (long cert validity)
    text_exts = {".go", ".sh", ""}
    for sf in sorted(repo.rglob("*")):
        # never follow file symlinks out of the untrusted checkout —
        # matched fragments land in committed facts (audit B5, plan P1.7)
        if sf.is_symlink() or not sf.is_file() or sf.suffix not in text_exts:
            continue
        rel = sf.relative_to(repo)
        if VENDOR_RX.search(str(rel)) or sf.stat().st_size > 1_000_000:
            continue
        try:
            text = sf.read_text(errors="replace")
        except OSError:
            continue
        if sf.suffix == ".go":
            for m in VALIDITY_ADDDATE_RX.finditer(text):
                if int(m.group(1)) >= 5:
                    facts.append(
                        Fact(
                            rule_id="HP_MAT_LONG_VALIDITY",
                            file=str(rel),
                            line=text[: m.start()].count("\n") + 1,
                            detail=f"AddDate years={m.group(1)}",
                        )
                    )
        if sf.suffix in {".sh", ""}:
            for m in VALIDITY_DAYS_RX.finditer(text):
                if int(m.group(1)) >= 1825:
                    facts.append(
                        Fact(
                            rule_id="HP_MAT_LONG_VALIDITY",
                            file=str(rel),
                            line=text[: m.start()].count("\n") + 1,
                            detail=f"-days {m.group(1)}",
                        )
                    )
    return facts


def _sbom_facts(sbom_path: Path, tables: dict) -> list[Fact]:
    """--from-sbom mode: provider + delegated facts from a CycloneDX SBOM."""
    general_facts = crypto_probe.probe_sbom(sbom_path)  # noqa: F405
    return [
        Fact(
            rule_id="HP_SBOM_CRYPTO_COMPONENT",
            file=gf.file,
            line=gf.line,
            detail=gf.detail[:200],
            pqc_capable=_pqc_capable_version(gf.provider, gf.version),
        )
        for gf in general_facts
    ]


def _post_process(facts: list[Fact], tables: dict) -> None:
    """Enrich facts with IR8547 mapping, provenance, path classification."""
    for fact in facts:
        fact.ir8547 = map_rule(fact.rule_id, tables, f"{fact.match} {fact.detail}")
        fact.provenance_hint = _provenance_hint(fact.rule_id, fact.file)
        fact.path_class = _classify_path(fact.file)

    # Governance facts assert "this app consumes a platform crypto API".
    # A vendored type definition (e.g. openshift/api's TLSSecurityProfile)
    # is not consumption evidence — every repo vendoring the API would read
    # as platform-governed. Vendored copies stay visible in the CBOM.
    facts[:] = [
        f
        for f in facts
        if not (f.rule_id.startswith("HP_GOV_") and f.path_class is not PathClass.FIRST_PARTY)
    ]

    facts.sort(key=lambda f: (f.file, f.line or 0, f.rule_id))
    for i, fact in enumerate(facts):
        fact.fact_id = f"F{i:04d}"


def _build_summary(facts: list[Fact]) -> dict[str, dict[str, int]]:
    counts: dict[str, dict[str, int]] = {
        "by_rule": {},
        "by_qclass": {},
        "by_provenance_hint": {},
        "by_path_class": {},
    }
    for fact in facts:
        qclass = fact.ir8547.qclass_resolved or fact.ir8547.qclass if fact.ir8547 else "unmapped"
        for bucket, val in (
            ("by_rule", fact.rule_id),
            ("by_qclass", qclass),
            ("by_provenance_hint", fact.provenance_hint),
            ("by_path_class", fact.path_class.value),
        ):
            counts[bucket][val] = counts[bucket].get(val, 0) + 1
    return counts


# ---------------------------------------------------------------------------
# Main pipeline
# ---------------------------------------------------------------------------


def build_facts(args) -> FactsDocument:
    tables = load_tables()
    rules_dir = Path(args.rules_dir or (HERE / "rules"))
    stamps = {
        "adapter_version": ADAPTER_VERSION,
        "pqc_scan_commit": PQC_SCAN_COMMIT,
        "rules_sha256": rules_pack_sha(rules_dir),
    }

    if args.from_sbom:
        facts = _sbom_facts(Path(args.from_sbom), tables)
        coverage = Coverage(
            assessment_basis="sbom-only",
            sbom=str(args.from_sbom),
        )
    else:
        repo = Path(args.repo_dir).resolve()
        scanner = Path(args.scanner or (SCRIPT_DIR / "bin" / "pqc-scan"))
        stamps["binary_sha256"] = sha256_file(scanner)
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            report = run_scanner(scanner, repo, rules_dir, Path(td))
            if args.cbom_out:
                cb = Path(td) / "cbom.json"
                if cb.exists():
                    Path(args.cbom_out).write_text(cb.read_text())

        raw_summary = report.get("summary") or {}
        facts = _parse_scanner_findings(report)
        facts.extend(_adapter_native_facts(repo, tables))

        n_rules = sum(
            len(re.findall(r"(?m)^- id:", p.read_text())) for p in sorted(rules_dir.glob("*.yml"))
        )
        coverage = Coverage(
            assessment_basis="source",
            scanned_files=raw_summary.get("scanned_files"),
            skipped_files=raw_summary.get("skipped_files"),
            rules_in_pack=n_rules,
        )
        if not facts:
            coverage.no_crypto_detected_assertion = (
                f"0 facts with {n_rules} rules over "
                f"{raw_summary.get('scanned_files')} files scanned "
                f"({raw_summary.get('skipped_files')} skipped)"
            )

    _post_process(facts, tables)

    return FactsDocument(
        repository=args.repo_url,
        stamps=stamps,
        coverage=coverage,
        summary=_build_summary(facts),
        facts=facts,
    )


# ---------------------------------------------------------------------------
# Facts schema gate
# ---------------------------------------------------------------------------

FACTS_SCHEMA = schema_path("pqc-facts")


def validate_facts(doc: dict, source: str = "<in-memory>") -> int:
    """Gate a facts document against contracts/schemas/pqc-facts.schema.json.

    Returns the number of schema violations (0 == valid), printing each.
    """
    try:
        import jsonschema
    except ImportError:
        print(
            "pqc_facts: jsonschema not installed — cannot gate facts "
            "output (pip install jsonschema)",
            file=sys.stderr,
        )
        return 1
    schema = json.loads(FACTS_SCHEMA.read_text())
    validator = jsonschema.Draft202012Validator(schema)
    errs = sorted(validator.iter_errors(doc), key=lambda e: list(e.path))
    for e in errs:
        loc = ".".join(str(p) for p in e.path) or "<root>"
        print(f"{source}: {loc}: {e.message}", file=sys.stderr)
    return len(errs)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main():
    ap = argparse.ArgumentParser()
    add_config_home_arg(ap)
    ap.add_argument("--repo-dir")
    ap.add_argument("--repo-url", default=None)
    ap.add_argument("--out")
    ap.add_argument("--scanner")
    ap.add_argument("--rules-dir")
    ap.add_argument("--cbom-out")
    ap.add_argument("--from-sbom")
    ap.add_argument("--validate-facts")
    args = ap.parse_args()
    load_engine(args.config_home)

    if args.validate_facts:
        p = Path(args.validate_facts)
        raise SystemExit(min(validate_facts(json.loads(p.read_text()), str(p)), 1))
    if not args.out or not (args.repo_dir or args.from_sbom):
        ap.error("need --out and one of --repo-dir/--from-sbom")

    doc = build_facts(args)
    serialized = doc.to_dict()
    if validate_facts(serialized, args.out):
        raise SystemExit(
            f"pqc_facts: refusing to write {args.out}: output violates pqc-facts.schema.json"
        )
    Path(args.out).write_text(json.dumps(serialized, indent=1, sort_keys=False))
    print(f"wrote {args.out}: {len(doc.facts)} facts ({doc.coverage.assessment_basis})")


if __name__ == "__main__":
    main()
