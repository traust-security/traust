#!/usr/bin/env python3
"""x/crypto tracker exporter — regenerates the OCP "x/crypto usage tracking"
workbook tab from the PQC facts corpus (deterministic; routes evidence,
never authors the final Status — the emitted status is a *suggestion*).

Sources, best evidence first per repo x package:
  1. `<slug>-xcrypto-usage.json` callgraph[] — reachable functions with a
     somepath witness (the workbook How-To's own method)
  2. `<slug>-xcrypto-usage.json` import_sites[] — first-party import lines
  3. `<slug>-pqc-facts.json` — x/crypto presence in vendored trees (the
     pre-existing rule hits inside vendored library code)

Outputs (under <results-root sibling> progress-tracker/metrics/dashboards/pqc/):
  xcrypto-tracker.csv  — tracker-shaped rows (Product/Org, Repository,
                         Entrypoint, Crypto module used, Status, Comment,
                         Dependency Graph) + evidence_tier + slug columns
  xcrypto-tracker.md   — coverage summary + per-tier counts

Optional: --push-sheet <spreadsheet-id> [--tab <title>] upserts the rows
into a Google Sheets tab using a `gcloud auth print-access-token` bearer
token (requires a Drive-scoped gcloud login; see the PQC campaign notes).

Kept until `<slug>-xcrypto-usage.json` (scan_xcrypto_usage.py) has a contracts schema traust-core
can record (NEED(Michele: xcrypto-usage artifact or code-facts section)).

Usage:
    python3 build_xcrypto_tracker.py --results-root <analysis-results> \
        [--out-dir DIR] [--push-sheet ID] [--tab TITLE]
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import subprocess
import sys
from pathlib import Path

from traust.context import (
    add_config_home_arg,
    load,
    progress_tracker_dir,
    resolve_results_root,
)

XC = "golang.org/x/crypto"
XC_RX = re.compile(r"(?:golang\.org/)?x/crypto/([a-zA-Z0-9_]+)")

# Suggested status per package: "Unacceptable?" = contains classically
# broken / upstream-deprecated primitives (openpgp is deprecated upstream;
# pkcs12 carries RC2/SHA-1 legacy; ssh ships classical KEX incl. the
# dh-group1-sha1 the fleet sweep flagged). "Acceptable?" = sound classical
# crypto that is IR 8547-acceptable *now* but on the 2035 clock where
# public-key. Teams own the final call — hence the trailing '?'.
STATUS = {
    "openpgp": "Unacceptable?",
    "pkcs12": "Unacceptable?",
    "otr": "Unacceptable?",
    "cast5": "Unacceptable?",
    "blowfish": "Unacceptable?",
    "twofish": "Unacceptable?",
    "tea": "Unacceptable?",
    "xtea": "Unacceptable?",
    "md4": "Unacceptable?",
    "ripemd160": "Unacceptable?",
    "ssh": "Unacceptable?",
    "curve25519": "Acceptable?",
    "ed25519": "Acceptable?",
    "nacl": "Acceptable?",
    "chacha20": "Acceptable?",
    "chacha20poly1305": "Acceptable?",
    "salsa20": "Acceptable?",
    "poly1305": "Acceptable?",
    "hkdf": "Acceptable?",
    "pbkdf2": "Acceptable?",
    "scrypt": "Acceptable?",
    "argon2": "Acceptable?",
    "bcrypt": "Acceptable?",
    "acme": "Acceptable?",
    "ocsp": "Acceptable?",
    "cryptobyte": "Acceptable?",
    "sha3": "Acceptable?",
    "blake2b": "Acceptable?",
    "blake2s": "Acceptable?",
    "x509roots": "Acceptable?",
}
CLOCK_NOTE = {
    "Unacceptable?": "contains classically-broken/upstream-deprecated primitives",
    "Acceptable?": "sound classical crypto; IR 8547 2035 clock where public-key",
    "Unknown": "no per-package suggestion table entry — needs team review",
}


def pkg_base(pkg: str) -> str:
    return pkg.removeprefix(XC + "/").split("/")[0] or "(root)"


def status_for(pkg: str) -> str:
    return STATUS.get(pkg_base(pkg), "Unknown")


def org_of(url: str | None, slug: str) -> str:
    if url and "github.com/" in url:
        return url.split("github.com/")[-1].split("/")[0]
    return slug.split("--")[0] if "--" in slug else ""


def collect(results_root: Path) -> list[dict]:
    rows = []
    pqc = results_root / "pqc"
    for repo_dir in sorted(p for p in pqc.iterdir() if p.is_dir() and not p.name.startswith("_")):
        slug = repo_dir.name
        usage_p = repo_dir / f"{slug}-xcrypto-usage.json"
        facts_p = repo_dir / f"{slug}-pqc-facts.json"
        url = None
        per_pkg: dict[str, dict] = {}

        if usage_p.is_file():
            try:
                u = json.loads(usage_p.read_text())
            except (OSError, json.JSONDecodeError):
                u = {}
            url = u.get("repository") or url
            for entry in u.get("callgraph", []):
                for r in entry.get("reachable", []):
                    fn = r["function"]
                    pkg = XC + "/" + fn.removeprefix(XC + "/").split(".")[0]
                    e = per_pkg.setdefault(pkg, {})
                    if e.get("tier") not in ("callgraph",):
                        e.clear()
                    e.setdefault("tier", "callgraph")
                    e.setdefault("functions", []).append(fn)
                    e.setdefault("entrypoint", entry["entrypoint"])
                    if r.get("somepath") and not e.get("somepath"):
                        e["somepath"] = r["somepath"]
            for s in u.get("import_sites", []):
                pkg = s["package"]
                e = per_pkg.setdefault(pkg, {})
                if "tier" not in e:
                    e["tier"] = (
                        "first-party-import"
                        if s["path_class"] == "first_party"
                        else "test-docs-import"
                    )
                    e["evidence"] = f"{s['file']}:{s['line']}"
                elif e["tier"] == "test-docs-import" and s["path_class"] == "first_party":
                    e["tier"] = "first-party-import"
                    e["evidence"] = f"{s['file']}:{s['line']}"
            for g in u.get("gomod", []):
                if g.get("require"):
                    per_pkg.setdefault("__version__", {})[g["gomod"]] = ",".join(g["require"])

        if not per_pkg and facts_p.is_file():
            try:
                f = json.loads(facts_p.read_text())
            except (OSError, json.JSONDecodeError):
                f = {}
            url = url or f.get("repository")
            for fact in f.get("facts", []):
                blob = (fact.get("file", "") or "") + " " + (fact.get("detail", "") or "")
                for m in XC_RX.finditer(blob):
                    pkg = XC + "/" + m.group(1)
                    e = per_pkg.setdefault(pkg, {})
                    if "tier" not in e:
                        e["tier"] = "dependency-presence"
                        e["evidence"] = f"{fact.get('file')}:{fact.get('line')}"

        versions = per_pkg.pop("__version__", {})
        vnote = (
            ("; go.mod: " + "; ".join(f"{k} {v}" for k, v in sorted(versions.items())))
            if versions
            else ""
        )
        for pkg in sorted(p for p in per_pkg):
            e = per_pkg[pkg]
            status = status_for(pkg)
            tier = e.get("tier", "dependency-presence")
            if tier == "callgraph":
                module = "; ".join(sorted(set(e.get("functions", [])))[:5])
                entrypoint = e.get("entrypoint", "")
                depgraph = " -> ".join(e.get("somepath") or []) or "no path"
                evidence = "callgraph-reachable"
            else:
                module, entrypoint = pkg, "n/a — static scan"
                depgraph = "not computed (no callgraph)"
                evidence = e.get("evidence", "")
            rows.append(
                {
                    "product_org": org_of(url, slug),
                    "repository": url or slug,
                    "entrypoint": entrypoint,
                    "crypto_module_used": module,
                    "status_suggested": status,
                    "comment": f"{tier}: {evidence} — {CLOCK_NOTE[status]}{vnote}",
                    "dependency_graph": depgraph,
                    "evidence_tier": tier,
                    "slug": slug,
                }
            )
    return rows


HEADERS = [
    "product_org",
    "repository",
    "entrypoint",
    "crypto_module_used",
    "status_suggested",
    "comment",
    "dependency_graph",
    "evidence_tier",
    "slug",
]


def push_sheet(rows: list[dict], spreadsheet_id: str, tab: str) -> None:
    import urllib.parse
    import urllib.request

    token = subprocess.run(
        ["gcloud", "auth", "print-access-token"], capture_output=True, text=True
    ).stdout.strip()
    if not token:
        raise SystemExit(
            "[!] no gcloud access token — run `gcloud auth login --enable-gdrive-access`"
        )

    def api(method, url, body=None):
        req = urllib.request.Request(
            url,
            data=json.dumps(body).encode() if body is not None else None,
            method=method,
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        )
        return json.load(urllib.request.urlopen(req))

    base = f"https://sheets.googleapis.com/v4/spreadsheets/{spreadsheet_id}"
    meta = api("GET", base + "?fields=sheets.properties.title")
    titles = {s["properties"]["title"] for s in meta.get("sheets", [])}
    if tab not in titles:
        api(
            "POST",
            base + ":batchUpdate",
            {"requests": [{"addSheet": {"properties": {"title": tab}}}]},
        )
    rng = urllib.parse.quote(f"'{tab}'")
    api("POST", f"{base}/values/{rng}:clear", {})
    values = [[h.replace("_", " ").title() for h in HEADERS[:7]]] + [
        [r[h] for h in HEADERS[:7]] for r in rows
    ]
    api(
        "PUT",
        f"{base}/values/{urllib.parse.quote(tab)}!A1?valueInputOption=RAW",
        {"values": values},
    )
    print(f"[+] pushed {len(rows)} row(s) to '{tab}' in {spreadsheet_id}", file=sys.stderr)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    add_config_home_arg(ap)
    ap.add_argument(
        "--results-root", type=Path, default=None, help="analysis-results dir (containing pqc/)"
    )
    ap.add_argument(
        "--out-dir",
        type=Path,
        default=None,
        help="default: progress-tracker/metrics/dashboards/pqc",
    )
    ap.add_argument("--push-sheet", default=None, metavar="SPREADSHEET_ID")
    ap.add_argument("--tab", default="Hybrid Platforms Sec (PQC static sweep)")
    args = ap.parse_args()
    results = resolve_results_root(args)
    core = load(args.config_home)
    out_dir = (
        args.out_dir.resolve()
        if args.out_dir
        else progress_tracker_dir(core) / "metrics" / "dashboards" / "pqc"
    )
    rows = collect(results)
    out_dir.mkdir(parents=True, exist_ok=True)
    csv_p = out_dir / "xcrypto-tracker.csv"
    with csv_p.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=HEADERS)
        w.writeheader()
        w.writerows(rows)
    tiers = {}
    for r in rows:
        tiers[r["evidence_tier"]] = tiers.get(r["evidence_tier"], 0) + 1
    md = [
        "# x/crypto usage tracker export",
        "",
        f"{len(rows)} repo×package rows across "
        f"{len({r['slug'] for r in rows})} repos. Evidence tiers: "
        + " · ".join(f"{k}: {v}" for k, v in sorted(tiers.items())),
        "",
        "Status column is a **suggestion** (IR 8547-derived per-package "
        "table); teams own the final call. Rows with tier "
        "`dependency-presence` come from rule hits inside vendored x/crypto "
        "code — run `scan_xcrypto_usage.py` (optionally `--callgraph`) per "
        "repo to upgrade them to import-site or reachability evidence.",
        "",
        f"CSV: `{csv_p.name}` · push: `--push-sheet <id> --tab <title>`",
        "",
    ]
    (out_dir / "xcrypto-tracker.md").write_text("\n".join(md), encoding="utf-8")
    print(f"[+] wrote {csv_p} ({len(rows)} rows) + xcrypto-tracker.md", file=sys.stderr)
    if args.push_sheet:
        push_sheet(rows, args.push_sheet, args.tab)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
