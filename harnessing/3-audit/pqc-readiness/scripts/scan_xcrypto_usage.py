#!/usr/bin/env python3
"""golang.org/x/crypto usage scanner (deterministic; never authors verdicts).

Closes the three gaps the pqc-scan facts leave around x/crypto (found while
filling the OCP "x/crypto usage tracking" workbook): the rules only fire
*inside vendored copies of x/crypto itself*, so first-party import sites,
go.mod dependency versions, and callgraph reachability were all unrecorded.

Emits a sidecar artifact `<slug>-xcrypto-usage.json` next to the pqc facts
(separate file on purpose — `<slug>-pqc-facts.json` is produced and stamped by
Core's native prescan and must remain the unchanged published artifact):

  A. import_sites[] — first-party (and test/docs, tagged) `import` lines
     referencing golang.org/x/crypto/<pkg>, with file:line and path_class.
  B. gomod[]        — every non-vendor go.mod's golang.org/x/crypto require
     + replace entries (version evidence the facts never captured).
  C. callgraph[]    — OPTIONAL (--callgraph): per-main-package reachable
     x/crypto functions with a `somepath` witness chain, via
     golang.org/x/tools/cmd/callgraph + digraph — the method the tracker
     workbook's How-To prescribes. Requires a Go toolchain and the two
     tools on PATH; failures are recorded per entrypoint, never hidden.

Usage:
    python3 scan_xcrypto_usage.py --repo-dir /tmp/<repo> --repo-url <URL> \
        --out <slug>-xcrypto-usage.json [--callgraph] [--timeout 300]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

XCRYPTO = "golang.org/x/crypto"
IMPORT_RX = re.compile(r'"golang\.org/x/crypto(?:/([a-zA-Z0-9_/]+))?"')
REQUIRE_RX = re.compile(r"^\s*(?:require\s+)?golang\.org/x/crypto\s+(v[\w.\-+]+)", re.M)
REPLACE_RX = re.compile(
    r"^\s*(?:replace\s+)?golang\.org/x/crypto\s*=>\s*(\S+)\s*(v[\w.\-+]+)?", re.M
)
SKIP_DIRS = {"vendor", ".git", ".gomodcache", "node_modules"}
TEST_DOC_HINTS = ("_test.go",)
TEST_DOC_DIRS = ("test", "tests", "testdata", "docs", "examples", "example")


def path_class(rel: Path) -> str:
    """Mirror the pqc-scan path taxonomy: vendor trees are skipped before we
    get here, so the split is first_party vs test_docs."""
    if rel.name.endswith(TEST_DOC_HINTS):
        return "test_docs"
    if any(part.lower() in TEST_DOC_DIRS for part in rel.parts[:-1]):
        return "test_docs"
    return "first_party"


def walk_go_files(repo: Path):
    for p in sorted(repo.rglob("*.go")):
        rel = p.relative_to(repo)
        if any(part in SKIP_DIRS for part in rel.parts):
            continue
        yield p, rel


def scan_imports(repo: Path) -> list[dict]:
    sites = []
    for p, rel in walk_go_files(repo):
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for i, line in enumerate(text.splitlines(), 1):
            m = IMPORT_RX.search(line)
            if not m:
                continue
            pkg = m.group(1) or ""
            sites.append(
                {
                    "file": str(rel),
                    "line": i,
                    "package": f"{XCRYPTO}/{pkg}".rstrip("/"),
                    "path_class": path_class(rel),
                }
            )
    return sites


def scan_gomod(repo: Path) -> list[dict]:
    mods = []
    for p in sorted(repo.rglob("go.mod")):
        rel = p.relative_to(repo)
        if any(part in SKIP_DIRS for part in rel.parts):
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        req = REQUIRE_RX.findall(text)
        rep = REPLACE_RX.findall(text)
        if req or rep:
            mods.append(
                {
                    "gomod": str(rel),
                    "require": sorted(set(req)),
                    "replace": [{"target": t, "version": v or None} for t, v in rep],
                }
            )
    return mods


def _run(cmd: list[str], cwd: Path, timeout: int) -> tuple[int, str, str]:
    try:
        r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return -1, "", f"timeout after {timeout}s"
    except OSError as e:
        return -1, "", str(e)


def discover_entrypoints(repo: Path, timeout: int) -> tuple[list[str], str | None]:
    """Main packages via `go list` (authoritative); returns (pkg_dirs, error)."""
    rc, out, err = _run(["go", "list", "-f", "{{.Name}} {{.Dir}}", "./..."], repo, timeout)
    if rc != 0:
        return [], f"go list failed: {err.strip()[:300]}"
    mains = []
    for line in out.splitlines():
        parts = line.split(None, 1)
        if len(parts) == 2 and parts[0] == "main":
            d = Path(parts[1])
            try:
                mains.append(str(d.relative_to(repo)) or ".")
            except ValueError:
                mains.append(parts[1])
    return sorted(mains), None


def callgraph_entry(repo: Path, entry: str, timeout: int) -> dict:
    """Reachable x/crypto functions from one main package + somepath witness."""
    rc, digraph_out, err = _run(["callgraph", "-format=digraph", f"./{entry}"], repo, timeout)
    if rc != 0:
        return {
            "entrypoint": entry,
            "error": (err or "callgraph failed").strip()[:300],
            "reachable": [],
        }
    targets = sorted(
        {
            tok
            for line in digraph_out.splitlines()
            for tok in line.split()
            if tok.startswith(XCRYPTO + "/")
        }
    )
    reachable = []
    digraph = shutil.which("digraph")
    root = None
    for line in digraph_out.splitlines():
        head = line.split(None, 1)[0] if line.split() else ""
        if head.endswith(".main") and "/x/" not in head:
            root = head
            break
    for fn in targets:
        item = {"function": fn, "somepath": None}
        if digraph and root:
            rc2, sp, _ = _run(["digraph", "somepath", root, fn], repo, min(timeout, 120))
            if rc2 == 0 and sp.strip():
                item["somepath"] = sp.split()
        reachable.append(item)
    return {"entrypoint": entry, "error": None, "reachable": reachable}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--repo-dir", type=Path, required=True)
    ap.add_argument("--repo-url", default=None)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument(
        "--callgraph",
        action="store_true",
        help="also compute reachable x/crypto functions per main "
        "package (needs go + callgraph + digraph; compiles "
        "the module — network for deps unless vendored)",
    )
    ap.add_argument(
        "--timeout", type=int, default=300, help="per-entrypoint callgraph timeout, seconds"
    )
    args = ap.parse_args()
    repo = args.repo_dir.resolve()
    if not repo.is_dir():
        print(f"[!] not a directory: {repo}", file=sys.stderr)
        return 2

    rc, head, _ = _run(["git", "rev-parse", "HEAD"], repo, 30)
    commit = head.strip() if rc == 0 else None

    import_sites = scan_imports(repo)
    gomod = scan_gomod(repo)
    callgraph = []
    callgraph_status = "skipped: --callgraph not requested"
    if args.callgraph:
        missing = [t for t in ("go", "callgraph") if not shutil.which(t)]
        if missing:
            callgraph_status = f"skipped: missing tools {missing}"
        else:
            entries, err = discover_entrypoints(repo, args.timeout)
            if err:
                callgraph_status = err
            else:
                callgraph = [callgraph_entry(repo, e, args.timeout) for e in entries]
                callgraph_status = f"ran: {len(entries)} main package(s)"

    doc = {
        "artifact": "xcrypto-usage",
        "repository": args.repo_url,
        "commit": commit,
        "stamps": {
            "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        },
        "summary": {
            "import_sites": len(import_sites),
            "first_party_import_sites": sum(
                1 for s in import_sites if s["path_class"] == "first_party"
            ),
            "packages": sorted({s["package"] for s in import_sites}),
            "gomod_refs": len(gomod),
            "callgraph": callgraph_status,
            "reachable_functions": sum(len(e["reachable"]) for e in callgraph),
        },
        "import_sites": import_sites,
        "gomod": gomod,
        "callgraph": callgraph,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    print(
        f"[+] wrote {args.out}: {len(import_sites)} import site(s), "
        f"{len(gomod)} go.mod ref(s), callgraph: {callgraph_status}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
