#!/usr/bin/env python3
"""
Build a portfolio repository graph from the inputs inventory CSVs
cross-referenced against analysis-results/findings/ coverage.

Node types: segment, release, product, product-version, category, owner-team,
            repo, repo-ref, findings
Edge rels : contains, ships, categorised-as, owned-by, has-findings, documents,
            has_ref, ships_ref

Ref layer (branch-awareness Phase 2): where an inventory CSV row
declares a Source Branch, an optional first-class ref node is created —
id `ref:<host>/<org>/<name>@<branch>`, kind `repo-ref` — linked by `has_ref`
(repo → ref) plus a `ships_ref` edge parallel to the branch-carrying `ships`
edge. Deliberately a DISTINCT rel (not `ships`): every existing consumer
filters rel=='ships' and would either skip or double-count ref targets;
`ships_ref` keeps all pre-existing nodes/edges/attrs byte-identical.

Outputs:
  repo-graph.json   nodes+edges, full fidelity
  repo-graph.dot    GraphViz source
  repo-graph.gexf   Gephi
  repo-graph.html   interactive vis-network (product-version/category
                    collapsed into tooltips to stay usable at ~10k nodes)
  repo-graph-stats.md  summary + top-hub table
"""

from __future__ import annotations

import argparse
import csv
import datetime
import html
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

from traust_engine.corpus import report_store
from traust_engine.corpus import resolver as corpus_resolver
from traust_engine.escaping import esc_html, json_script, md_cell

from traust.context import (
    add_config_home_arg,
    analysis_results_dir,
    inputs_dir,
    load_engine,
)
from traust.inventory import load_descriptor


# ─────────────────────────── CLI ──────────────────────────────
def parse_args(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    add_config_home_arg(p)
    p.add_argument("--inputs", type=Path, default=None, help="path to the inputs inventory repo")
    p.add_argument("--findings", type=Path, default=None, help="path to analysis-results/findings/")
    p.add_argument(
        "--out",
        type=Path,
        default=None,
        help="output directory (default: <analysis-results>/graph)",
    )
    p.add_argument(
        "--exclude",
        action="append",
        default=["ansible"],
        help="input segment(s) to skip (repeatable)",
    )
    p.add_argument("--date", default=datetime.date.today().isoformat())
    return p.parse_args(argv)


DESC = None  # InventoryDescriptor, set in _execute_graph_build()


def main(argv=None) -> int:
    global ARGS, ENGINE, INPUTS, FINDINGS, OUT
    ARGS = parse_args(argv)
    ENGINE = load_engine(ARGS.config_home)
    ar = analysis_results_dir(ENGINE)
    INPUTS = (ARGS.inputs or inputs_dir(ENGINE)).resolve()
    FINDINGS = (ARGS.findings or (ar / "findings")).resolve()
    OUT = (ARGS.out or (ar / "graph")).resolve()
    OUT.mkdir(parents=True, exist_ok=True)
    if not INPUTS.is_dir():
        sys.exit(f"inputs not found: {INPUTS}")
    if not FINDINGS.is_dir():
        sys.exit(f"findings not found: {FINDINGS}")
    _execute_graph_build()
    return 0


ARGS = None
ENGINE = None
INPUTS = None
FINDINGS = None
OUT = None

# ─────────────────────────── model ────────────────────────────
NODES: dict[str, dict] = {}
EDGES: set[tuple[str, str, str]] = set()
EDGE_ATTRS: dict[tuple[str, str, str], dict] = {}


def nid(kind: str, key: str) -> str:
    return f"{kind}:{key}"


def add_node(kind: str, key: str, label: str | None = None, **attrs) -> str:
    i = nid(kind, key)
    if i not in NODES:
        NODES[i] = {"id": i, "type": kind, "label": label or key, "attrs": dict(attrs)}
    else:
        NODES[i]["attrs"].update({k: v for k, v in attrs.items() if v})
    return i


def add_edge(a: str, b: str, rel: str, **attrs):
    e = (a, b, rel)
    EDGES.add(e)
    if attrs:
        EDGE_ATTRS.setdefault(e, {}).update(attrs)


# Ref layer rels (branch-awareness Phase 2). Excluded from the degree/hub
# computation so pre-existing stats stay stable.
REF_RELS = {"has_ref", "ships_ref"}


def add_ref(repo_id: str, branch: str | None) -> str | None:
    """One `repo-ref` node per unique (repo, branch) declared by an
    inventory CSV row, plus a `has_ref` edge (repo → ref). Returns the
    ref node id, or None when the row carries no branch. Additive only:
    repo-node identity and all pre-existing edges/attrs are untouched."""
    b = (branch or "").strip()
    if not b:
        return None
    c = repo_id.removeprefix("repo:")  # <host>/<org>/<name>
    i = f"ref:{c}@{b}"
    if i not in NODES:
        org_name = "/".join(c.split("/")[1:])  # <org>/<name>
        NODES[i] = {"id": i, "type": "repo-ref", "label": f"{org_name}@{b}", "attrs": {"branch": b}}
    add_edge(repo_id, i, "has_ref")
    return i


# ─────────────────────── repo canonicalisation ────────────────
def canon_repo(url: str) -> str | None:
    """Canonical repo identity: <host>/<project-path>.

    GitHub projects are always exactly org/name, so deeper URL segments
    (/tree/…, /blob/…) are dropped. Every other host keeps the FULL
    path: GitLab subgroup projects (group/subgroup/repo) are distinct
    repos, and truncating them to two segments collapsed all 60+
    an engagement's builds/* repos into one node and produced the
    phantom aap-cpaas/source row in the week-2 audit batch (2026-07-29).
    """
    if not url or not url.strip():
        return None
    u = url.strip().rstrip("/").removesuffix(".git")
    m = re.match(r"https?://([^/]+)/([^?#]+)", u)
    if not m:
        m = re.match(r"git@([^:]+):(.+)", u)
    if not m:
        return None
    host, path = m.group(1), m.group(2).strip("/").removesuffix(".git")
    segs = [s for s in path.split("/") if s]
    if len(segs) < 2:
        return None
    if host.lower() == "github.com":
        segs = segs[:2]
    return f"{host}/" + "/".join(segs)


# ─────────────────── corpus resolver (discovery) ──────────────────
# Report discovery is delegated to traust_engine.corpus.resolver — the one
# definition of the report population. Depth-tolerant: shallow findings/<repo>/ dirs
# (no product parent) count, as do branch re-audit dirs at any depth.
# Symlink aliases are excluded by the resolver. Hard-fail on load errors:
# discovery correctness is the point, so there is no ad-hoc fallback walk.
CORPUS = corpus_resolver


def _execute_graph_build() -> None:
    global NODES, EDGES, EDGE_ATTRS
    NODES.clear()
    EDGES.clear()
    EDGE_ATTRS.clear()
    CORPUS_CFG = ENGINE.corpus.config()

    # ─────────────────────── findings index ───────────────────────
    print(f"indexing findings/ ({FINDINGS}) …", file=sys.stderr)
    FIND_BY_URL: dict[str, list[str]] = defaultdict(list)
    FIND_META: dict[str, dict] = {}
    SEV_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0, None: -1}

    # repo-graph is deliberately HP-scoped: only the findings tree is resolved.
    _TREE = FINDINGS.name
    _ar = analysis_results_dir(ENGINE)
    if FINDINGS.parent.resolve() == _ar.resolve():
        _RES = ENGINE.corpus.load_resolution(trees=[_TREE])
    else:
        _RES = report_store.load_resolution(FINDINGS.parent, CORPUS_CFG, trees=[_TREE])
    _STORE = report_store.ReportStore(report_store.LocalBackend(FINDINGS.parent))
    if _TREE not in _RES.trees:
        sys.exit(
            f"FATAL: {FINDINGS} is not a registered corpus tree "
            "(config: corpus-config.yaml in $TRAUST_CONFIG_HOME) — register it via "
            "/corpus-intake; repo-graph only walks registered trees"
        )

    for rec in _RES.records:
        if rec.is_md_only:
            continue  # same population as before: JSON-backed reports only
        # The node key used to be audit_json.parent relative to FINDINGS. It is the
        # record's own identity, so take it from there: verified equal on every
        # record, and it no longer needs the artifact to sit in a directory we can walk.
        rel = f"{rec.product}/{rec.repo_dir}" if rec.product else rec.repo_dir
        meta = {
            "audit": True,
            "triage": False,
            "tm": False,
            "sev": None,
            "tp": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "url": None,
            "dispositions": False,
            "resolved": 0,
            "open": 0,
            "fp": 0,
            "hardening": 0,
            "undetermined": 0,
        }
        # Prefer the track-findings cumulative report when present — same schema,
        # plus current per-finding dispositions.
        cj = Path(rec.findings_current) if rec.findings_current else None
        # is_symlink() is filesystem-only and has no object-storage analogue; kept
        # because dropping it would change which report a node counts from, which is a
        # behaviour change, not a refactor. Residual coupling, tracked in the plan.
        src = cj if (cj is not None and not cj.is_symlink()) else Path(rec.audit_json)
        try:
            j = _STORE.get_json(report_store.to_ref(str(src), FINDINGS.parent))
            url = (j.get("metadata") or {}).get("repository")
            meta["url"] = url
            if url and (c := canon_repo(url)):
                FIND_BY_URL[c].append(rel)
            if j.get("disposition_summary"):
                meta["dispositions"] = True
                # Count from findings directly so confirmed false positives are
                # excluded from open/resolved (same semantics as the executive
                # summary dashboard).
                for fnd in j.get("findings") or []:
                    if fnd.get("validation_status") == "false_positive":
                        meta["fp"] += 1
                        continue
                    if fnd.get("validation_status") == "hardening":
                        # posture debt — not an open confirmed vulnerability
                        meta["hardening"] += 1
                        continue
                    res = (fnd.get("disposition") or {}).get("resolution")
                    if res in ("resolved", "risk_accepted"):
                        meta["resolved"] += 1
                    else:
                        meta["open"] += 1
        except Exception:
            pass
        if rec.triage_json:
            meta["triage"] = True
            try:
                t = _STORE.get_json(report_store.to_ref(rec.triage_json, FINDINGS.parent))
                s = t.get("summary") or {}
                meta["tp"] = s.get("true_positives") or 0
                # triage.schema.json (harness >= 0.25.0) counts hardening and
                # undetermined separately — never fold them into tp or fp.
                meta["hardening"] = max(meta["hardening"], int(s.get("hardening") or 0))
                meta["undetermined"] = int(s.get("undetermined") or 0)
                # by_severity keys are lowercase in triage.schema.json;
                # June-era artifacts used uppercase — accept both.
                bs = {str(k).lower(): v for k, v in (s.get("by_severity") or {}).items()}
                meta["high"], meta["medium"], meta["low"] = (
                    bs.get("high") or 0,
                    bs.get("medium") or 0,
                    bs.get("low") or 0,
                )
                for k in ("critical", "high", "medium", "low"):
                    if bs.get(k):
                        meta["sev"] = k.upper()
                        break
            except Exception:
                pass
        if rec.threat_model:
            meta["tm"] = True
        FIND_META[rel] = meta

    _SHALLOW_DIRS = sum(1 for r in FIND_META if "/" not in r)
    print(
        f"  {len(FIND_META)} findings dirs ({_SHALLOW_DIRS} shallow), "
        f"{len(FIND_BY_URL)} unique repo URLs",
        file=sys.stderr,
    )

    # Cloud-config declared-layer coverage (analysis-results/cloud-config/,
    # /cloud-config-audit): a coverage FLAG keyed by metadata.repository.
    # Findings counts stay a separate unit — never folded into sev/tp.
    CLOUD_COV: dict[str, int] = {}
    _CLOUD_ROOT = FINDINGS.parent / "cloud-config"
    if _CLOUD_ROOT.is_dir():
        for _cj in sorted(_CLOUD_ROOT.rglob("*-cloud-config-audit.json")):
            if _cj.is_symlink():
                continue
            try:
                _rep = json.loads(_cj.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            _url = (_rep.get("metadata") or {}).get("repository")
            _c = canon_repo(_url) if _url else None
            if _c:
                CLOUD_COV[_c] = CLOUD_COV.get(_c, 0) + sum(
                    1 for f in _rep.get("findings") or [] if f.get("status") != "suppressed"
                )
    if CLOUD_COV:
        print(
            f"  cloud-config declared-layer coverage: {len(CLOUD_COV)} repo URL(s)", file=sys.stderr
        )

    # ─────────────────────── CSV ingestion ────────────────────────
    def read_csv(p: Path):
        with p.open(newline="", encoding="utf-8") as f:
            yield from csv.DictReader(f)

    def repo_from_row(row: dict) -> tuple[str | None, str, str]:
        url = row.get("GitHub URL") or row.get("URL") or ""
        c = canon_repo(url)
        org = row.get("Organization") or row.get("Organization/Group") or ""
        name = row.get("Repo Name") or ""
        if c and (not org or not name):
            parts = c.split("/")
            # host is parts[0]; the (possibly subgrouped) namespace is
            # everything between host and repo name
            org, name = "/".join(parts[1:-1]), parts[-1]
        return c, org, name

    def add_repo(row: dict) -> str | None:
        c, org, name = repo_from_row(row)
        if not c:
            return None
        host = c.split("/")[0]
        return add_node(
            "repo", c, label=f"{org}/{name}", url=f"https://{c}", org=org, name=name, host=host
        )

    def ingest_owners(oc: Path):
        if not oc.exists():
            return
        for row in read_csv(oc):
            c, _, _ = repo_from_row(row)
            team = (row.get("Owner Team") or "").strip()
            if c and team:
                tn = add_node("owner-team", team, manager=row.get("Manager"))
                add_edge(tn, nid("repo", c), "owned-by")

    def ingest_release_payload(sname: str) -> None:
        """Kind `release-payload`: one <sname>-<ver>-payload-repos.csv per release,
        optional <sname>/<sub>/*-repos.csv product sub-trees, owners.csv at both."""
        label = DESC.label(sname)
        seg = add_node("segment", sname, label=label)
        root = INPUTS / sname
        rx = re.compile(re.escape(sname) + r"-([\d.]+)-payload-repos\.csv$")
        for pcsv in sorted(root.glob(f"{sname}-*-payload-repos.csv")):
            m = rx.search(pcsv.name)
            if not m:
                continue
            ver = m.group(1)
            rel = add_node(
                "release",
                f"{sname}-{ver}",
                label=DESC.segment(sname).release_label(ver),
                segment=sname,
                version=ver,
            )
            add_edge(seg, rel, "contains")
            for row in read_csv(pcsv):
                r = add_repo(row)
                if not r:
                    continue
                cat = (row.get("Category") or "").strip()
                br = row.get("Source Branch")
                if cat:
                    cn = add_node("category", f"{sname}/{cat}", label=cat, segment=sname)
                    add_edge(rel, cn, "contains")
                    add_edge(cn, r, "ships", release=ver, branch=br)
                    if rn := add_ref(r, br):
                        add_edge(cn, rn, "ships_ref", release=ver, branch=br)
                else:
                    add_edge(rel, r, "ships", branch=br)
                    if rn := add_ref(r, br):
                        add_edge(rel, rn, "ships_ref", branch=br)
        for subdir in sorted(p for p in root.iterdir() if p.is_dir()):
            sub = subdir.name
            for pcsv in sorted(subdir.glob("*-repos.csv")):
                if pcsv.name.startswith("owners"):
                    continue
                pn = add_node(
                    "product", f"{sname}-{sub}", label=f"{label} {sub.title()}", segment=sname
                )
                add_edge(seg, pn, "contains")
                for row in read_csv(pcsv):
                    r = add_repo(row)
                    if r:
                        add_edge(pn, r, "ships")
            ingest_owners(subdir / "owners.csv")
        ingest_owners(root / "owners.csv")

    def ingest_catalog(sname: str) -> None:
        """Kind `catalog`: <sname>/<product>/<ver>/*-payload-repos.csv per product
        version, <sname>/<product>/*-repos.csv unversioned, owners.csv per product."""
        seg = add_node("segment", sname, label=DESC.label(sname))
        for opdir in sorted(p for p in (INPUTS / sname).iterdir() if p.is_dir()):
            op = opdir.name
            pn = add_node("product", f"operator:{op}", label=op, segment=sname)
            add_edge(seg, pn, "contains")
            for pcsv in sorted(opdir.glob("*/*-payload-repos.csv")):
                ver = pcsv.parent.name
                vn = add_node(
                    "product-version",
                    f"operator:{op}@{ver}",
                    label=f"{op} {ver}",
                    segment=sname,
                    product=op,
                    version=ver,
                )
                add_edge(pn, vn, "contains")
                for row in read_csv(pcsv):
                    r = add_repo(row)
                    if not r:
                        continue
                    cat = (row.get("Category") or "").strip()
                    br = row.get("Source Branch") or row.get("Branch")
                    if cat:
                        cn = add_node(
                            "category", f"operator:{op}/{cat}", label=cat, segment=sname, product=op
                        )
                        add_edge(vn, cn, "contains")
                        add_edge(cn, r, "ships", version=ver, branch=br)
                        if rn := add_ref(r, br):
                            add_edge(cn, rn, "ships_ref", version=ver, branch=br)
                    else:
                        add_edge(vn, r, "ships", branch=br)
                        if rn := add_ref(r, br):
                            add_edge(vn, rn, "ships_ref", branch=br)
            for pcsv in opdir.glob("*-repos.csv"):
                if pcsv.name == "owners.csv":
                    continue
                for row in read_csv(pcsv):
                    r = add_repo(row)
                    if r:
                        add_edge(pn, r, "ships")
            ingest_owners(opdir / "owners.csv")

    def ingest_groups(sname: str, product_prefix: str) -> None:
        """Kinds `groups` and `services`: each immediate subdirectory groups repos
        (one dir per org/service/engagement) holding *-repos.csv + owners.csv, per
        the add-inputs layout. Rows may carry App/Sub-Service and Resource Type."""
        seg = add_node("segment", sname, label=DESC.label(sname))
        for gdir in sorted(p for p in (INPUTS / sname).iterdir() if p.is_dir()):
            grp = gdir.name
            pn = add_node("product", f"{product_prefix}{grp}", label=grp, segment=sname)
            add_edge(seg, pn, "contains")
            for pcsv in sorted(gdir.glob("*-repos.csv")):
                if pcsv.name.startswith("owners"):
                    continue
                for row in read_csv(pcsv):
                    r = add_repo(row)
                    if r:
                        add_edge(
                            pn,
                            r,
                            "ships",
                            sub_service=(row.get("App/Sub-Service") or "").strip() or None,
                            resource_type=row.get("Resource Type"),
                        )
            ingest_owners(gdir / "owners.csv")

    # segments
    SEGMENTS = [
        d.name
        for d in INPUTS.iterdir()
        if d.is_dir() and not d.name.startswith(".") and d.name not in ARGS.exclude
    ]
    print(f"segments: {SEGMENTS}  (excluded: {ARGS.exclude})", file=sys.stderr)

    # ── segments by kind (inventory descriptor: <inputs>/inventory.yaml) ──
    # Which layout a segment uses is declared, never inferred from its name;
    # an undeclared segment is `groups`, the layout add-inputs writes.
    global DESC
    DESC = load_descriptor(INPUTS)
    print(f"descriptor: {DESC.path or '(none — all segments are groups)'}", file=sys.stderr)
    for sname in SEGMENTS:
        kind = DESC.kind(sname)
        if kind == "release-payload":
            ingest_release_payload(sname)
        elif kind == "catalog":
            ingest_catalog(sname)
        elif kind == "services":
            ingest_groups(sname, product_prefix="service:")
        else:
            ingest_groups(sname, product_prefix=f"{sname}:")

    # ── repo → findings ──
    print("linking repos → findings …", file=sys.stderr)
    repo_nodes = [n for n in NODES.values() if n["type"] == "repo"]
    linked, unlinked = 0, 0
    for n in repo_nodes:
        c = n["id"].removeprefix("repo:")
        dirs = list(FIND_BY_URL.get(c, []))
        # fallback: match by name only, but never claim a findings dir whose
        # audit-JSON URL points at a different repo.
        if not dirs:
            name = n["attrs"].get("name")
            org = n["attrs"].get("org") or ""
            if name:
                for rel, m in FIND_META.items():
                    if rel.split("/")[-1] != name:
                        continue
                    mu = canon_repo(m.get("url") or "")
                    if mu and mu != c:
                        continue
                    if (
                        not mu
                        and org
                        and org.lower() not in rel.lower()
                        and any(
                            canon_repo(mm.get("url") or "")
                            for mm in (FIND_META[r] for r in FIND_META if r.split("/")[-1] == name)
                            if mm.get("url")
                        )
                    ):
                        continue
                    dirs.append(rel)
            dirs = list(dict.fromkeys(dirs))
        if not dirs:
            if c in CLOUD_COV:
                linked += 1
                n["attrs"].update(findings="cloud-config", cloud_config_findings=CLOUD_COV[c])
            else:
                unlinked += 1
                n["attrs"]["findings"] = "none"
            continue
        linked += 1
        best_sev, tp_sum, cov = None, 0, set()
        for rel in dirs:
            m = FIND_META.get(rel, {})
            fn = add_node(
                "findings",
                rel,
                label=rel,
                audit=m.get("audit"),
                triage=m.get("triage"),
                tm=m.get("tm"),
                sev=m.get("sev"),
                tp=m.get("tp"),
                high=m.get("high"),
                medium=m.get("medium"),
                low=m.get("low"),
                path=f"findings/{rel}",
                dispositions=m.get("dispositions"),
                resolved_findings=m.get("resolved"),
                open_findings=m.get("open"),
                false_positives=m.get("fp"),
                hardening_findings=m.get("hardening"),
                undetermined_findings=m.get("undetermined"),
            )
            add_edge(n["id"], fn, "has-findings")
            tp_sum += m.get("tp") or 0
            if SEV_ORDER.get(m.get("sev"), -1) > SEV_ORDER.get(best_sev, -1):
                best_sev = m.get("sev")
            for k in ("audit", "triage", "tm"):
                if m.get(k):
                    cov.add(k)
        if c in CLOUD_COV:
            cov.add("cloud-config")
            n["attrs"]["cloud_config_findings"] = CLOUD_COV[c]
        n["attrs"].update(
            findings="+".join(sorted(cov)) or "none",
            max_sev=best_sev,
            tp_total=tp_sum,
            findings_dirs=len(dirs),
        )

    # drop edges whose endpoints never materialised
    EDGES = {e for e in EDGES if e[0] in NODES and e[1] in NODES}

    # ─────────────────────── stats ────────────────────────────────
    by_type = defaultdict(int)
    for n in NODES.values():
        by_type[n["type"]] += 1
    by_rel = defaultdict(int)
    # sorted(): EDGES is a set, so unsorted iteration gave by_rel a different KEY ORDER
    # every run and repo-graph.json/.html were not reproducible — two identical runs of
    # the same code produced different bytes, which quietly disqualified them as a drift
    # gate. .dot and .gexf were already stable because they sort at write time.
    for _, _, r in sorted(EDGES):
        by_rel[r] += 1
    degree = defaultdict(int)
    for a, b, r in EDGES:
        if r in REF_RELS:  # ref layer is additive — hub degrees stable
            continue
        degree[a] += 1
        degree[b] += 1
    hubs = sorted(
        (n for n in NODES.values() if n["type"] == "repo"), key=lambda n: -degree[n["id"]]
    )[:20]

    print(f"nodes: {len(NODES)}  edges: {len(EDGES)}", file=sys.stderr)
    print(f"  by type: {dict(by_type)}", file=sys.stderr)
    print(f"  repos linked→findings: {linked}/{len(repo_nodes)}", file=sys.stderr)

    # ─────────────────────── emit JSON ────────────────────────────
    # --- derived context/doc nodes (doc-variance lane P3, v0.227.3) --------
    # Standing product-context files and the docs-product map are committed
    # INPUTS; the graph derives linkage from them (graphs resolve, never
    # store): context:<product>/<file> nodes, doc-product:<slug> nodes with
    # enumerated versions, and documents edges to the mapped product nodes.
    # informed_by (model provenance -> context doc) lands with structured
    # provenance; absence of context nodes for a product is coverage signal.
    try:
        import yaml as _yaml

        _ctx_root = INPUTS / "adhoc"
        if _ctx_root.is_dir():
            for _cdir in sorted(_ctx_root.glob("*-context")):
                _prod_slug = _cdir.name[: -len("-context")]
                for _doc in sorted(_cdir.glob("*.md")):
                    add_node(
                        "context",
                        f"{_prod_slug}/{_doc.name}",
                        label=_doc.name,
                        product_hint=_prod_slug,
                        path=str(_doc.relative_to(INPUTS)),
                    )
        _map_p = _ctx_root / "docs-product-map.yaml"
        if _map_p.is_file():
            _map = _yaml.safe_load(_map_p.read_text(encoding="utf-8"))
            for _slug, _e in sorted((_map.get("products") or {}).items()):
                _dn = add_node(
                    "doc-product",
                    _slug,
                    versions=",".join(str(v) for v in _e.get("versions") or []),
                    confirmed=bool(_e.get("confirmed")),
                )
                for _gp in _e.get("graph_products") or []:
                    if _gp in NODES:
                        add_edge(_dn, _gp, "documents")
    except Exception as _e:
        print(f"context/doc layer skipped: {_e}")

    with (OUT / "repo-graph.json").open("w") as f:
        json.dump(
            {
                "generated": ARGS.date,
                "sources": {
                    "inputs": str(INPUTS),
                    "findings": str(FINDINGS),
                    "excluded": ARGS.exclude,
                },
                "stats": {
                    "nodes": len(NODES),
                    "edges": len(EDGES),
                    "by_type": dict(by_type),
                    "by_rel": dict(by_rel),
                    "repos_with_findings": linked,
                    "repos_without_findings": unlinked,
                },
                "nodes": list(NODES.values()),
                "edges": [
                    {"from": a, "to": b, "rel": r, **EDGE_ATTRS.get((a, b, r), {})}
                    for a, b, r in sorted(EDGES)
                ],
            },
            f,
            indent=2,
        )

    # ─────────────────────── emit DOT ─────────────────────────────
    TYPE_STYLE = {
        "segment": 'shape=box3d,style=filled,fillcolor="#2b6cb0",fontcolor=white',
        "release": 'shape=box,style=filled,fillcolor="#3182ce",fontcolor=white',
        "product": 'shape=box,style=filled,fillcolor="#63b3ed"',
        "product-version": 'shape=box,style="rounded,filled",fillcolor="#bee3f8"',
        "category": 'shape=folder,style=filled,fillcolor="#faf089"',
        "owner-team": 'shape=oval,style=filled,fillcolor="#c6f6d5"',
        "repo": "shape=component,style=filled",
        "repo-ref": 'shape=cds,style=filled,fillcolor="#d6bcfa"',
        "findings": "shape=note,style=filled",
    }
    SEV_COLOR = {
        "CRITICAL": "#e53e3e",
        "HIGH": "#ed8936",
        "MEDIUM": "#ecc94b",
        "LOW": "#48bb78",
        None: "#e2e8f0",
        "INFO": "#e2e8f0",
    }

    def dot_esc(s):
        return s.replace("\\", "\\\\").replace('"', '\\"')

    with (OUT / "repo-graph.dot").open("w") as f:
        f.write('digraph portfolio {\n  rankdir=LR;\n  node [fontname="Helvetica"];\n')
        f.write("  graph [overlap=false,splines=true];\n")
        for n in NODES.values():
            style = TYPE_STYLE.get(n["type"], "")
            fill = ""
            if n["type"] in ("repo", "findings"):
                key = "max_sev" if n["type"] == "repo" else "sev"
                fill = f',fillcolor="{SEV_COLOR.get(n["attrs"].get(key))}"'
            f.write(f'  "{dot_esc(n["id"])}" [label="{dot_esc(n["label"])}",{style}{fill}];\n')
        for a, b, r in sorted(EDGES):
            style = {
                "owned-by": "style=dashed,color=green4",
                "has-findings": "style=dotted,color=gray50",
            }.get(r, "")
            f.write(f'  "{dot_esc(a)}" -> "{dot_esc(b)}" [label="{r}",{style}];\n')
        f.write("}\n")

    # ─────────────────────── emit GEXF ────────────────────────────
    def x(s):
        return html.escape(str(s or ""), quote=True)

    ATTRS = [
        "type",
        "segment",
        "product",
        "version",
        "org",
        "name",
        "host",
        "url",
        "findings",
        "max_sev",
        "tp_total",
        "findings_dirs",
        "audit",
        "triage",
        "tm",
        "sev",
        "tp",
        "high",
        "medium",
        "low",
        "manager",
        "path",
        "branch",
    ]  # appended last: pre-existing GEXF attr ids stay stable
    with (OUT / "repo-graph.gexf").open("w") as f:
        f.write('<?xml version="1.0" encoding="UTF-8"?>\n')
        f.write('<gexf xmlns="http://www.gexf.net/1.3" version="1.3">\n')
        f.write(
            f'<meta lastmodifieddate="{ARGS.date}">'
            "<creator>traust/repo-graph</creator>"
            "<description>Hybrid Platforms portfolio repo graph</description></meta>\n"
        )
        f.write('<graph mode="static" defaultedgetype="directed">\n')
        f.write('<attributes class="node">\n')
        for i, a in enumerate(ATTRS):
            f.write(f'  <attribute id="{i}" title="{a}" type="string"/>\n')
        f.write('</attributes>\n<attributes class="edge">\n')
        f.write('  <attribute id="0" title="rel" type="string"/>\n')
        f.write("</attributes>\n<nodes>\n")
        for n in NODES.values():
            f.write(f'  <node id="{x(n["id"])}" label="{x(n["label"])}"><attvalues>')
            f.write(f'<attvalue for="0" value="{x(n["type"])}"/>')
            for i, a in enumerate(ATTRS[1:], start=1):
                v = n["attrs"].get(a)
                if v is not None and v != "":
                    f.write(f'<attvalue for="{i}" value="{x(v)}"/>')
            f.write("</attvalues></node>\n")
        f.write("</nodes>\n<edges>\n")
        for i, (a, b, r) in enumerate(sorted(EDGES)):
            f.write(
                f'  <edge id="{i}" source="{x(a)}" target="{x(b)}">'
                f'<attvalues><attvalue for="0" value="{x(r)}"/></attvalues></edge>\n'
            )
        f.write("</edges>\n</graph>\n</gexf>\n")

    # ─────────── standard population block (traust.cli.groups.corpus) ────────────────
    def _population_lines(counts):
        """Markdown lines of the standard population block, rendered with the
        corpus module already loaded for discovery."""
        roots = CORPUS.roots_description(
            CORPUS_CFG,
            [_TREE],
            extra=[
                "inventory CSVs: <inputs>/"
                "{openshift,operator-catalog,services} (ansible/ excluded)",
            ],
        )
        return CORPUS.population_block_lines(
            tool="repo-graph",
            roots=roots,
            unit="repos (inventory) × coverage flags "
            "(audit/triage/threat-model) and per-dir disposition counts",
            filters="symlink aliases excluded (corpus resolver); md-only "
            "reports skipped (audit JSON required); findings-current "
            "preferred; triage true-positives only for tp counts",
            denominator="inventory CSV rows (repo universe) — reports "
            "without an inventory row are invisible to this "
            "tool",
            counts=counts,
        )

    def _population_html(lines):
        """Render the population block lines as a final HTML footer panel."""
        if not lines:
            return ""
        lis = []
        for ln in lines:
            if not ln.startswith("- "):
                continue  # heading/blank handled by the <b> below
            t = html.escape(ln[2:], quote=True)
            t = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", t)
            t = re.sub(r"`([^`]+)`", r"<code>\1</code>", t)
            lis.append(f"<li>{t}</li>")
        return (
            "<div id='pop' style='padding:10px 14px;background:#1a202c;"
            "color:#a0aec0;font-size:12px;line-height:1.7'>"
            "<b style='color:#fff'>Population</b>"
            "<ul style='margin:4px 0 0;padding-left:18px'>" + "".join(lis) + "</ul></div>"
        )

    _POP_DISP_DIRS = sum(1 for m in FIND_META.values() if m.get("dispositions"))
    POP_LINES = _population_lines(
        {
            "Inventory repos": f"{len(repo_nodes):,}",
            "Repos with findings coverage": f"{linked:,} / {len(repo_nodes):,}",
            "Findings dirs with disposition ledgers": f"{_POP_DISP_DIRS:,} / {len(FIND_META):,}",
            "Discovery": "corpus resolver (traust.cli.groups.corpus) — depth-tolerant "
            "walk of the findings tree; shallow findings/<repo>/ dirs "
            f"with no product parent are included ({_SHALLOW_DIRS} "
            "currently)",
        }
    )

    # ─────────────────────── emit HTML ────────────────────────────
    HTML_TYPES = {"segment", "release", "product", "owner-team", "repo", "findings"}
    GROUPS = {"segment": 0, "release": 1, "product": 2, "owner-team": 3, "repo": 4, "findings": 5}

    repo_products: dict[str, set[str]] = defaultdict(set)
    repo_cats: dict[str, set[str]] = defaultdict(set)
    for a, b, r in EDGES:
        if r == "ships" and NODES[b]["type"] == "repo":
            src = NODES[a]
            if src["type"] == "category":
                repo_cats[b].add(src["label"])
            prod = src["attrs"].get("product") or src["label"]
            repo_products[b].add(prod if src["type"] != "release" else src["label"])

    html_edges: set[tuple[str, str, str]] = set()
    for a, b, r in EDGES:
        if NODES[a]["type"] in HTML_TYPES and NODES[b]["type"] in HTML_TYPES:
            html_edges.add((a, b, r))
    for a, b, r in EDGES:
        if r != "ships" or NODES[b]["type"] != "repo":
            continue
        src = NODES[a]
        if src["type"] == "product-version":
            html_edges.add((nid("product", "operator:" + src["attrs"]["product"]), b, "ships"))
        elif src["type"] == "category":
            if DESC.kind(src["attrs"].get("segment", "")) == "release-payload":
                for xa, xb, xr in EDGES:
                    if xr == "contains" and xb == a and NODES[xa]["type"] == "release":
                        html_edges.add((xa, b, "ships"))
            elif p := src["attrs"].get("product"):
                html_edges.add((nid("product", f"operator:{p}"), b, "ships"))

    vis_nodes, vis_edges = [], []
    for n in NODES.values():
        if n["type"] not in HTML_TYPES:
            continue
        tip = f"<b>{html.escape(n['label'])}</b><br><i>{n['type']}</i>"
        color = None
        if n["type"] == "repo":
            a = n["attrs"]
            color = SEV_COLOR.get(a.get("max_sev"))
            tip += (
                f"<br>coverage: {a.get('findings')}"
                f"<br>max sev: {a.get('max_sev') or '—'} · TP: {a.get('tp_total') or 0}"
                f"<br>findings dirs: {a.get('findings_dirs') or 0}"
                f"<br>categories: {', '.join(sorted(repo_cats.get(n['id'], set()))) or '—'}"
                f"<br>ships in {len(repo_products.get(n['id'], set()))} products/releases"
                f"<br><a href='{esc_html(a.get('url'))}'>{esc_html(a.get('url'))}</a>"
            )
        elif n["type"] == "findings":
            a = n["attrs"]
            color = SEV_COLOR.get(a.get("sev"))
            tip += (
                f"<br>path: findings/{n['label']}"
                f"<br>audit:{a.get('audit')} triage:{a.get('triage')} tm:{a.get('tm')}"
                f"<br>sev:{a.get('sev') or '—'} TP:{a.get('tp') or 0} "
                f"({a.get('high') or 0}H/{a.get('medium') or 0}M/{a.get('low') or 0}L)"
            )
        elif n["type"] == "owner-team":
            tip += f"<br>manager: {n['attrs'].get('manager') or '—'}"
        vn = {"id": n["id"], "label": n["label"], "group": GROUPS[n["type"]], "title": tip}
        if color:
            vn["color"] = color
        vis_nodes.append(vn)
    seen = set()
    for a, b, r in sorted(html_edges):  # sorted: see by_rel above
        if NODES.get(a, {}).get("type") not in HTML_TYPES:
            continue
        if NODES.get(b, {}).get("type") not in HTML_TYPES:
            continue
        if (a, b) in seen:
            continue
        seen.add((a, b))
        vis_edges.append(
            {"from": a, "to": b, "title": r, "dashes": r in ("owned-by", "has-findings")}
        )

    with (OUT / "repo-graph.html").open("w") as f:
        f.write(
            """<!DOCTYPE html><html><head><meta charset="utf-8">
    <title>Hybrid Platforms — Portfolio Repository Graph</title>
    <script src="https://unpkg.com/vis-network@9.1.9/standalone/umd/vis-network.min.js"></script>
    <style>
     body{margin:0;font-family:Helvetica,Arial,sans-serif}
     #hdr{padding:8px 14px;background:#1a202c;color:#fff;font-size:14px;
          display:flex;gap:18px;align-items:center;flex-wrap:wrap}
     #hdr b{font-size:16px}
     #net{width:100vw;height:calc(100vh - 46px);border-top:1px solid #2d3748}
     .lg{display:inline-flex;align-items:center;gap:4px}
     .sw{width:12px;height:12px;display:inline-block;border:1px solid #4a5568}
     select,input{background:#2d3748;color:#fff;border:1px solid #4a5568;padding:2px 6px}
    </style></head><body>
    <div id="hdr">
     <b>Hybrid Platforms Portfolio Graph</b>
     <span>generated """
            + esc_html(ARGS.date)
            + """ · excluded: """
            + esc_html(", ".join(ARGS.exclude))
            + """</span>
     <span class="lg"><span class="sw" style="background:#2b6cb0"></span>segment</span>
     <span class="lg"><span class="sw" style="background:#3182ce"></span>release</span>
     <span class="lg"><span class="sw" style="background:#63b3ed"></span>product</span>
     <span class="lg"><span class="sw" style="background:#c6f6d5"></span>owner-team</span>
     <span class="lg"><span class="sw" style="background:#e53e3e"></span>repo·CRIT</span>
     <span class="lg"><span class="sw" style="background:#ed8936"></span>HIGH</span>
     <span class="lg"><span class="sw" style="background:#ecc94b"></span>MED</span>
     <span class="lg"><span class="sw" style="background:#48bb78"></span>LOW</span>
     <span class="lg"><span class="sw" style="background:#e2e8f0"></span>none</span>
     <label>filter <input id="q" size="20" placeholder="repo/product…"></label>
     <label>focus <select id="seg"><option value="">all</option>
       <option>openshift</option><option>operator-catalog</option>
       <option>services</option></select></label>
     <span id="stats"></span>
    </div><div id="net"></div><script>
    const NODES = """
        )
        # json_script: a </script> inside any label/url string would
        # terminate the element and hand the rest of the page to the input
        f.write(json_script(vis_nodes))
        f.write(";\nconst EDGES = ")
        f.write(json_script(vis_edges))
        f.write(""";
    document.getElementById('stats').textContent =
      NODES.length+' nodes · '+EDGES.length+' edges (version/category collapsed)';
    const nodeDS = new vis.DataSet(NODES);
    const edgeDS = new vis.DataSet(EDGES);
    const net = new vis.Network(document.getElementById('net'),
      {nodes:nodeDS, edges:edgeDS},
      {physics:{enabled:true,stabilization:{iterations:200},
                barnesHut:{gravitationalConstant:-30000,springLength:200}},
       interaction:{hover:true,tooltipDelay:120,hideEdgesOnDrag:true},
       groups:{0:{shape:'box',color:'#2b6cb0',font:{color:'#fff',size:22}},
               1:{shape:'box',color:'#3182ce',font:{color:'#fff'}},
               2:{shape:'box',color:'#63b3ed'},
               3:{shape:'ellipse',color:'#c6f6d5'},
               4:{shape:'dot',size:8},5:{shape:'triangle',size:6}},
       edges:{arrows:'to',color:{opacity:0.35},smooth:false}});
    net.once('stabilizationIterationsDone',()=>net.setOptions({physics:false}));
    document.getElementById('q').addEventListener('input',e=>{
      const q=e.target.value.toLowerCase();
      if(!q){nodeDS.update(NODES.map(n=>({id:n.id,hidden:false})));return;}
      const hit=new Set(NODES.filter(n=>n.label.toLowerCase().includes(q)).map(n=>n.id));
      EDGES.forEach(e=>{if(hit.has(e.from))hit.add(e.to);if(hit.has(e.to))hit.add(e.from);});
      nodeDS.update(NODES.map(n=>({id:n.id,hidden:!hit.has(n.id)})));
    });
    document.getElementById('seg').addEventListener('change',e=>{
      const s=e.target.value;
      if(!s){nodeDS.update(NODES.map(n=>({id:n.id,hidden:false})));return;}
      const root='segment:'+s;const keep=new Set([root]);let frontier=[root];
      const adj={};EDGES.forEach(e=>{(adj[e.from]=adj[e.from]||[]).push(e.to);});
      while(frontier.length){const nx=[];frontier.forEach(f=>{
        (adj[f]||[]).forEach(t=>{if(!keep.has(t)){keep.add(t);nx.push(t);}});});frontier=nx;}
      nodeDS.update(NODES.map(n=>({id:n.id,hidden:!keep.has(n.id)&&n.group!==3})));
    });
    net.on('doubleClick',p=>{if(p.nodes.length){
      const n=nodeDS.get(p.nodes[0]);
      const u=(n.title.match(/href='([^']+)'/)||[])[1];if(u)window.open(u,'_blank');}});
    </script>""")
        f.write(_population_html(POP_LINES))
        f.write("</body></html>")

    # ─────────────────────── stats.md ─────────────────────────────
    with (OUT / "repo-graph-stats.md").open("w") as f:
        f.write("# Portfolio Repository Graph — stats\n\n")
        f.write(
            f"Generated {ARGS.date} from `{INPUTS.name}/"
            f"{{{','.join(SEGMENTS)}}}` (excluded: {', '.join(ARGS.exclude)}) × "
            f"`{FINDINGS.parent.name}/{FINDINGS.name}/`.\n\n"
        )
        f.write(f"**Nodes:** {len(NODES)} · **Edges:** {len(EDGES)}\n\n")
        f.write("| node type | count |\n|---|---:|\n")
        for k, v in sorted(by_type.items(), key=lambda kv: -kv[1]):
            f.write(f"| {k} | {v} |\n")
        f.write("\n| edge rel | count |\n|---|---:|\n")
        for k, v in sorted(by_rel.items(), key=lambda kv: -kv[1]):
            f.write(f"| {k} | {v} |\n")
        f.write(
            f"\n**Repos with findings coverage:** {linked}/{len(repo_nodes)} "
            f"({unlinked} uncovered)\n\n"
        )
        disp_dirs = sum(1 for m in FIND_META.values() if m.get("dispositions"))
        if disp_dirs:
            resolved = sum(m.get("resolved") or 0 for m in FIND_META.values())
            open_f = sum(m.get("open") or 0 for m in FIND_META.values())
            fps = sum(m.get("fp") or 0 for m in FIND_META.values())
            f.write(
                f"**Findings dirs with disposition ledgers "
                f"(track-findings):** {disp_dirs}/{len(FIND_META)} — "
                f"{resolved} resolved/risk-accepted, {open_f} open, "
                f"{fps} false positives excluded\n\n"
            )
        if by_type.get("repo-ref"):
            f.write(
                f"**Ref layer (branch-awareness Phase 2):** "
                f"{by_type['repo-ref']} repo-ref nodes — one per unique "
                f"(repo, Source Branch) declared by an inventory CSV — "
                f"{by_rel.get('has_ref', 0)} has_ref + "
                f"{by_rel.get('ships_ref', 0)} ships_ref edges. Excluded "
                f"from hub degrees and from the HTML view.\n\n"
            )
        f.write("## Top-20 hub repositories (highest degree)\n\n")
        f.write("| repo | degree | max sev | TP | ships in |\n|---|---:|---|---:|---:|\n")
        for n in hubs:
            f.write(
                f"| [{md_cell(n['label'])}]({n['attrs'].get('url')}) | {degree[n['id']]} "
                f"| {n['attrs'].get('max_sev') or '—'} "
                f"| {n['attrs'].get('tp_total') or 0} "
                f"| {len(repo_products.get(n['id'], set()))} |\n"
            )
        f.write("\n## Outputs\n\n")
        f.write("- `repo-graph.json` — full-fidelity nodes+edges\n")
        f.write("- `repo-graph.dot` — GraphViz source (`dot -Tsvg -Ksfdp …`)\n")
        f.write("- `repo-graph.gexf` — Gephi import\n")
        f.write("- `repo-graph.html` — interactive vis-network (version/category collapsed)\n")
        if POP_LINES:
            f.write("\n---\n\n" + "\n".join(POP_LINES) + "\n")

    print(f"\nwrote → {OUT}/", file=sys.stderr)
    for p in sorted(OUT.iterdir()):
        print(f"  {p.name}  ({p.stat().st_size:,} bytes)", file=sys.stderr)


if __name__ == "__main__":
    sys.exit(main())
