"""``traust store …`` — build and inspect the storage/v1 store the views read.

The seam that makes git-or-database an ADOPTER CHOICE rather than a fork in
the code. An adopter who keeps artifacts in git runs ``store ingest`` to
materialise a local SQLite store; an adopter on a database gets the same
rows at submit time and never runs this at all. Either way the dashboards
read the same views, because the views are the contract and the loading is
not.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

from traust_contracts.v1.storage import Store
from traust_engine.corpus import store_ingest, store_open

from traust.cli.groups._registry import OpSpec
from traust.context import analysis_results_dir

# ---------------------------------------------------------------------------
# ingest
# ---------------------------------------------------------------------------


def add_ingest_args(ap) -> None:
    ap.add_argument("--results-root", type=Path, default=None)
    ap.add_argument(
        "--out",
        type=Path,
        default=None,
        help="default: locations.store, else <results-root>/graph/store.db",
    )
    ap.add_argument("--trees", nargs="*", default=None)
    ap.add_argument(
        "--rebuild",
        action="store_true",
        help="discard an existing store first. The store is a CACHE for a git "
        "adopter, so this is cheap; it is NOT for a database adopter, whose "
        "store is the system of record.",
    )


def call_ingest(engine, args) -> int:
    results = (
        args.results_root.resolve()
        if args.results_root is not None
        else analysis_results_dir(engine)
    )
    out = args.out or store_open.store_path(engine)
    if out is None:
        print("no store location: set locations.store or --out")
        return 1
    out.parent.mkdir(parents=True, exist_ok=True)
    if args.rebuild and out.exists():
        out.unlink()

    conn = sqlite3.connect(out)
    store = Store(conn)
    store.init()
    report = store_ingest.ingest_tree(store, results, engine.corpus.config(), trees=args.trees)
    conn.commit()
    conn.close()
    print(store_ingest.render(report))
    print(f"wrote {out}")
    # A rejection is a data-quality queue, not a failed build: the artifacts
    # that DID validate are in the store and the dashboards over them are
    # correct. Exiting non-zero here would abort a dashboard rebuild over a
    # handful of off-contract files.
    return 0


INGEST = OpSpec(
    add_args=add_ingest_args,
    call=call_ingest,
    help="materialise the storage/v1 store from the artifact tree",
)


# ---------------------------------------------------------------------------
# status
# ---------------------------------------------------------------------------


def add_status_args(ap) -> None:
    ap.add_argument("--out", type=Path, default=None, help="store to inspect")


def call_status(engine, args) -> int:
    path = args.out or store_open.store_path(engine)
    print(f"store:  {path}")
    print(f"scopes: {', '.join(store_open.scope_ids(engine))}")
    if path is None or not path.is_file():
        print("state:  ABSENT — run `traust store ingest`")
        return 1
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    meta = conn.execute(
        "SELECT contract_version, revision, applied_at FROM traust_storage_meta"
    ).fetchone()
    bindings = conn.execute("SELECT COUNT(*) FROM artifact_binding").fetchone()[0]
    views = [
        row[0]
        for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='view' ORDER BY name"
        )
    ]
    print(f"state:  contracts {meta[0]}, REVISION {meta[1]}, applied {meta[2]}")
    print(f"        {bindings:,} bindings, {len(views)} views")
    conn.close()
    return 0


STATUS = OpSpec(
    add_args=add_status_args,
    call=call_status,
    help="where the store is, what revision it holds, and how much is in it",
)
