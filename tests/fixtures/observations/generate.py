"""Record old main()'s inputs to decide() and observed fields, offline.

Run manually with --source pointing at the reviewed build_rescan_worklist.py.
Normal tests use reference.json and never execute this generator or Git.
The built-in replies are synthetic. --recorded-forge also replays captured
public GitHub responses; the audit baseline remains a synthetic test input.
"""

from __future__ import annotations

import argparse
import copy
import datetime as dt
import hashlib
import json
import socket
import subprocess
import tempfile
from pathlib import Path
from types import ModuleType, SimpleNamespace
from unittest.mock import patch

REVISION = "2ad90c14300df343a790182d837b43ebc5263162"
SOURCE_SHA256 = "742643c232656bfd240e2f280d664277d18e0ff24f949122dcee12ce3306f80f"


def generate(source: Path, recorded_forge: Path | None = None) -> dict:
    data = source.read_bytes()
    assert hashlib.sha256(data).hexdigest() == SOURCE_SHA256, "review source drift first"
    module = ModuleType("observation_reference")
    module.__file__ = str(source)
    exec(compile(data, str(source), "exec"), module.__dict__)

    def forbidden(*args, **kwargs):
        raise AssertionError("fixture generator cannot access network or launch processes")

    socket.socket = socket.create_connection = subprocess.run = subprocess.Popen = forbidden

    class FixedDate(dt.date):
        @classmethod
        def today(cls):
            return cls(2026, 10, 6)

    module._dt = SimpleNamespace(date=FixedDate, datetime=dt.datetime, UTC=dt.UTC)
    info = {
        "ok": True,
        "pushed_at": "2026-10-01T12:00:00Z",
        "archived": False,
        "default_branch": "main",
        "visibility": "public",
        "fork": False,
        "parent": None,
    }
    compare = {
        "ok": True,
        "ahead_by": 2,
        "truncated": False,
        "files": [
            {"filename": "pkg/auth.go", "changes": 240},
            {"filename": "vendor/auth.go", "changes": 9000},
        ],
    }
    cases = [
        ("sensitive-first-party", {}, {}, {}, {}),
        ("measured-zero", {}, {}, {"ahead_by": 0, "files": []}, {}),
        ("dependencies-only", {}, {}, {"files": [{"filename": "go.mod", "changes": 10}]}, {}),
        ("unchanged", {}, {"pushed_at": "2026-08-01T00:00:00Z"}, {}, {}),
        ("same-day-push", {}, {"pushed_at": "2026-09-01T00:00:00Z"}, {}, {}),
        ("missing-denominator", {"lines_reviewed": None}, {}, {}, {}),
        ("missing-date", {"audit_date": None}, {}, {}, {}),
        ("archived-live-risk", {"live_crit_high": 5}, {"archived": True}, {}, {}),
        (
            "private-upstream",
            {},
            {"visibility": "private", "fork": True, "parent": "o/upstream"},
            {},
            {},
        ),
        ("info-failure", {}, {"ok": False, "kind": "unreachable", "error": "offline"}, {}, {}),
        (
            "compare-failure",
            {},
            {},
            {"ok": False, "kind": "no-credentials", "error": "offline"},
            {},
        ),
        (
            "gitlab-subgroup",
            {"repo_url": "https://gitlab.com/g/sub/repo"},
            {},
            {"patch": "diff", "truncated": True},
            {},
        ),
    ]
    if recorded_forge is not None:
        capture = json.loads(recorded_forge.read_text())
        project = capture["repository_url"].removeprefix("https://github.com/")
        replies = {
            f"repos/{project}": capture["info"]["response"],
            f"repos/{project}/compare/{capture['base_sha']}...HEAD": capture["compare"]["response"],
        }

        def replay(argv, **kwargs):
            assert argv[:2] == ["gh", "api"]
            return subprocess.CompletedProcess(
                argv, 0, stdout=json.dumps(replies[argv[2]]), stderr=""
            )

        # Run the original adapters too, rather than duplicating their JSON
        # normalization in the generator. No process or network is invoked.
        with patch.object(subprocess, "run", replay):
            recorded_info = module.gh_repo_info(project)
            recorded_compare = module.gh_compare(project, capture["base_sha"])
        assert recorded_info["ok"] and recorded_compare["ok"]
        cases.append(
            (
                "recorded-public-github",
                {"repo_url": capture["repository_url"], "pinned_sha": capture["base_sha"]},
                recorded_info,
                recorded_compare,
                {},
            )
        )
    recorded = []
    with tempfile.TemporaryDirectory(prefix="observation-reference-") as directory:
        root = Path(directory)
        db = root / "findings.db"
        db.touch()
        module.load_engine = lambda config: None
        module.analysis_results_dir = lambda engine: root
        module.harness_version = lambda: "fixture"
        module.optional_config_path = lambda name: None
        module.gh_rate_remaining = lambda: 100_000
        original_decide = module.decide
        for name, repo_over, info_over, compare_over, _ in cases:
            repo = {
                "repo_key": "fixture/repo",
                "repo_url": "https://github.com/o/repo",
                "audit_date": "2026-09-01",
                "pinned_sha": "a" * 40,
                "lines_reviewed": 10000,
                "live_crit_high": 1,
                **repo_over,
            }
            entry = {
                **repo,
                "sibling_repo_keys": [],
                "report_path": None,
                "product": None,
                "tree": None,
                "ownership": None,
            }
            reply_info, reply_compare = {**info, **info_over}, {**compare, **compare_over}
            module.load_population = lambda path, entry=entry: [entry]
            module._report_meta = lambda path, repo=repo: (
                repo["pinned_sha"],
                repo["lines_reviewed"],
                [],
            )
            module.gh_repo_info = lambda project, reply=reply_info: copy.deepcopy(reply)
            module.gitlab_repo_info = lambda host, project, reply=reply_info: copy.deepcopy(reply)
            module.gh_compare = lambda project, sha, reply=reply_compare: copy.deepcopy(reply)
            module.gitlab_compare = lambda host, project, sha, branch, reply=reply_compare: (
                copy.deepcopy(reply)
            )
            contexts = []

            def record(ctx, contexts=contexts):
                contexts.append(dict(ctx))
                return original_decide(ctx)

            module.decide = record
            out = root / "worklist.json"
            assert (
                module.main(
                    [
                        "--db",
                        str(db),
                        "--out",
                        str(out),
                        "--no-bootstrap",
                        "--no-tripwire",
                        "--no-preroute",
                        "--no-threat-model",
                    ]
                )
                == 0
            )
            assert len(contexts) == 1
            recorded.append(
                {
                    "name": name,
                    "repo": repo,
                    "info": reply_info,
                    "compare": reply_compare,
                    "ctx": contexts[0],
                    "status": entry["status"],
                    "observed": {
                        key: entry.get(key)
                        for key in ("C", "S", "S_lines", "deps_only", "ahead_by", "truncated")
                    },
                }
            )
    reference = {
        "source_revision": REVISION,
        "source_sha256": SOURCE_SHA256,
        "now": "2026-10-06T12:00:00+00:00",
        "cases": recorded,
    }
    if recorded_forge is not None:
        reference["recorded_forge"] = {
            "file": recorded_forge.name,
            "sha256": hashlib.sha256(recorded_forge.read_bytes()).hexdigest(),
        }
    return reference


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--recorded-forge", type=Path)
    args = parser.parse_args()
    Path(__file__).with_name("reference.json").write_text(
        json.dumps(generate(args.source, args.recorded_forge), indent=2) + "\n"
    )
