"""``traust check coverage``: a checkout's entry points against the pre-scans that enumerate them.

traust-core's ``code_facts.coverage`` returns each threat-model entry point and each pre-scan
family as covered, uncovered or unexplained. This door adds the security pack's policy: which
results would send the repository to coverage repair instead of a paid audit. The policy runs in
observe mode: it reports ``would_route`` and never blocks or reroutes.
"""

from __future__ import annotations

import json
from pathlib import Path

from traust_core.v1.errors import NotFoundError
from traust_core.v1.models.code_facts import CoverageCheck, CoverageSource, CoverageStatus
from traust_core.v1.models.common import ToolRequest
from traust_core.v1.models.values import GitSha, HttpsRepoUrl

from traust.cli._doors import parser, run
from traust.context import load

MODE = "observe"
REPAIR_LANE = "coverage-repair"


def would_route(check: CoverageCheck) -> list[str]:
    """Why the repository would go to coverage repair; empty when it wouldn't. A pre-scan that
    detected a framework it can't enumerate, or a threat-model entry point of a kind some
    pre-scan covers that came back uncovered, routes. Unexplained (untagged) entry points and
    kinds no pre-scan enumerates are reported, never routed."""
    reasons = []
    for e in check.entries:
        if e.status is not CoverageStatus.UNCOVERED or e.enumerator is None:
            continue
        where = "pre-scan" if e.source is CoverageSource.PRE_SCAN else "threat model"
        reasons.append(f"{where}: {e.entry_point} ({e.reason})")
    return reasons


def document(check: CoverageCheck) -> dict:
    reasons = would_route(check)
    return {
        "mode": MODE,
        "threat_model_found": check.threat_model_found,
        "summary": {s.value: check.count(s) for s in CoverageStatus},
        "would_route": {"lane": REPAIR_LANE, "reasons": reasons} if reasons else None,
        "entries": [e.model_dump(mode="json", exclude_none=True) for e in check.entries],
    }


def main(argv: list[str] | None = None) -> int:
    ap = parser("check", "coverage", "A checkout's entry points against the pre-scans.")
    ap.add_argument("checkout", type=Path, help="the checkout to read (read-only)")
    ap.add_argument(
        "--repo-url", help="https URL of the registered repository, to read its threat model"
    )
    ap.add_argument("--sha", help="the checked-out commit (with --repo-url)")
    ap.add_argument("-o", "--out", type=Path, help="write the JSON here instead of stdout")
    args = ap.parse_args(argv)
    if bool(args.repo_url) != bool(args.sha):
        ap.error("--repo-url and --sha go together")

    def call() -> dict | None:
        core = load(args.config_home)
        services = core.services()
        ref_id = None
        if args.repo_url:
            url = HttpsRepoUrl.parse(args.repo_url, core.config.forge_hosts)
            repo = services.portfolio.find_repository(url)
            if repo is None or repo.id is None:
                raise NotFoundError(f"repository {args.repo_url} is not registered")
            ref = services.portfolio.register_ref(repo.id, GitSha.parse(args.sha), None, None)
            ref_id = ref.id
        check = services.code_facts.coverage(ToolRequest(workspace=args.checkout), ref_id)
        doc = document(check)
        if args.out is None:
            return doc
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
        return {"wrote": str(args.out), **doc["summary"], "would_route": bool(doc["would_route"])}

    return run(call)
