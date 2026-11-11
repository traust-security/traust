#!/usr/bin/env python3
"""Deterministic fix-propagation check for cross-repo remediations, on traust-core.

When a finding's fix lands in a DIFFERENT repository (upstream library, vendored dependency,
base image), the finding is not resolved until the ORIGINAL commit consumes the fixed version.
This answers that one question from the commit's SBOMs: its manifest SBOM (pass `--sbom` to
record one first, e.g. `syft dir:<checkout> -o cyclonedx-json`) and the images built from it.

Output (JSON to stdout, and --out if given):
  {"propagation": "consumed" | "pending" | "module_absent" | "not_observed",
   "checked": [ {source, version, consumed} ... ]}

'module_absent' is NOT automatically 'consumed': removal usually fixes, but the verifier judges
(the dependency may have been vendored under a different name). 'not_observed': the commit has
no SBOM, so nothing can be said. Never auto-resolve from this output alone.

Usage:
  traust check fix-propagation --repo-url https://github.com/org/app --sha <commit> \\
      --ecosystem go --module golang.org/x/net --fixed-version v0.17.0 \\
      [--sbom app.cdx.json] [--out f.json]
"""

from __future__ import annotations

import json
from pathlib import Path

from traust_core.v1.models.dependencies import Version
from traust_core.v1.models.values import HttpsRepoUrl
from traust_core.v1.models.vocabulary import Ecosystem

from traust.cli._doors import add_branch_arg, parser, register_commit, run
from traust.context import load


def main(argv: list[str] | None = None) -> int:
    ap = parser("check", "fix-propagation", "Has the original commit consumed the fixed version?")
    ap.add_argument("--repo-url", required=True, help="https URL of the ORIGINAL repository")
    ap.add_argument("--sha", required=True, help="the commit to check")
    add_branch_arg(ap)
    ap.add_argument("--ecosystem", required=True, choices=[e.value for e in Ecosystem])
    ap.add_argument("--module", required=True, help="the package the fix landed in")
    ap.add_argument("--fixed-version", required=True)
    ap.add_argument("--sbom", type=Path, help="the commit's SBOM, recorded before checking")
    ap.add_argument("--out", type=Path)
    args = ap.parse_args(argv)

    def call() -> str:
        core = load(args.config_home)
        services = core.services()
        url = HttpsRepoUrl.parse(args.repo_url, core.config.forge_hosts)
        repo = services.portfolio.register_repository(url, False)
        ref = register_commit(services, repo.id, args.sha, args.branch)
        if args.sbom is not None:
            services.exposure.ingest_sbom(args.sbom.read_bytes(), ref.id)
        found = services.exposure.consumes_fix(
            ref.id, Ecosystem(args.ecosystem), args.module, Version(args.fixed_version)
        )
        text = json.dumps(
            {
                "module": args.module,
                "fixed_version": args.fixed_version,
                "propagation": found.state.value,
                "checked": [
                    {
                        "source": f"image:{c.image_id}" if c.image_id else "manifest",
                        "version": c.version,
                        "consumed": c.consumed,
                    }
                    for c in found.checked
                ],
            },
            indent=1,
        )
        if args.out is not None:
            args.out.write_text(text + "\n", encoding="utf-8")
        return text

    return run(call)


if __name__ == "__main__":
    import sys

    from traust.cli.__main__ import main as cli

    raise SystemExit(cli(["check", "fix-propagation", *sys.argv[1:]]))
