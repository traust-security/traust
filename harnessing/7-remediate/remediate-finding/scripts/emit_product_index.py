#!/usr/bin/env python3
# Legacy batch mode, kept: no traust-core door selects candidates in bulk by product yet; run_one.sh
# now takes work item ids (traust remediation open), so this CSV manifest no longer feeds it.
"""
Emit a per-product remediation index repository.

Reads ``analysis-results/remediations/_manifest/remediation-manifest.csv``,
filters to one ``logical_product``, and writes a self-contained landing
directory (README + INDEX.md +
findings.csv + repositories.csv + abandoned.csv) suitable for pushing to
``<org>/<prefix>-<product>-index`` (prefix from ``REMEDIATION_PREFIX``, default ``traust``).

Unlike the global ``<prefix>-control`` repo, the per-product index is the
artifact handed to the owning team's reviewer alongside read access to the
``<fork_org>/<repo>`` mirrors (remediation.yaml).

CLI:
  emit_product_index.py <logical_product> [--out <dir>] [--display-name <name>]
"""

from __future__ import annotations

import argparse
import csv
import sys
from collections import Counter, defaultdict
from pathlib import Path

from traust.context import (
    add_config_home_arg,
    load_engine,
    remediation_settings,
    resolve_results_root,
    workspace_dir,
)

_SETTINGS = remediation_settings()
PREFIX = _SETTINGS["naming_prefix"]
FORK_ORG = _SETTINGS["fork_org"] or "<fork_org>"

HERE = Path(__file__).resolve().parent

SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def emit(product: str, out_dir: Path, display: str | None, manifest: Path) -> tuple[int, int, int]:
    with manifest.open(encoding="utf-8") as _f:
        rows = list(csv.DictReader(_f))
    mine = [r for r in rows if r["logical_product"] == product]
    if not mine:
        print(f"ERROR: no manifest rows with logical_product={product!r}", file=sys.stderr)
        sys.exit(1)
    done = [r for r in mine if r["status"] in ("checks_passed", "revalidated_fixed")]
    abandoned = [r for r in mine if r["status"] == "abandoned"]
    pending = [
        r for r in mine if r["status"] not in ("checks_passed", "revalidated_fixed", "abandoned")
    ]

    by_repo: dict[tuple, list] = defaultdict(list)
    for r in done:
        by_repo[(r["repo_name"], r["upstream_url"], r["fork_url"], r["audited_commit"])].append(r)
    sorted_repos = sorted(by_repo.items(), key=lambda kv: -len(kv[1]))

    out_dir.mkdir(parents=True, exist_ok=True)
    name = display or product

    # README.md
    by_sev = Counter(r["severity"] for r in done)
    readme = [
        f"# {name} — remediation index\n\n",
        "**Embargoed.** This repository indexes the automated security-finding patches produced by the ",
        f"traust Stage-9 remediation harness for **{name}**.\n\n",
        f"Each patch lives on a `{PREFIX}/<finding-id>/<slug>` branch in a **private mirror** under ",
        f"`github.com/{FORK_ORG}/<repo>`, cut from the audited upstream commit and carrying ",
        "exactly one finding's fix. Compare links in `INDEX.md` show the diff against the audited commit.\n\n",
        "## Snapshot\n\n| | |\n|---|---|\n",
        f"| Patched findings | **{len(done)}** |\n",
        f"| Repositories | **{len(by_repo)}** |\n",
        f"| Abandoned (FP / already-fixed / architectural) | {len(abandoned)} |\n",
        f"| In flight | {len(pending)} |\n",
        f"| By severity | {' · '.join(f'{k}: {v}' for k, v in sorted(by_sev.items(), key=lambda x: SEV_RANK.get(x[0], 9)))} |\n\n",
        "## Files\n\n| File | Purpose |\n|---|---|\n",
        "| [`INDEX.md`](INDEX.md) | Per-repo: upstream, mirror, every fix branch with title/severity/CWE/compare link |\n",
        "| [`findings.csv`](findings.csv) | Flat one-row-per-finding CSV |\n",
        "| [`repositories.csv`](repositories.csv) | One row per repo: mirror URL, finding counts by severity |\n",
        "| [`abandoned.csv`](abandoned.csv) | Findings ruled FP / already-fixed on inspection |\n\n",
        "## Reviewing\n\n",
        f"1. Accept your collaborator invitation(s) to the `{FORK_ORG}/<repo>` mirrors listed in `repositories.csv`.\n",
        "2. For each finding in `INDEX.md`, open the **compare** link to see the diff against the audited commit.\n",
        "3. Each fix commit message carries the full rationale; the schema-validated `*-remediation.json` report "
        "(rationale, behaviour-change note, residual risk, check results) is held in the harness workspace under "
        f"`analysis-results/remediations/{product}/<repo>/` — ask the remediation operator for a copy if needed.\n\n",
        "## Embargo\n\n",
        "Do not open PRs against, comment on, or otherwise reference these findings on the **public upstream** ",
        "repositories until a disclosure decision is made. Branch and commit names use only the internal `rem_id`.\n",
    ]
    (out_dir / "README.md").write_text("".join(readme), encoding="utf-8")

    # INDEX.md
    out = [
        f"# {name} — per-repository remediation index\n\n",
        f"**{len(done)} patched findings across {len(by_repo)} repositories.**\n\n",
        "| # | Repo | Mirror | Patched | H/M/L |\n|---|---|---|---|---|\n",
    ]
    for i, (key, findings) in enumerate(sorted_repos, 1):
        repo, upstream, fork, sha = key
        sevs = Counter(r["severity"] for r in findings)
        out.append(
            f"| {i} | [{repo}]({upstream}) | [mirror]({fork}) | {len(findings)} | "
            f"{sevs.get('high', 0)}/{sevs.get('medium', 0)}/{sevs.get('low', 0)} |\n"
        )
    out.append("\n---\n\n")
    for key, findings in sorted_repos:
        repo, upstream, fork, sha = key
        out.append(f"\n## `{repo}`\n\n")
        out.append(f"- **Upstream**: <{upstream}> @ `{sha[:12]}`\n")
        out.append(f"- **Private mirror**: <{fork}>\n")
        out.append(
            "\n| rem_id | sev | CWE | title | branch | compare |\n|---|---|---|---|---|---|\n"
        )
        for r in sorted(findings, key=lambda f: (SEV_RANK.get(f["severity"], 9), f["rem_id"])):
            title = (r["title"] or "").replace("|", "\\|")[:90]
            compare = f"{fork}/compare/{sha[:12]}...{r['fix_branch']}"
            out.append(
                f"| `{r['rem_id']}` | {r['severity']} | {r['cwes']} | {title} | "
                f"[`{r['fix_branch'].split('/', 2)[-1][:40]}`]({fork}/tree/{r['fix_branch']}) | "
                f"[diff]({compare}) |\n"
            )
    (out_dir / "INDEX.md").write_text("".join(out), encoding="utf-8")

    # findings.csv
    with open(out_dir / "findings.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(
            [
                "repo",
                "rem_id",
                "severity",
                "cwes",
                "title",
                "upstream_url",
                "audited_commit",
                "mirror_url",
                "fix_branch",
                "fix_commit",
                "compare_url",
                "status",
            ]
        )
        for key, findings in sorted_repos:
            repo, upstream, fork, sha = key
            for r in sorted(findings, key=lambda f: (SEV_RANK.get(f["severity"], 9), f["rem_id"])):
                w.writerow(
                    [
                        repo,
                        r["rem_id"],
                        r["severity"],
                        r["cwes"],
                        r["title"],
                        upstream,
                        sha,
                        fork,
                        r["fix_branch"],
                        r["fix_commit"],
                        f"{fork}/compare/{sha[:12]}...{r['fix_branch']}",
                        r["status"],
                    ]
                )

    # repositories.csv
    with open(out_dir / "repositories.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(
            [
                "repo",
                "upstream_url",
                "mirror_url",
                "audited_commit",
                "patched_findings",
                "high",
                "medium",
                "low",
            ]
        )
        for key, findings in sorted_repos:
            repo, upstream, fork, sha = key
            sevs = Counter(r["severity"] for r in findings)
            w.writerow(
                [
                    repo,
                    upstream,
                    fork,
                    sha,
                    len(findings),
                    sevs.get("high", 0),
                    sevs.get("medium", 0),
                    sevs.get("low", 0),
                ]
            )

    # abandoned.csv
    with open(out_dir / "abandoned.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["repo", "rem_id", "severity", "title", "triage_path"])
        for r in sorted(abandoned, key=lambda x: x["rem_id"]):
            w.writerow([r["repo_name"], r["rem_id"], r["severity"], r["title"], r["triage_path"]])

    return len(done), len(by_repo), len(abandoned)


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    add_config_home_arg(ap)
    ap.add_argument("--results-root", type=Path, default=None)
    ap.add_argument(
        "product", help="logical_product value in remediation-manifest.csv (e.g. mtv, mce, acs)"
    )
    ap.add_argument(
        "--out", help="output directory (default: .fork-staging/<prefix>-<product>-index)"
    )
    ap.add_argument("--display-name", help="human-readable product name for README/INDEX headings")
    args = ap.parse_args(argv)

    engine = load_engine(args.config_home)
    workspace = workspace_dir(engine)
    manifest = (
        resolve_results_root(args) / "remediations" / "_manifest" / "remediation-manifest.csv"
    )

    out_dir = (
        Path(args.out)
        if args.out
        else workspace / ".fork-staging" / f"{PREFIX}-{args.product}-index"
    )
    done, repos, abandoned = emit(args.product, out_dir, args.display_name, manifest)
    print(f"wrote {out_dir}")
    print(f"  {done} patched findings · {repos} repos · {abandoned} abandoned")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
