"""``traust repo checkout``: a commit's files through core's checkout service — the one door —
printing the workspace path for a skill or a hand run. The workspace is the caller's to use; a
session (``traust session run --checkout``) releases its own when it ends."""

from __future__ import annotations

from traust_core.v1.context import CheckoutRequest
from traust_core.v1.models.values import GitSha, HttpsRepoUrl, LocalRepoUrl

from traust.cli._doors import parser, run
from traust.context import load


def _history(raw: str | None) -> int | GitSha | None:
    """A depth when it reads as one, else the anchor sha the history must reach."""
    if raw is None:
        return None
    # a sha is 40/64 hex chars and may be all digits; only a shorter digit run is a depth
    return int(raw) if raw.isdigit() and len(raw) not in (40, 64) else GitSha.parse(raw)


def checkout(argv: list[str] | None = None) -> int:
    ap = parser(
        "repo",
        "checkout",
        "Print the path of a commit's checked-out workspace, through core's checkout service "
        "(the mirror cache), for skills and hand runs. The workspace is the caller's to use "
        "and remove when done (a plain directory); a session (`traust session run --checkout`) "
        "releases its own when it ends.",
    )
    ap.add_argument("url", help="https URL or local path of the repository")
    ap.add_argument("--ref", required=True, help="the commit's full sha")
    ap.add_argument(
        "--keep",
        action="append",
        metavar="GLOB",
        help="a glob of files to keep (repeatable): the forge archive serves kept files "
        "read-only, with no history and no writes",
    )
    ap.add_argument(
        "--history",
        help="the history the workspace must hold: a depth, or the anchor sha it must reach",
    )
    ap.add_argument("--writable", action="store_true", help="a workspace the run may write to")
    args = ap.parse_args(argv)

    def call() -> str:
        core = load(args.config_home)
        request = CheckoutRequest(
            repo=(
                HttpsRepoUrl.parse(args.url, core.config.forge_hosts)
                if args.url.startswith("https://")
                else LocalRepoUrl.parse(args.url)
            ),
            ref=GitSha.parse(args.ref),
            history=_history(args.history),
            writable=args.writable,
            keep=tuple(args.keep) if args.keep else None,
        )
        return str(core.services().checkouts.checkout(request).data.path)

    return run(call)
