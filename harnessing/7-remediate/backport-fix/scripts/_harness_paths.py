"""Workspace / sibling resolution shared by the backport-fix scripts.

    workspace = HARNESS_WORKSPACE if set, else the first ancestor of this
                checkout that contains analysis-results/
    harness   = this checkout when it carries VERSION, else <workspace>/traust
                (the harness is a sibling of the internal skills overlay)
    contracts = the installed traust-contracts package, else a sibling
                traust-contracts checkout

Never a fixed parent count. This skill already moved one tier deeper
(harnessing/backport-fix -> harnessing/7-remediate/backport-fix), and every
depth-based lookup broke silently: publish-by-default started pointing at
<repo>/analysis-results (inside the checkout, not the corpus) and the VERSION
reads always missed. The README records the same failure class from the
earlier restructure ("Why the search, not a fixed depth").

Kept in one module so the resolution rules have a single implementation and
one test surface. Import path: these scripts are run directly, so their own
directory is sys.path[0]; importlib-based loaders (the unit tests) must add
it, which both scripts do before importing this module.
"""
from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

_VERSION_RE = re.compile(r"^\d+\.\d+\.\d+$")
_SHA_RE = re.compile(r"^[0-9a-f]{7,40}$")


_URL_USERINFO_RE = re.compile(r"(?P<scheme>[A-Za-z][A-Za-z0-9+.-]*://)(?P<userinfo>[^/?#]*@)")


def strip_url_credentials(url: str) -> str:
    """Drop `user:token@` from a URL's authority.

    Origins, `--repo-url` and `--fork-url` values are written into published
    artifacts and printed to terminals; a remote rewritten as
    `https://x-access-token:ghp_...@github.com/o/r` must never travel with the
    token attached. Only the authority is touched, so an `@` in a path or
    query survives. scp-like `user@host:path` forms are handled by the callers
    that convert them to https.
    """
    return _URL_USERINFO_RE.sub(r"\g<scheme>", str(url or "").strip())


def repo_root() -> Path:
    """This checkout's root, found by marker rather than by counting parents."""
    here = Path(__file__).resolve().parent
    for parent in here.parents:
        if (parent / ".git").exists():
            return parent
    # Packaged install (no .git): scripts -> backport-fix -> 7-remediate ->
    # harnessing -> repo root.
    return here.parents[3]


def _from_env(name: str, base: Path) -> Path | None:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return None
    p = Path(raw).expanduser()
    return p if p.is_absolute() else (base / p).resolve()


def workspace_root(*, required: bool = False) -> Path | None:
    """Directory holding the sibling repos: analysis-results/, traust/, ..."""
    root = repo_root()
    env = _from_env("HARNESS_WORKSPACE", root)
    if env is not None:
        if required and not (env / "analysis-results").is_dir():
            raise SystemExit(
                f"HARNESS_WORKSPACE={env} has no analysis-results/ — "
                "point it at the directory holding the sibling repos"
            )
        return env
    for parent in root.parents:
        if (parent / "analysis-results").is_dir():
            return parent
    if required:
        raise SystemExit(
            "workspace (the directory holding analysis-results/) not found "
            f"above {root} — set HARNESS_WORKSPACE"
        )
    return None


def harness_root() -> Path | None:
    """The harness checkout: this repo when cloned here, else the sibling."""
    root = repo_root()
    if (root / "VERSION").is_file():
        return root
    ws = workspace_root()
    if ws is None:
        return None
    candidate = ws / "traust"
    return candidate if (candidate / "VERSION").is_file() else None


def analysis_results_root() -> Path | None:
    """Where reports are published: AUDIT_RESULTS_ROOT, else the sibling.

    A relative AUDIT_RESULTS_ROOT resolves against the workspace root (the
    directory the corpus hangs off), falling back to this checkout.
    """
    root = repo_root()
    ws = workspace_root()
    env = _from_env("AUDIT_RESULTS_ROOT", ws or root)
    if env is not None:
        return env
    return (ws / "analysis-results") if ws is not None else None


def harness_version(*, with_rev: bool = False) -> str:
    """The harness VERSION (optionally suffixed with its short SHA).

    traust-internal carries no VERSION of its own: the number belongs to the
    upstream harness, which is a sibling checkout. Returns "0.0.0" when that
    checkout is not present, so callers never fabricate a version.
    """
    harness = harness_root()
    if harness is None:
        return "0.0.0"
    try:
        version = (harness / "VERSION").read_text().strip()
    except OSError:
        return "0.0.0"
    if not _VERSION_RE.fullmatch(version):
        return "0.0.0"
    if not with_rev:
        return version
    try:
        sha = subprocess.run(
            ["git", "-C", str(harness), "rev-parse", "--short=7", "HEAD"],
            capture_output=True, text=True, timeout=10, check=True,
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return version
    return f"{version}-{sha}" if _SHA_RE.fullmatch(sha) else version


def contracts_schema_path(name: str) -> Path | None:
    """Resolve a v1 contract schema by basename.

    Prefers the installed traust-contracts (or legacy ai-security-contracts)
    package, then a sibling checkout, then this repo's transitional schema/.
    """
    for mod in ("traust_contracts.paths", "ai_security_contracts.paths"):
        try:
            mod_obj = __import__(mod, fromlist=["schema_path"])
            p = Path(mod_obj.schema_path(name))
        except Exception:
            continue
        if p.is_file():
            return p
    ws = workspace_root()
    if ws is not None:
        for candidate in (
            # v0.1 layout (traust-contracts #136): artifacts_schema/v1
            ws / "traust-contracts" / "artifacts_schema" / "v1" / name,
            # pre-0.1 layout, kept for older checkouts
            ws / "traust-contracts" / "schemas" / "v1" / name,
            ws / "ai-security-contracts" / "schemas" / name,
        ):
            if candidate.is_file():
                return candidate
    vendored = repo_root() / "schema" / name
    return vendored if vendored.is_file() else None
