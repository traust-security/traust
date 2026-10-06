"""Observe one repository using the existing worklist's forge and metric rules.

The small mutation helpers are shared with the batch CLI during migration.
Fleet ordering, quota allocation and its shared ban breaker remain in that CLI.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from typing import Literal, Protocol

from pydantic import ConfigDict
from traust_core.v1.domain import HttpsRepoUrl, Model, ValidationError

from traust.cli import build_rescan_worklist as legacy
from traust_pack_security.models import AuditedRepo, RepoState
from traust_pack_security.vocab import ComparisonStatus


class ForgeClient(Protocol):
    """Only the existing info, comparison, and quota calls; no new endpoints."""

    def repo_info(self, kind: str, host: str, project: str) -> dict: ...
    def compare(self, kind: str, host: str, project: str, sha: str, branch: str) -> dict: ...
    def remaining(self) -> int | None: ...


class LegacyForgeClient:
    def repo_info(self, kind: str, host: str, project: str) -> dict:
        return (
            legacy.gh_repo_info(project)
            if kind == "github"
            else legacy.gitlab_repo_info(host, project)
        )

    def compare(self, kind: str, host: str, project: str, sha: str, branch: str) -> dict:
        return (
            legacy.gh_compare(project, sha)
            if kind == "github"
            else legacy.gitlab_compare(host, project, sha, branch)
        )

    def remaining(self) -> int | None:
        return legacy.gh_rate_remaining()


class _ForgeFailure(Model):
    # Failure payloads may retain unused info/comparison fields. Only their
    # status and diagnostic are consumed, as in the legacy helpers.
    model_config = ConfigDict(extra="ignore")

    ok: Literal[False] = False
    kind: Literal["no-credentials", "unreachable", "error", "ban-suspected"] = "error"
    error: str | None = None


class _RepoInfo(Model):
    ok: Literal[True]
    pushed_at: str | None = None
    archived: bool | None = None
    default_branch: str | None = None
    visibility: str | None = None
    fork: bool | None = None
    parent: str | None = None


class _ChangedFile(Model):
    filename: str
    changes: int


class _Comparison(Model):
    ok: Literal[True]
    ahead_by: int
    truncated: bool
    files: list[_ChangedFile]
    patch: str | None = None


class _Quota(Model):
    ok: Literal[True]
    remaining: int | None


def _forge_result(fetch: Callable, response_type: type[Model], *args) -> dict:
    """Validate the normalized forge response before dates/metrics consume it.

    Only the adapter call and response validation degrade here. Exceptions in
    observation calculations or persistence remain visible to their callers.
    Core and Pydantic validation errors both derive from ValueError.
    """
    try:
        result = fetch(*args)
        shape = response_type if result.get("ok") else _ForgeFailure
        return shape.model_validate(result, strict=True).model_dump()
    except OSError as exc:
        return {"ok": False, "kind": "unreachable", "error": str(exc)}
    except (AttributeError, KeyError, TypeError, ValueError) as exc:
        # Avoid including raw forge payloads in stored validation diagnostics.
        return {
            "ok": False,
            "kind": "error",
            "error": f"malformed forge response ({type(exc).__name__})",
        }


def observe_info(
    entry: dict, gh_info: Callable, gl_info: Callable, breaker: legacy._BanBreaker
) -> None:
    """The per-entry body of stage1, with its existing batch breaker injected."""
    kind, host, project = legacy.split_repo_url(entry["repo_url"])
    entry["host_kind"], entry["host"], entry["project"] = kind, host, project
    if entry["repo_url"] is None:
        entry["status"] = "no-repo-url"
        return
    if kind is None:
        entry["status"] = "unsupported-host"
        return
    if kind == "github" and breaker.tripped:
        entry["status"] = "ban-suspected"
        entry["error"] = (
            "skipped: consecutive-error streak suggests a "
            "GitHub secondary ban (rate_limit is blind to "
            "these); next daily run retries"
        )
        return
    info = gh_info(project) if kind == "github" else gl_info(host, project)
    if kind == "github":
        breaker.record(info.get("ok", False))
    if not info.get("ok"):
        entry["status"] = info.get("kind", "error")
        entry["error"] = info.get("error")
        return
    entry["status"] = "ok"
    entry["pushed_at"] = info.get("pushed_at")
    entry["archived"] = bool(info.get("archived"))
    entry["default_branch"] = info.get("default_branch")
    entry["visibility"] = info.get("visibility")
    entry["fork"] = bool(info.get("fork"))
    entry["parent"] = info.get("parent")


def observe_comparison(
    entry: dict, gh_cmp: Callable, gl_cmp: Callable, *, quota_deferred: bool = False
) -> None:
    """The per-entry body of stage2. Quota allocation is the caller's decision."""
    if not entry.get("pinned_sha"):
        entry["status"] = "no-pinned-sha"
        return
    if quota_deferred:
        entry["status"] = "quota-deferred"
        return
    if entry["host_kind"] == "github":
        result = gh_cmp(entry["project"], entry["pinned_sha"])
    else:
        result = gl_cmp(
            entry["host"],
            entry["project"],
            entry["pinned_sha"],
            entry.get("default_branch") or "HEAD",
        )
    if not result.get("ok"):
        entry["status"] = result.get("kind", "error")
        entry["error"] = result.get("error")
        return
    entry["ahead_by"] = result["ahead_by"]
    entry["truncated"] = result["truncated"]
    if result.get("patch"):
        entry["_patch"] = result["patch"]
    entry.update(legacy.change_metrics(result["files"]))


def observe_repo(
    repo: AuditedRepo,
    forge: ForgeClient,
    now: datetime,
    *,
    network: bool = True,
    breaker: legacy._BanBreaker | None = None,
) -> RepoState:
    """Collect facts for one repo; expected forge trouble becomes a status.

    An unchanged repo is not compared. An inventory repo without an audit keeps
    the existing zero-forge-call bootstrap behavior. Input/storage failures are
    not forge failures and must not be misreported as successful observations.
    """
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("observation time must include a timezone")
    entry = repo.model_dump()
    typed_url = None
    if repo.repo_url is not None:
        try:
            typed_url = HttpsRepoUrl.parse(repo.repo_url, legacy.GIT_HOSTS)
            if legacy.GIT_HOSTS[typed_url.host] == "github":
                # Match the legacy forge target: GitHub URLs address owner/repo,
                # even when a report links to a tree/blob below that root.
                path = "/".join(typed_url.path.split("/")[:2])
                typed_url = HttpsRepoUrl.parse(f"https://{typed_url.host}/{path}", legacy.GIT_HOSTS)
            entry["repo_url"] = str(typed_url)
        except (ValidationError, ValueError):
            typed_url = None
            entry["status"] = "unsupported-host"
    if repo.repo_url is None:
        entry["status"] = "no-repo-url"
    elif not repo.has_audit and typed_url is not None:
        entry["status"] = "never-audited"
    elif "status" not in entry and not network:
        entry["status"] = "network-skipped"
    elif "status" not in entry:
        observe_info(
            entry,
            lambda project: _forge_result(
                forge.repo_info, _RepoInfo, "github", typed_url.host, project
            ),
            lambda host, project: _forge_result(
                forge.repo_info, _RepoInfo, "gitlab", host, project
            ),
            breaker if breaker is not None else legacy._BanBreaker(),
        )

    today = now.date()
    audited = legacy._parse_date(repo.audit_date) if repo.has_audit else None
    pushed = legacy._parse_date(entry.get("pushed_at"))
    changed = bool(pushed and audited and pushed >= audited)
    if entry["status"] == "ok" and changed:
        # A single observation checks live remaining quota; it does not reserve
        # capacity. The batch caller retains its index-based fleet allocation.
        quota = {"ok": True, "remaining": None}
        if entry["host_kind"] == "github" and repo.pinned_sha:
            quota = _forge_result(lambda: {"ok": True, "remaining": forge.remaining()}, _Quota)
        if not quota["ok"]:
            entry.update(status=quota["kind"], error=quota["error"])
        else:
            remaining = quota["remaining"]
            observe_comparison(
                entry,
                lambda project, sha: _forge_result(
                    forge.compare, _Comparison, "github", typed_url.host, project, sha, "HEAD"
                ),
                lambda host, project, sha, branch: _forge_result(
                    forge.compare, _Comparison, "gitlab", host, project, sha, branch
                ),
                quota_deferred=remaining is not None and remaining <= 0,
            )
    dormant = bool(pushed and (today - pushed).days > legacy.DORMANT_DAYS)
    changed_lines = entry.get("C")
    return RepoState(
        repo_key=repo.repo_key,
        repo=typed_url,
        source_url=repo.repo_url,
        status=ComparisonStatus(entry["status"]),
        risk_tier=legacy.risk_tier(repo.live_crit_high, entry.get("archived", False), dormant),
        exposure=legacy.exposure_class(entry),
        audit_age_days=(today - audited).days if audited else None,
        changed_lines=changed_lines,
        churn_ratio=changed_lines / repo.lines_reviewed
        if changed_lines is not None and repo.lines_reviewed
        else None,
        sensitive_changed=entry.get("S"),
        sensitive_lines=entry.get("S_lines"),
        deps_only=entry.get("deps_only"),
        ahead_by=entry.get("ahead_by"),
        compare_truncated=entry.get("truncated"),
        push_changed=changed if pushed and audited else None,
        observed_at=now,
        error=entry.get("error"),
    )
