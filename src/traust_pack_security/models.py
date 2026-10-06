"""Inputs and observed facts, not routing decisions or engine job records."""

from pydantic import AwareDatetime, Field
from traust_core.v1.domain import HttpsRepoUrl, Model

from traust_pack_security.vocab import ComparisonStatus


class AuditedRepo(Model):
    """One deduplicated baseline, or a known inventory repo without an audit.

    The legacy report parser accepts abbreviated SHAs. Keep that input contract
    here rather than silently imposing Core's full-SHA rule on existing reports.
    """

    repo_key: str = Field(min_length=1)
    repo_url: str | None
    has_audit: bool = True
    audit_date: str | None = None
    pinned_sha: str | None = None
    lines_reviewed: int | None = None
    live_crit_high: int = 0
    designation: str | None = None


class RepoState(Model):
    """Latest observation. None means unavailable; measured zero stays zero.

    source_url preserves unsupported input for diagnosis. repo_key preserves
    identity when there is no usable typed URL. Lane and events are not state.
    """

    repo_key: str = Field(min_length=1)
    repo: HttpsRepoUrl | None
    source_url: str | None
    status: ComparisonStatus
    risk_tier: str
    exposure: str | None
    audit_age_days: int | None
    changed_lines: int | None
    churn_ratio: float | None
    sensitive_changed: bool | None
    sensitive_lines: int | None
    deps_only: bool | None
    ahead_by: int | None
    compare_truncated: bool | None
    push_changed: bool | None
    observed_at: AwareDatetime
    error: str | None = None

    @property
    def identity(self) -> str:
        # URL dedupe survives a different audit filing becoming the freshest.
        # Prefixes keep a missing-URL key distinct from a literal repository URL.
        return f"url:{self.repo}" if self.repo is not None else f"key:{self.repo_key}"
