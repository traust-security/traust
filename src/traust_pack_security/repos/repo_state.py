"""Latest repository observations, following Core's SQL repository pattern."""

from __future__ import annotations

from typing import Protocol
from urllib.parse import urlsplit

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql, sqlite
from sqlalchemy.engine import Engine
from traust_core.v1.domain import HttpsRepoUrl, RepositoryError
from traust_core.v1.repositories import SqlRepository, SqlUnitOfWork
from traust_core.v1.repositories.sql import UtcTimestamp, schema_drift

from traust_pack_security.models import RepoState


class RepoStateRepository(Protocol):
    def save(self, state: RepoState) -> None: ...
    def get(self, repo: HttpsRepoUrl) -> RepoState | None: ...
    def get_by_key(self, repo_key: str) -> RepoState | None: ...
    def list(self) -> list[RepoState]: ...


metadata = sa.MetaData()
repo_state = sa.Table(
    "security_repo_state",
    metadata,
    sa.Column("identity", sa.Text, primary_key=True),
    sa.Column("repo_key", sa.Text, nullable=False, unique=True),
    sa.Column("repo", sa.Text),
    sa.Column("source_url", sa.Text),
    sa.Column("status", sa.Text, nullable=False),
    sa.Column("risk_tier", sa.Text, nullable=False),
    sa.Column("exposure", sa.Text),
    sa.Column("audit_age_days", sa.Integer),
    sa.Column("changed_lines", sa.BigInteger),
    sa.Column("churn_ratio", sa.Float),
    sa.Column("sensitive_changed", sa.Boolean),
    sa.Column("sensitive_lines", sa.BigInteger),
    sa.Column("deps_only", sa.Boolean),
    sa.Column("ahead_by", sa.BigInteger),
    sa.Column("compare_truncated", sa.Boolean),
    sa.Column("push_changed", sa.Boolean),
    sa.Column("observed_at", UtcTimestamp, nullable=False),
    sa.Column("error", sa.Text),
)


def initialize_repo_state(engine: Engine) -> None:
    """Create this new pack table; never modify existing mismatched columns."""
    metadata.create_all(engine)
    if problems := schema_drift(engine, metadata):
        raise RepositoryError("repo-state schema mismatch: " + "; ".join(problems))


def _from_row(row) -> RepoState | None:
    if row is None:
        return None
    data = dict(row)
    data.pop("identity")
    if url := data["repo"]:
        data["repo"] = HttpsRepoUrl.parse(url, [urlsplit(url).hostname])
    return RepoState.model_validate(data)


class SqlRepoStateRepository(SqlRepository):
    def save(self, state: RepoState) -> None:
        # A missing URL can later be repaired, or a filing's URL can change.
        # Retire its old identity in the same transaction, not as a second row.
        self._execute(
            "replace previous filing identity",
            sa.delete(repo_state).where(
                repo_state.c.repo_key == state.repo_key,
                repo_state.c.identity != state.identity,
            ),
        )
        row = state.model_dump()
        row.update(identity=state.identity, repo=str(state.repo) if state.repo else None)
        insert = (
            postgresql.insert if self._connection.dialect.name == "postgresql" else sqlite.insert
        )
        statement = insert(repo_state).values(row)
        statement = statement.on_conflict_do_update(
            index_elements=["identity"],
            set_={key: statement.excluded[key] for key in row if key != "identity"},
        )
        self._execute("save observation", statement)

    def get(self, repo: HttpsRepoUrl) -> RepoState | None:
        statement = sa.select(repo_state).where(repo_state.c.identity == f"url:{repo}")
        return _from_row(self._execute("get observation", statement).mappings().first())

    def get_by_key(self, repo_key: str) -> RepoState | None:
        statement = sa.select(repo_state).where(repo_state.c.repo_key == repo_key)
        return _from_row(
            self._execute("get observation by key", statement).mappings().one_or_none()
        )

    def list(self) -> list[RepoState]:
        statement = sa.select(repo_state).order_by(repo_state.c.identity)
        return [_from_row(row) for row in self._execute("list observations", statement).mappings()]


class RepoStateUnitOfWork(SqlUnitOfWork):
    repo_state: SqlRepoStateRepository

    def _open_repositories(self) -> None:
        self.repo_state = SqlRepoStateRepository(self.connection)


class InMemoryRepoStateRepository:
    def __init__(self) -> None:
        self._rows: dict[str, RepoState] = {}

    def save(self, state: RepoState) -> None:
        self._rows = {
            key: value for key, value in self._rows.items() if value.repo_key != state.repo_key
        }
        self._rows[state.identity] = state

    def get(self, repo: HttpsRepoUrl) -> RepoState | None:
        return self._rows.get(f"url:{repo}")

    def get_by_key(self, repo_key: str) -> RepoState | None:
        return next((state for state in self._rows.values() if state.repo_key == repo_key), None)

    def list(self) -> list[RepoState]:
        return [self._rows[key] for key in sorted(self._rows)]
