"""Temporary adapter over the existing read paths until XWING-2213 lands.

No new findings SQL or report parser. The legacy population reader retains URL
dedupe, freshest baseline selection, and max live risk across sibling filings.
Only the selected repository's report and forge state are observed.
"""

from pathlib import Path
from typing import Protocol

from traust.cli import build_rescan_worklist as legacy
from traust_pack_security.models import AuditedRepo


class ObservationInputs(Protocol):
    def find(self, *, repo_url: str | None = None, repo_key: str | None = None) -> AuditedRepo: ...


class LegacyObservationInputs:
    def __init__(self, findings_db: Path, graph_db: Path, designations: Path):
        self.findings_db = findings_db
        self.graph_db = graph_db
        self.designations = designations

    def find(self, *, repo_url: str | None = None, repo_key: str | None = None) -> AuditedRepo:
        if (repo_url is None) == (repo_key is None):
            raise ValueError("supply exactly one repository URL or key")
        if not self.findings_db.is_file():
            raise FileNotFoundError(f"findings projection not found: {self.findings_db}")
        url = legacy.normalize_repo_url(repo_url) if repo_url is not None else None
        if repo_url is not None and not url:
            raise ValueError("repository URL could not be normalized")
        entries = legacy.load_population(self.findings_db)
        designations = legacy.load_designations(self.designations)
        for entry in entries:
            matches = (
                entry["repo_url"] == url
                if url
                else repo_key in [entry["repo_key"], *entry["sibling_repo_keys"]]
            )
            if matches:
                sha, lines, _ = legacy._report_meta(entry["report_path"])
                return AuditedRepo(
                    repo_key=entry["repo_key"],
                    repo_url=entry["repo_url"],
                    audit_date=entry["audit_date"],
                    pinned_sha=sha,
                    lines_reviewed=lines,
                    live_crit_high=entry["live_crit_high"],
                    designation=legacy.lookup_designation(entry["repo_url"], designations),
                )
        if url:
            # Absence from the audited view is not proof of inventory membership.
            baselined = {entry["repo_url"] for entry in entries if entry["repo_url"]}
            for entry in legacy.never_audited_rows(self.graph_db, baselined, designations):
                if entry["repo_url"] == url:
                    return AuditedRepo(
                        repo_key=entry["repo_key"],
                        repo_url=url,
                        has_audit=False,
                        designation=legacy.lookup_designation(url, designations),
                    )
        raise LookupError("repository not found in the available audit/inventory views")
