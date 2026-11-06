"""Validate report destinations and publish staged report sets with rollback recovery."""

from __future__ import annotations

import shutil
import stat
import sys
from pathlib import Path
from tempfile import mkdtemp

from traust_core.v1.errors import ValidationError


def report_paths(paths: tuple[Path, ...]) -> tuple[Path, ...]:
    resolved = tuple(path.resolve() for path in paths)
    if len(set(resolved)) != len(resolved):
        raise ValidationError("JSON, Markdown and HTML destinations must be distinct")
    identities = set()
    for path in resolved:
        if any(path in other.parents for other in resolved):
            raise ValidationError("Report destinations cannot contain one another")
        try:
            info = path.stat()
        except FileNotFoundError:
            continue
        if not stat.S_ISREG(info.st_mode):
            raise ValidationError(f"Report destination is not a regular file: {path}")
        identity = (info.st_dev, info.st_ino)
        if identity in identities:
            raise ValidationError("JSON, Markdown and HTML destinations must be distinct")
        identities.add(identity)
    return resolved


def write_reports(outputs: dict[Path, str]) -> None:
    """Stage the complete set; restore previous files after a handled publication failure."""
    directories: list[Path] = []
    staged: list[tuple[Path, Path, Path | None]] = []
    retain_backups = False
    committed = False
    try:
        for path, content in outputs.items():
            path.parent.mkdir(parents=True, exist_ok=True)
            directory = Path(mkdtemp(prefix=".report-files-", dir=path.parent))
            directories.append(directory)
            new = directory / "new"
            new.write_text(content, encoding="utf-8")
            backup = None
            if path.exists():
                new.chmod(stat.S_IMODE(path.stat().st_mode))
                backup = directory / "previous"
            staged.append((new, path, backup))
        # Keep recovery files until replacement or restoration has definitely completed.
        retain_backups = True
        try:
            for new, path, backup in staged:
                if backup is not None:
                    path.replace(backup)
                new.replace(path)
        except BaseException:
            recovery_errors = []
            for new, path, backup in reversed(staged):
                try:
                    # Inspect the files, not a post-rename flag: cancellation can arrive
                    # after a rename succeeds but before Python records its completion.
                    if backup is not None:
                        if backup.exists():
                            backup.replace(path)
                    elif not new.exists():
                        path.unlink(missing_ok=True)
                except OSError as recovery_error:
                    recovery_errors.append(f"{path}: {recovery_error}")
            if recovery_errors:
                print(f"ERROR: rollback incomplete: {'; '.join(recovery_errors)}", file=sys.stderr)
            else:
                retain_backups = False
            raise
        else:
            committed = True
            retain_backups = False
    finally:
        if retain_backups:
            locations = ", ".join(str(directory) for directory in directories)
            print(f"ERROR: recovery files retained in: {locations}", file=sys.stderr)
        else:
            for directory in directories:
                try:
                    shutil.rmtree(directory)
                except OSError as cleanup_error:
                    state = "committed" if committed else "did not commit"
                    print(
                        f"WARNING: report publication {state}; could not remove staging "
                        f"directory {directory}: {cleanup_error}",
                        file=sys.stderr,
                    )
