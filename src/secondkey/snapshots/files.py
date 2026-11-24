"""File and directory snapshots (tar.gz) for rm, git clean and friends."""

from __future__ import annotations

import os
import shutil
import tarfile
import tempfile
from pathlib import Path
from typing import Any

from ..classify import Action
from ..policy import Policy
from ..store import Snapshot
from ..util import human_size
from .base import NothingToProtect, Provider, RestoreError, SnapshotUnavailable


def _size(path: str) -> tuple[int, int]:
    """(bytes, file count) for a file or directory tree, not following symlinks."""
    if os.path.islink(path) or os.path.isfile(path):
        return os.lstat(path).st_size, 1
    total, count = 0, 0
    for root, dirs, files in os.walk(path):
        for f in files:
            try:
                total += os.lstat(os.path.join(root, f)).st_size
                count += 1
            except OSError:
                pass
    return total, count


def measure(paths: list[str]) -> tuple[int, int, list[str]]:
    total, count, existing = 0, 0, []
    for p in paths:
        if os.path.lexists(p):
            b, c = _size(p)
            total, count = total + b, count + c
            existing.append(p)
    return total, count, existing


def archive(paths: list[str], dest: Path) -> list[dict[str, Any]]:
    entries = []
    with tarfile.open(dest / "files.tar.gz", "w:gz") as tar:
        for i, p in enumerate(paths):
            tar.add(p, arcname=str(i), recursive=True)
            entries.append({"i": i, "path": os.path.abspath(p), "dir": os.path.isdir(p) and not os.path.islink(p)})
    return entries


def unarchive(snap_path: str, entries: list[dict[str, Any]], force: bool) -> list[str]:
    conflicts = [e["path"] for e in entries if os.path.lexists(e["path"])]
    if conflicts and not force:
        raise RestoreError("these paths exist again, so restoring would overwrite them: "
                           + ", ".join(conflicts[:5]) + (" ..." if len(conflicts) > 5 else "")
                           + ". Move them away or re-run with --force.")
    done = []
    with tempfile.TemporaryDirectory(prefix="secondkey-restore-") as tmp, \
            tarfile.open(Path(snap_path) / "files.tar.gz", "r:gz") as tar:
        try:
            tar.extractall(tmp, filter="data")  # Python 3.12+ safe extraction
        except TypeError:  # pragma: no cover - older Python
            tar.extractall(tmp)
        for e in entries:
            src, dst = os.path.join(tmp, str(e["i"])), e["path"]
            if os.path.lexists(dst):
                if os.path.isdir(dst) and not os.path.islink(dst):
                    shutil.rmtree(dst)
                else:
                    os.remove(dst)
            os.makedirs(os.path.dirname(dst) or "/", exist_ok=True)
            shutil.move(src, dst)
            done.append(dst)
    return done


class FilesProvider(Provider):
    name = "files"

    def plan(self, action: Action, policy: Policy) -> list[str]:
        paths = action.target.get("paths") or []
        total, count, existing = measure(paths)
        if not existing:
            raise NothingToProtect("none of the paths exist")
        if total > policy.max_file_snapshot_bytes:
            raise SnapshotUnavailable(f"{human_size(total)} is over the {human_size(policy.max_file_snapshot_bytes)} file snapshot limit")
        return [f"{count} file{'s' if count != 1 else ''}, {human_size(total)} in {len(existing)} path{'s' if len(existing) != 1 else ''}"]

    def take(self, action: Action, dest: Path, policy: Policy) -> tuple[str, dict[str, Any]]:
        paths = action.target.get("paths") or []
        total, count, existing = measure(paths)
        if not existing:
            raise NothingToProtect("none of the paths exist")
        if total > policy.max_file_snapshot_bytes:
            raise SnapshotUnavailable(f"{human_size(total)} is over the file snapshot limit")
        entries = archive(existing, dest)
        names = ", ".join(os.path.relpath(p, action.target.get("cwd") or os.getcwd()) for p in existing[:3])
        label = f"{names}{' ...' if len(existing) > 3 else ''} ({count} files, {human_size(total)})"
        return label, {"entries": entries, "bytes": total, "files": count}

    def describe_restore(self, snap: Snapshot, mode: str | None = None) -> list[str]:
        return [f"put back {e['path']}" for e in snap.meta["entries"]]

    def restore(self, snap: Snapshot, mode: str | None = None, force: bool = False) -> list[str]:
        done = unarchive(snap.path, snap.meta["entries"], force)
        return [f"restored {p}" for p in done]
