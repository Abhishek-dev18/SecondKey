from __future__ import annotations

from pathlib import Path
from typing import Any

from ..classify import Action
from ..policy import Policy
from ..store import Snapshot


class SnapshotUnavailable(RuntimeError):
    """The action can't be protected by a snapshot (reason in message)."""


class NothingToProtect(SnapshotUnavailable):
    """Nothing exists that the action could destroy (e.g. DROP TABLE IF EXISTS on a missing table)."""


class RestoreError(RuntimeError):
    pass


class Provider:
    name = "base"
    #: whether `secondkey undo` can put things back automatically
    restorable = True

    def plan(self, action: Action, policy: Policy) -> list[str]:
        """Check a snapshot is possible and describe the blast radius.

        Returns human-readable impact lines. Raises SnapshotUnavailable.
        """
        return []

    def take(self, action: Action, dest: Path, policy: Policy) -> tuple[str, dict[str, Any]]:
        """Write the restore point into ``dest``. Returns (label, meta)."""
        raise NotImplementedError

    def describe_restore(self, snap: Snapshot, mode: str | None = None) -> list[str]:
        return [f"restore {snap.label}"]

    def restore(self, snap: Snapshot, mode: str | None = None, force: bool = False) -> list[str]:
        """Put things back. Returns lines describing what was done."""
        raise NotImplementedError
