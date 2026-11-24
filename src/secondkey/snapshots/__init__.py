"""Snapshot providers and the helpers that drive them."""

from __future__ import annotations

import shutil

from ..classify import Action
from ..policy import Policy
from ..store import Snapshot, Store
from ..util import new_id, now, snapshot_root
from .base import NothingToProtect, Provider, RestoreError, SnapshotUnavailable
from .files import FilesProvider
from .git import GitProvider
from .k8s import K8sProvider
from .postgres import PostgresProvider
from .terraform import TerraformProvider

PROVIDERS: dict[str, Provider] = {p.name: p for p in (FilesProvider(), GitProvider(), PostgresProvider(),
                                                         K8sProvider(), TerraformProvider())}

__all__ = ["PROVIDERS", "Provider", "RestoreError", "SnapshotUnavailable", "NothingToProtect", "plan", "take_all", "restore"]


def plan(actions: list[Action], policy: Policy) -> tuple[list[str], list[str]]:
    """Return (impact lines, problems) for the actions that will be snapshotted."""
    impact, problems = [], []
    for a in actions:
        prov = PROVIDERS.get(a.provider or "")
        if not prov:
            problems.append(f"{a.summary}: no automatic snapshot for {a.category}")
            continue
        try:
            impact.extend(prov.plan(a, policy))
        except SnapshotUnavailable as e:
            problems.append(f"{a.summary}: {e}")
        except Exception as e:  # never let a planning bug block the decision flow
            problems.append(f"{a.summary}: couldn't check ({e.__class__.__name__}: {e})")
    return impact, problems


def take_all(actions: list[Action], request_id: str | None, policy: Policy,
             store: Store) -> tuple[list[Snapshot], list[str], list[str]]:
    """Snapshot every protectable action.

    Returns (snapshots, skipped, failures). *skipped* are actions with no
    provider or nothing to protect; *failures* are snapshots that should have
    worked but didn't.
    """
    snaps, skipped, failures = [], [], []
    for a in actions:
        prov = PROVIDERS.get(a.provider or "")
        if not prov:
            skipped.append(f"{a.summary}: no automatic snapshot for {a.category}")
            continue
        sid = new_id("snap")
        dest = snapshot_root() / sid
        dest.mkdir(parents=True)
        try:
            label, meta = prov.take(a, dest, policy)
        except NothingToProtect as e:
            shutil.rmtree(dest, ignore_errors=True)
            skipped.append(f"{a.summary}: {e}")
            continue
        except Exception as e:
            shutil.rmtree(dest, ignore_errors=True)
            failures.append(f"{a.summary}: {e}")
            continue
        snap = Snapshot(sid, now(), request_id, prov.name, label, str(dest), {**meta, "action": a.to_dict()})
        store.add_snapshot(snap)
        snaps.append(snap)
    return snaps, skipped, failures


def describe(snap: Snapshot, mode: str | None = None) -> list[str]:
    return PROVIDERS[snap.provider].describe_restore(snap, mode)


def restore(snap: Snapshot, mode: str | None = None, force: bool = False) -> list[str]:
    return PROVIDERS[snap.provider].restore(snap, mode, force)
