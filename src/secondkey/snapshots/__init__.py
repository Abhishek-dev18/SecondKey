"""Snapshot providers and the helpers that drive them."""

from __future__ import annotations

import os
import shutil
import time
from pathlib import Path

from ..classify import Action
from ..policy import Policy
from ..store import Snapshot, Store
from ..util import home, new_id, now, snapshot_root
from .base import NothingToProtect, Provider, RestoreError, SnapshotUnavailable
from .aws import AWSProvider
from .docker import DockerProvider
from .files import FilesProvider
from .git import GitProvider
from .k8s import K8sProvider
from .mysql import MySQLProvider
from .postgres import PostgresProvider
from .terraform import TerraformProvider

PROVIDERS: dict[str, Provider] = {p.name: p for p in (FilesProvider(), GitProvider(), PostgresProvider(), MySQLProvider(),
                                                         K8sProvider(), TerraformProvider(), AWSProvider(), DockerProvider())}

__all__ = ["PROVIDERS", "Provider", "RestoreError", "SnapshotUnavailable", "NothingToProtect", "plan", "prune", "dir_size", "take_all", "restore"]


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
        meta["disk_bytes"] = dir_size(dest)
        snap = Snapshot(sid, now(), request_id, prov.name, label, str(dest), {**meta, "action": a.to_dict()})
        store.add_snapshot(snap)
        snaps.append(snap)
    if snaps:
        maybe_auto_prune(store, policy)
    return snaps, skipped, failures


def dir_size(path: str | Path) -> int:
    total = 0
    for root, _dirs, files in os.walk(path):
        for f in files:
            try:
                total += os.lstat(os.path.join(root, f)).st_size
            except OSError:
                pass
    return total


def prune(store: Store, policy: Policy, older_than_days: float | None = None, max_bytes: int | None = None,
          dry_run: bool = False) -> list[tuple[Snapshot, str, int]]:
    """Delete old snapshots. Returns (snapshot, reason, bytes) for each one removed.

    Never removes the newest snapshot, so the last action can always be undone.
    """
    days = policy.retention_days if older_than_days is None else older_than_days
    cap = policy.max_total_bytes if max_bytes is None else max_bytes
    snaps = store.live_snapshots()
    if not snaps:
        return []
    newest = snaps[-1].id
    sized = [(s, s.meta.get("disk_bytes") if os.path.isdir(s.path) and "disk_bytes" in s.meta else
              (dir_size(s.path) if os.path.isdir(s.path) else 0)) for s in snaps]
    doomed: list[tuple[Snapshot, str, int]] = []
    cutoff = now() - days * 86400 if days and days > 0 else None
    keep = []
    for s, size in sized:
        if cutoff is not None and s.created < cutoff and s.id != newest:
            doomed.append((s, f"older than {days:g} days", size))
        else:
            keep.append((s, size))
    total = sum(sz for _, sz in keep)
    if cap and cap > 0:
        for s, size in keep:
            if total <= cap or s.id == newest:
                break
            doomed.append((s, "over the total snapshot size limit", size))
            total -= size
    if not dry_run:
        for s, _reason, _size in doomed:
            try:
                PROVIDERS[s.provider].cleanup(s)
            except Exception:  # cleanup is best effort
                pass
            shutil.rmtree(s.path, ignore_errors=True)
            store.set_snapshot_status(s.id, "pruned")
    return doomed


def maybe_auto_prune(store: Store, policy: Policy) -> None:
    """Prune at most once a day, piggy-backing on normal use."""
    marker = home() / ".last_prune"
    try:
        if marker.exists() and time.time() - marker.stat().st_mtime < 86400:
            return
        marker.touch()
        removed = prune(store, policy)
        if removed:
            from .. import audit
            audit.record("prune", snapshots=[s.id for s, _, _ in removed], auto=True,
                         bytes=sum(b for _, _, b in removed))
    except Exception:  # never let housekeeping break the gate
        pass


def describe(snap: Snapshot, mode: str | None = None) -> list[str]:
    return PROVIDERS[snap.provider].describe_restore(snap, mode)


def restore(snap: Snapshot, mode: str | None = None, force: bool = False) -> list[str]:
    return PROVIDERS[snap.provider].restore(snap, mode, force)
