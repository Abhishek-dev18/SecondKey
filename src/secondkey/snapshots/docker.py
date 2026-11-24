"""Docker volume snapshots: tar the volume contents through a throwaway container."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..classify import Action
from ..policy import Policy
from ..store import Snapshot
from ..util import CommandError, run
from .base import NothingToProtect, Provider, RestoreError, SnapshotUnavailable


def _image(policy: Policy | None) -> str:
    return str((policy.snapshots.get("docker_image") if policy else None) or "alpine:3")


def _volumes(action: Action) -> list[str]:
    t = action.target
    if t.get("dangling"):
        try:
            return run(["docker", "volume", "ls", "-q", "-f", "dangling=true"], timeout=60).stdout.split()
        except CommandError as e:
            raise SnapshotUnavailable(f"docker volume ls failed: {e.stderr.strip()[:200]}") from e
    return list(t.get("volumes") or [])


def _exists(vol: str) -> bool:
    return run(["docker", "volume", "inspect", vol], check=False, timeout=30).returncode == 0


class DockerProvider(Provider):
    name = "docker"

    def plan(self, action: Action, policy: Policy) -> list[str]:
        vols = [v for v in _volumes(action) if _exists(v)]
        if not vols:
            raise NothingToProtect("no matching volumes")
        return [f"{len(vols)} volume{'s' if len(vols) != 1 else ''} will be archived: " + ", ".join(vols[:6])]

    def take(self, action: Action, dest: Path, policy: Policy) -> tuple[str, dict[str, Any]]:
        vols = [v for v in _volumes(action) if _exists(v)]
        if not vols:
            raise NothingToProtect("no matching volumes")
        image = _image(policy)
        for v in vols:
            try:
                run(["docker", "run", "--rm", "-v", f"{v}:/from:ro", "-v", f"{dest}:/to", image,
                     "tar", "czf", f"/to/{v}.tgz", "-C", "/from", "."], timeout=3600)
            except CommandError as e:
                raise SnapshotUnavailable(f"couldn't archive volume {v}: {e.stderr.strip()[:200]}") from e
        return f"docker volumes {', '.join(vols[:4])}{' ...' if len(vols) > 4 else ''}", {"volumes": vols, "image": image}

    def describe_restore(self, snap: Snapshot, mode: str | None = None) -> list[str]:
        return [f"recreate volume {v} and unpack its saved contents" for v in snap.meta["volumes"]]

    def restore(self, snap: Snapshot, mode: str | None = None, force: bool = False) -> list[str]:
        out = []
        for v in snap.meta["volumes"]:
            if _exists(v) and not force:
                raise RestoreError(f"volume {v} exists again; use --force to unpack over it")
            try:
                run(["docker", "volume", "create", v], timeout=60)
                run(["docker", "run", "--rm", "-v", f"{v}:/to", "-v", f"{snap.path}:/from:ro", snap.meta["image"],
                     "tar", "xzf", f"/from/{v}.tgz", "-C", "/to"], timeout=3600)
            except CommandError as e:
                raise RestoreError(f"couldn't restore volume {v}: {e.stderr.strip()[:300]}") from e
            out.append(f"volume {v} restored")
        return out
