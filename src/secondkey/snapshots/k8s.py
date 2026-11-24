"""Kubernetes snapshots: export the objects about to be deleted as YAML."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from ..classify import Action
from ..policy import Policy
from ..store import Snapshot
from ..util import CommandError, run
from .base import NothingToProtect, Provider, RestoreError, SnapshotUnavailable

DROP_FLAGS = ("--force", "--now", "--wait", "--grace-period", "--cascade", "--ignore-not-found", "--timeout",
              "--dry-run", "--interactive", "-i", "--raw", "--output", "-o")
VOLATILE = ("uid", "resourceVersion", "creationTimestamp", "generation", "managedFields", "selfLink", "deletionTimestamp",
            "deletionGracePeriodSeconds", "ownerReferences")


def get_args(args: list[str]) -> list[str]:
    """Turn `delete <what>` arguments into `get <what> -o yaml`."""
    out, i, swapped = [], 0, False
    while i < len(args):
        a = args[i]
        if not swapped and a == "delete":
            out.append("get")
            swapped = True
        elif a.split("=", 1)[0] in DROP_FLAGS:
            if "=" not in a and a in ("--grace-period", "--cascade", "--timeout", "--output", "-o") and i + 1 < len(args):
                i += 1
        else:
            out.append(a)
        i += 1
    return out + ["-o", "yaml"]


def clean(doc: dict[str, Any]) -> dict[str, Any]:
    items = doc.get("items") if doc.get("kind", "").endswith("List") else [doc]
    cleaned = []
    for it in items or []:
        it = dict(it)
        it.pop("status", None)
        md = dict(it.get("metadata") or {})
        for k in VOLATILE:
            md.pop(k, None)
        ann = dict(md.get("annotations") or {})
        ann.pop("kubectl.kubernetes.io/last-applied-configuration", None)
        if ann:
            md["annotations"] = ann
        else:
            md.pop("annotations", None)
        it["metadata"] = md
        if it.get("kind") == "Service":
            spec = dict(it.get("spec") or {})
            for k in ("clusterIP", "clusterIPs"):
                spec.pop(k, None)
            it["spec"] = spec
        cleaned.append(it)
    return {"apiVersion": "v1", "kind": "List", "items": cleaned}


class K8sProvider(Provider):
    name = "k8s"

    def _export(self, action: Action) -> dict[str, Any]:
        args = get_args(action.target.get("args") or [])
        try:
            out = run(["kubectl", *args], cwd=action.target.get("cwd"), timeout=120).stdout
        except CommandError as e:
            raise SnapshotUnavailable(f"kubectl get failed: {e.stderr.strip()[:300]}") from e
        return clean(yaml.safe_load(out) or {})

    def plan(self, action: Action, policy: Policy) -> list[str]:
        doc = self._export(action)
        names = [f"{i.get('kind')}/{i['metadata'].get('name')}" for i in doc["items"]]
        return [f"{len(names)} object{'s' if len(names) != 1 else ''}: " + ", ".join(names[:6]) + (" ..." if len(names) > 6 else "")]

    def take(self, action: Action, dest: Path, policy: Policy) -> tuple[str, dict[str, Any]]:
        doc = self._export(action)
        if not doc["items"]:
            raise NothingToProtect("kubectl found no matching objects")
        (dest / "resources.yaml").write_text(yaml.safe_dump(doc, sort_keys=False))
        names = [f"{i.get('kind')}/{i['metadata'].get('name')}" for i in doc["items"]]
        return ", ".join(names[:4]) + (" ..." if len(names) > 4 else ""), {"objects": names, "cwd": action.target.get("cwd")}

    def describe_restore(self, snap: Snapshot, mode: str | None = None) -> list[str]:
        return [f"kubectl apply {len(snap.meta['objects'])} saved objects: " + ", ".join(snap.meta["objects"][:6]),
                "workloads are recreated from their spec; data in deleted volumes is not restored"]

    def restore(self, snap: Snapshot, mode: str | None = None, force: bool = False) -> list[str]:
        try:
            out = run(["kubectl", "apply", "-f", str(Path(snap.path) / "resources.yaml")], cwd=snap.meta.get("cwd"), timeout=300).stdout
        except CommandError as e:
            raise RestoreError(f"kubectl apply failed: {e.stderr.strip()[:400]}") from e
        return [ln for ln in out.splitlines() if ln.strip()]
