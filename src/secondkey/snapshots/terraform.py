"""Terraform / OpenTofu: back up the state file and the config commit.

Honest limits: after `terraform destroy` the real resources are gone. Pushing
the old state back would make Terraform believe they still exist, which is
worse. So for destroy/apply, undo explains how to recreate the resources from
the saved config instead of touching state. For state surgery
(`state rm/mv/push`, import, taint) undo pushes the saved state back.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..classify import Action
from ..policy import Policy
from ..store import Snapshot
from ..util import CommandError, run
from .base import Provider, RestoreError, SnapshotUnavailable


class TerraformProvider(Provider):
    name = "terraform"

    def _pull(self, action: Action) -> str:
        t = action.target
        try:
            return run([t.get("binary", "terraform"), "state", "pull"], cwd=t.get("cwd"), timeout=300).stdout
        except CommandError as e:
            raise SnapshotUnavailable(f"state pull failed: {e.stderr.strip()[:300]}") from e

    def plan(self, action: Action, policy: Policy) -> list[str]:
        state = self._pull(action)
        try:
            n = len(json.loads(state).get("resources") or []) if state.strip() else 0
        except json.JSONDecodeError:
            n = 0
        note = "" if action.category == "tf.state_write" else " (state backup only; destroyed cloud resources can't be un-destroyed)"
        return [f"state with {n} resource{'s' if n != 1 else ''} will be backed up{note}"]

    def take(self, action: Action, dest: Path, policy: Policy) -> tuple[str, dict[str, Any]]:
        state = self._pull(action)
        (dest / "terraform.tfstate").write_text(state)
        cwd = action.target.get("cwd")
        commit = run(["git", "-C", cwd or ".", "rev-parse", "--verify", "-q", "HEAD"], check=False).stdout.strip() if cwd else ""
        try:
            n = len(json.loads(state).get("resources") or []) if state.strip() else 0
        except json.JSONDecodeError:
            n = 0
        return f"terraform state ({n} resources)" + (f", config @ {commit[:8]}" if commit else ""), {
            "cwd": cwd, "binary": action.target.get("binary", "terraform"), "category": action.category,
            "commit": commit or None, "resources": n}

    def describe_restore(self, snap: Snapshot, mode: str | None = None) -> list[str]:
        m = snap.meta
        if m["category"] == "tf.state_write":
            return [f"push the saved state ({m['resources']} resources) back with `{m['binary']} state push -force`"]
        steps = ["Terraform can't un-destroy cloud resources. To recreate them:"]
        if m.get("commit"):
            steps.append(f"  git checkout {m['commit'][:8]} -- .   (the config as it was)")
        steps.append(f"  {m['binary']} apply")
        steps.append(f"saved state for reference (resource IDs, attributes): {Path(snap.path) / 'terraform.tfstate'}")
        return steps

    def restore(self, snap: Snapshot, mode: str | None = None, force: bool = False) -> list[str]:
        m = snap.meta
        if m["category"] != "tf.state_write":
            raise RestoreError("\n".join(self.describe_restore(snap)))
        try:
            run([m["binary"], "state", "push", "-force", str(Path(snap.path) / "terraform.tfstate")], cwd=m["cwd"], timeout=300)
        except CommandError as e:
            raise RestoreError(f"state push failed: {e.stderr.strip()[:400]}") from e
        return [f"terraform state restored ({m['resources']} resources)"]
