"""Policy loading and evaluation."""

from __future__ import annotations

import fnmatch
import os
import re
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import Any

import yaml

from .classify import Action
from .util import home

STRICTNESS = {"allow": 0, "ask": 1, "deny": 2}
GUARD_REASON = ("An agent can't approve its own requests, run undo, or change SecondKey's policy, hooks or state. "
                "Only a human can turn the second key")


class PolicyError(ValueError):
    pass


@dataclass
class Rule:
    match: list[str]
    action: str
    snapshot: bool
    reason: str | None = None

    def matches(self, category: str) -> bool:
        return any(fnmatch.fnmatchcase(category, pat) for pat in self.match)


@dataclass
class Verdict:
    action: Action
    decision: str
    snapshot: bool
    rule: str
    reason: str | None = None


@dataclass
class Decision:
    decision: str                      # allow | ask | deny
    verdicts: list[Verdict]
    reason: str = ""

    @property
    def snapshot_actions(self) -> list[Action]:
        return [v.action for v in self.verdicts if v.snapshot and v.decision != "deny"]


@dataclass
class Policy:
    rules: list[Rule]
    default: str = "allow"
    approval: dict[str, Any] = field(default_factory=dict)
    notify: dict[str, Any] = field(default_factory=dict)
    snapshots: dict[str, Any] = field(default_factory=dict)
    source: str = "built-in"

    @property
    def wait_seconds(self) -> float:
        return float(self.approval.get("wait_seconds", 0) or 0)

    @property
    def ttl_seconds(self) -> float:
        return float(self.approval.get("ttl_minutes", 15)) * 60

    @property
    def require_snapshot(self) -> bool:
        return bool(self.approval.get("require_snapshot", True))

    @property
    def retention_days(self) -> float:
        return float(self.snapshots.get("retention_days", 14))

    @property
    def max_total_bytes(self) -> int:
        return int(float(self.snapshots.get("max_total_mb", 5120)) * 1024 * 1024)

    @property
    def max_file_snapshot_bytes(self) -> int:
        return int(float(self.snapshots.get("max_file_snapshot_mb", 500)) * 1024 * 1024)

    def slack_webhook(self) -> str | None:
        raw = str(self.notify.get("slack_webhook") or "")
        val = _interpolate(raw).strip()
        return val or None

    def verdict(self, action: Action) -> Verdict:
        if action.category.startswith("secondkey.") and action.category != "secondkey.read":
            # Built-in guard, not configurable: the agent must never hold the second key.
            return Verdict(action, "deny", False, "built-in guard", GUARD_REASON)
        for i, rule in enumerate(self.rules):
            if rule.matches(action.category):
                return Verdict(action, rule.action, rule.snapshot, f"rules[{i}] {', '.join(rule.match)[:60]}", rule.reason)
        return Verdict(action, self.default, False, "default")

    def evaluate(self, actions: list[Action]) -> Decision:
        verdicts = [self.verdict(a) for a in actions]
        if not verdicts:
            return Decision("allow", [], "nothing to check")
        worst = max(verdicts, key=lambda v: STRICTNESS[v.decision])
        reason = worst.reason or (f"{worst.action.category} → {worst.decision}")
        return Decision(worst.decision, verdicts, reason)


def _interpolate(value: str) -> str:
    return re.sub(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}", lambda m: os.environ.get(m.group(1), ""), value)


def parse_policy(data: dict[str, Any], source: str) -> Policy:
    if not isinstance(data, dict):
        raise PolicyError(f"{source}: policy must be a mapping")
    default = str(data.get("default", "allow"))
    if default not in STRICTNESS:
        raise PolicyError(f"{source}: default must be allow, ask or deny")
    rules = []
    for i, r in enumerate(data.get("rules") or []):
        if not isinstance(r, dict) or "match" not in r or "action" not in r:
            raise PolicyError(f"{source}: rules[{i}] needs 'match' and 'action'")
        match = r["match"] if isinstance(r["match"], list) else [r["match"]]
        action = str(r["action"])
        if action not in STRICTNESS:
            raise PolicyError(f"{source}: rules[{i}].action must be allow, ask or deny (got {action!r})")
        snapshot = bool(r.get("snapshot", action == "ask"))
        rules.append(Rule([str(m) for m in match], action, snapshot, r.get("reason")))
    return Policy(rules, default, dict(data.get("approval") or {}), dict(data.get("notify") or {}),
                  dict(data.get("snapshots") or {}), source)


def default_policy_text() -> str:
    return resources.files("secondkey").joinpath("default_policy.yaml").read_text(encoding="utf-8")


def find_policy_file(cwd: str) -> Path | None:
    env = os.environ.get("SECONDKEY_POLICY")
    if env:
        return Path(env)
    d = Path(cwd).resolve()
    for p in [d, *d.parents]:
        cand = p / ".secondkey" / "policy.yaml"
        if cand.is_file():
            return cand
        if (p / ".git").exists():
            break
    user = home() / "policy.yaml"
    return user if user.is_file() else None


def load_policy(cwd: str, path: str | None = None) -> Policy:
    file = Path(path) if path else find_policy_file(cwd)
    if file is None:
        return parse_policy(yaml.safe_load(default_policy_text()), "built-in default")
    try:
        data = yaml.safe_load(file.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as e:
        raise PolicyError(f"{file}: {e}") from e
    return parse_policy(data, str(file))
