"""The decision flow shared by every integration.

    classify → policy → deny
                      → allow  (snapshot first if the rule says so)
                      → ask    → already approved for this exact call? snapshot, then run
                               → otherwise create a held request, notify, optionally wait
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass, field
from typing import Any

from . import audit, notify
from .classify import Action, classify_tool
from .policy import Decision, Policy, load_policy
from .snapshots import plan as plan_snapshots
from .snapshots import take_all
from .store import Request, Snapshot, Store

VOLATILE_INPUT_KEYS = {"description", "timeout", "run_in_background", "dangerouslyDisableSandbox"}
QUIET_CATEGORIES = ("fs.read", "tool.", "shell.other", "git.read", "sql.read", "k8s.read", "tf.read", "cloud.read")


@dataclass
class GateResult:
    outcome: str                         # allow | deny | held | ask (native prompt)
    message: str                         # text for the agent
    decision: Decision
    request: Request | None = None
    snapshots: list[Snapshot] = field(default_factory=list)


def command_text(tool: str, tool_input: dict[str, Any]) -> str:
    if "command" in tool_input:
        return str(tool_input["command"])
    return f"{tool} " + json.dumps({k: v for k, v in tool_input.items() if k not in VOLATILE_INPUT_KEYS}, sort_keys=True)


def fingerprint(cwd: str, tool: str, tool_input: dict[str, Any]) -> str:
    stable = {k: v for k, v in tool_input.items() if k not in VOLATILE_INPUT_KEYS}
    if "command" in stable:
        stable["command"] = str(stable["command"]).strip()
    raw = json.dumps([os.path.realpath(cwd), tool, stable], sort_keys=True)
    return hashlib.sha256(raw.encode()).hexdigest()


def _categories(decision: Decision) -> list[str]:
    return [v.action.category for v in decision.verdicts]


def _quiet(decision: Decision) -> bool:
    return all(c.startswith(QUIET_CATEGORIES) for c in _categories(decision))


def _undo_hint(snaps: list[Snapshot]) -> str:
    if not snaps:
        return ""
    ids = " ".join(s.id for s in snaps)
    return f" Restore point{'s' if len(snaps) > 1 else ''} saved: {ids} (undo with `secondkey undo {snaps[0].id}`)."


def evaluate(*, source: str, tool: str, tool_input: dict[str, Any], cwd: str, env: dict[str, str] | None = None,
             policy: Policy | None = None, store: Store | None = None, wait: float | None = None,
             native_ask: bool | None = None) -> GateResult:
    policy = policy or load_policy(cwd)
    store = store or Store()
    actions = classify_tool(tool, tool_input, cwd, env)
    decision = policy.evaluate(actions)
    cmd = command_text(tool, tool_input)
    base = {"source": source, "tool": tool, "cwd": cwd, "command": cmd[:2000], "categories": _categories(decision)}

    if decision.decision == "deny":
        audit.record("deny", **base, reason=decision.reason)
        return GateResult("deny", f"SecondKey blocked this: {decision.reason} "
                                  "Do not retry it or look for another way to do the same thing; tell the user what you were trying to do.",
                          decision)

    if decision.decision == "allow":
        snaps: list[Snapshot] = []
        if decision.snapshot_actions:
            snaps, _skipped, failures = take_all(decision.snapshot_actions, None, policy, store)
            for f in failures:
                audit.record("snapshot_failed", **base, error=f)
        if snaps or not _quiet(decision):
            audit.record("allow", **base, snapshots=[s.id for s in snaps])
        return GateResult("allow", _undo_hint(snaps).strip(), decision, snapshots=snaps)

    # ask
    if native_ask is None:
        native_ask = str(policy.approval.get("via", "secondkey")) == "agent"
    if native_ask:
        return _native_ask(decision, policy, store, base)

    fp = fingerprint(cwd, tool, tool_input)
    grant = store.claim_grant(fp)
    if grant:
        return _run_approved(grant, decision, policy, store, base)

    denied = store.recent_denial(fp, policy.ttl_seconds)
    if denied:
        return _denied_message(denied, decision)

    protect = decision.snapshot_actions
    req, created = store.create_request(source=source, cwd=cwd, tool=tool, command=cmd, fingerprint=fp,
                                        actions=[a.to_dict() for a in protect], reason=decision.reason, impact=[])
    if created:
        impact, problems = plan_snapshots(protect, policy) if protect else ([], [])
        store.db.execute("UPDATE requests SET impact=? WHERE id=?", (json.dumps(impact + [f"not protected: {p}" for p in problems]), req.id))
        req = store.get_request(req.id)  # type: ignore[assignment]
        audit.record("hold", **base, request=req.id, reason=decision.reason, impact=req.impact)
        hook = policy.slack_webhook()
        if hook:
            notify.slack(hook, notify.approval_text(req, impact, problems))

    wait = policy.wait_seconds if wait is None else wait
    deadline = time.time() + max(0.0, wait)
    while wait > 0 and time.time() < deadline:
        cur = store.get_request(req.id)
        if cur and cur.status == "approved":
            grant = store.claim_grant(fp)
            if grant:
                return _run_approved(grant, decision, policy, store, base)
        if cur and cur.status == "denied":
            return _denied_message(cur, decision)
        time.sleep(1)

    cur = store.get_request(req.id) or req
    if cur.status == "denied":
        return _denied_message(cur, decision)
    return GateResult("held", _held_message(cur), decision, request=cur)


def _held_message(req: Request) -> str:
    lines = [f"SecondKey held this command for human approval (request {req.id}).",
             f"Why: {req.reason}."]
    if req.impact:
        lines.append("Impact: " + "; ".join(req.impact[:6]) + ".")
    if not any(i.startswith("not protected") for i in req.impact) and req.actions:
        lines.append("A restore point will be taken right before it runs, so it can be undone.")
    lines.append(f"Do not try to work around this or run an equivalent command. Ask the user to review it and run "
                 f"`secondkey approve {req.id}` (or `secondkey deny {req.id}`), then retry exactly the same command.")
    return " ".join(lines)


def _denied_message(req: Request, decision: Decision) -> GateResult:
    by = f" by {req.decided_by}" if req.decided_by else ""
    return GateResult("deny", f"SecondKey: a human denied this command{by} (request {req.id}). Do not retry it; "
                              "ask the user how they want to proceed.", decision, request=req)


def _run_approved(grant: Request, decision: Decision, policy: Policy, store: Store, base: dict[str, Any]) -> GateResult:
    actions = [Action.from_dict(a) for a in grant.actions]
    snaps: list[Snapshot] = []
    if actions and not grant.skip_snapshot:
        snaps, skipped, failures = take_all(actions, grant.id, policy, store)
        if failures and policy.require_snapshot:
            for s in snaps:
                store.db.execute("UPDATE snapshots SET status='unused' WHERE id=?", (s.id,))
            reason = "snapshot failed: " + "; ".join(failures)
            store.db.execute("UPDATE requests SET status='pending', reason=?, updated=? WHERE id=?",
                             (reason, time.time(), grant.id))
            audit.record("snapshot_failed", **base, request=grant.id, error=reason)
            return GateResult("deny", f"SecondKey: approved, but the restore point could not be taken ({'; '.join(failures)}), "
                                      f"so nothing was run. Tell the user. They can fix the problem and retry, or run "
                                      f"`secondkey approve {grant.id} --no-snapshot` to run it without a restore point.",
                              decision, request=grant)
    store.finish(grant.id, "executed", [s.id for s in snaps])
    audit.record("run_approved", **base, request=grant.id, approved_by=grant.decided_by,
                 snapshots=[s.id for s in snaps], without_snapshot=grant.skip_snapshot)
    msg = f"SecondKey: approved by {grant.decided_by or 'a human'} (request {grant.id}).{_undo_hint(snaps)}"
    return GateResult("allow", msg, decision, request=grant, snapshots=snaps)


def _native_ask(decision: Decision, policy: Policy, store: Store, base: dict[str, Any]) -> GateResult:
    """Snapshot now, then let the agent's own permission prompt ask the human."""
    snaps, _skipped, failures = take_all(decision.snapshot_actions, None, policy, store)
    audit.record("ask_agent_prompt", **base, reason=decision.reason, snapshots=[s.id for s in snaps], snapshot_failures=failures)
    parts = [f"SecondKey: {decision.reason}."]
    if snaps:
        parts.append(f"Restore point taken ({', '.join(s.id for s in snaps)}); if you approve and regret it, run `secondkey undo {snaps[0].id}`.")
    if failures:
        parts.append("WARNING: no restore point: " + "; ".join(failures) + ".")
    return GateResult("ask", " ".join(parts), decision, snapshots=snaps)
