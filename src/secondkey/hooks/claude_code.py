"""Claude Code PreToolUse hook.

Reads the hook JSON on stdin and answers with a permission decision:

* allow  -> no output, so Claude Code's normal permission flow still applies
            (SecondKey never widens what Claude Code would allow on its own)
* deny / held -> permissionDecision "deny" with the reason shown to Claude
* ask (approval.via: agent) -> permissionDecision "ask" so Claude Code prompts

If SecondKey itself fails, it answers "ask" instead of crashing: a crashing
hook is treated as a non-blocking error and the tool would simply run.
"""

from __future__ import annotations

import json
import os
import sys
import traceback
from typing import IO

from .. import gate
from ..policy import PolicyError


def _emit(out: IO[str], decision: str | None, reason: str = "", context: str = "") -> None:
    spec: dict = {"hookEventName": "PreToolUse"}
    if decision:
        spec["permissionDecision"] = decision
        spec["permissionDecisionReason"] = reason
    if context:
        spec["additionalContext"] = context
    out.write(json.dumps({"hookSpecificOutput": spec}))
    out.flush()


def main(stdin: IO[str] | None = None, stdout: IO[str] | None = None, stderr: IO[str] | None = None) -> int:
    stdin, stdout, stderr = stdin or sys.stdin, stdout or sys.stdout, stderr or sys.stderr
    try:
        data = json.load(stdin)
    except (json.JSONDecodeError, ValueError) as e:
        _emit(stdout, "ask", f"SecondKey couldn't read the hook input ({e}); please review this action yourself.")
        return 0
    if data.get("hook_event_name", "PreToolUse") != "PreToolUse":
        return 0
    tool = str(data.get("tool_name") or "")
    tool_input = data.get("tool_input") or {}
    cwd = str(data.get("cwd") or os.getcwd())
    try:
        result = gate.evaluate(source="claude-code", tool=tool, tool_input=tool_input, cwd=cwd)
    except PolicyError as e:
        _emit(stdout, "ask", f"SecondKey policy error: {e}. Please review this action yourself.")
        return 0
    except Exception as e:  # noqa: BLE001 - must never crash open
        print("secondkey hook error:\n" + traceback.format_exc(), file=stderr)
        _emit(stdout, "ask", f"SecondKey hit an internal error ({e.__class__.__name__}: {e}). Please review this action yourself.")
        return 0

    if result.outcome == "allow":
        if result.message:
            _emit(stdout, None, context=result.message)
        return 0
    if result.outcome == "ask":
        _emit(stdout, "ask", result.message)
        return 0
    _emit(stdout, "deny", result.message)
    return 0
