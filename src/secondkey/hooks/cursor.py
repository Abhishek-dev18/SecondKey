"""Cursor hooks: beforeShellExecution, beforeReadFile and beforeMCPExecution.

Cursor's contract differs from Claude Code's: the command is at the top level
of the input, and every response must carry a "permission" field
("allow" | "deny" | "ask") plus optional user_message / agent_message.

Held commands are answered with "deny" (never "ask"): several Cursor versions
have run commands anyway when a hook answered "ask".
"""

from __future__ import annotations

import json
import os
import sys
import traceback
from typing import IO, Any

from .. import gate
from ..policy import PolicyError


def _emit(out: IO[str], permission: str, agent: str = "", user: str = "") -> None:
    body: dict[str, Any] = {"permission": permission}
    if agent:
        body["agent_message"] = agent
    if user:
        body["user_message"] = user
    out.write(json.dumps(body))
    out.flush()


def _call(data: dict[str, Any]) -> tuple[str, dict[str, Any], str]:
    event = data.get("hook_event_name", "beforeShellExecution")
    roots = data.get("workspace_roots") or []
    cwd = str(data.get("cwd") or (roots[0] if roots else os.getcwd()))
    if event == "beforeReadFile":
        return "Read", {"file_path": data.get("file_path") or data.get("path") or ""}, cwd
    if event == "beforeMCPExecution":
        server = data.get("server") or data.get("server_name") or "cursor"
        tool = data.get("tool_name") or "unknown"
        tool_input = data.get("tool_input")
        if isinstance(tool_input, str):
            try:
                tool_input = json.loads(tool_input)
            except json.JSONDecodeError:
                tool_input = {"raw": tool_input}
        return f"mcp__{server}__{tool}", tool_input or {}, cwd
    return "Bash", {"command": str(data.get("command") or "")}, cwd


def main(stdin: IO[str] | None = None, stdout: IO[str] | None = None, stderr: IO[str] | None = None) -> int:
    stdin, stdout, stderr = stdin or sys.stdin, stdout or sys.stdout, stderr or sys.stderr
    try:
        data = json.load(stdin)
    except (json.JSONDecodeError, ValueError) as e:
        _emit(stdout, "deny", f"SecondKey couldn't read the hook input ({e}).", "SecondKey hook input was unreadable; blocked to be safe.")
        return 0
    tool, tool_input, cwd = _call(data)
    try:
        result = gate.evaluate(source="cursor", tool=tool, tool_input=tool_input, cwd=cwd, native_ask=False)
    except PolicyError as e:
        _emit(stdout, "deny", f"SecondKey policy error: {e}. Ask the user to fix .secondkey/policy.yaml.", f"SecondKey policy error: {e}")
        return 0
    except Exception as e:  # noqa: BLE001 - must never fail open
        print("secondkey cursor hook error:\n" + traceback.format_exc(), file=stderr)
        _emit(stdout, "deny", f"SecondKey hit an internal error ({e}); this action was blocked to be safe.",
              f"SecondKey internal error: {e}. Run `secondkey doctor`.")
        return 0
    if result.outcome == "allow":
        _emit(stdout, "allow", result.message)
        return 0
    user = result.message
    if result.request is not None and result.outcome == "held":
        user = f"SecondKey is holding a command for you: `secondkey approve {result.request.id}` (or deny)."
    _emit(stdout, "deny", result.message, user)
    return 0
