import io
import json
import os
import subprocess

import pytest

from secondkey.hooks import claude_code


@pytest.fixture(autouse=True)
def sk_home(tmp_path, monkeypatch):
    home = tmp_path / "skhome"
    monkeypatch.setenv("SECONDKEY_HOME", str(home))
    monkeypatch.setenv("SECONDKEY_USER", "tester")
    monkeypatch.delenv("SECONDKEY_POLICY", raising=False)
    monkeypatch.delenv("SECONDKEY_SLACK_WEBHOOK", raising=False)
    return home


@pytest.fixture
def project(tmp_path):
    p = tmp_path / "proj"
    p.mkdir()
    return p


def call_hook(command: str, cwd, tool: str = "Bash", tool_input: dict | None = None) -> dict:
    payload = {"session_id": "t", "cwd": str(cwd), "hook_event_name": "PreToolUse", "tool_name": tool,
               "tool_input": tool_input if tool_input is not None else {"command": command, "description": "x"}}
    out = io.StringIO()
    rc = claude_code.main(io.StringIO(json.dumps(payload)), out, io.StringIO())
    assert rc == 0
    text = out.getvalue()
    return json.loads(text)["hookSpecificOutput"] if text else {}


def decision_of(resp: dict) -> str:
    return resp.get("permissionDecision", "allow")


def git(cwd, *args):
    return subprocess.run(["git", "-C", str(cwd), *args], check=True, capture_output=True, text=True,
                          env={**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t",
                               "GIT_COMMITTER_EMAIL": "t@t"}).stdout.strip()
