"""End-to-end gate behaviour through the Claude Code hook, using file snapshots."""

import io
import json
import subprocess

from secondkey import audit, gate
from secondkey.cli import main as cli
from secondkey.hooks import claude_code
from secondkey.store import Store

from .conftest import call_hook, decision_of


def make_tree(project):
    d = project / "data"
    (d / "nested").mkdir(parents=True)
    (d / "a.txt").write_text("alpha")
    (d / "nested" / "b.txt").write_text("beta")
    return d


def req_id(reason: str) -> str:
    return reason.split("(request ")[1].split(")")[0]


def test_full_loop_hold_approve_run_undo(project):
    data = make_tree(project)
    r = call_hook("rm -rf data", project)
    assert decision_of(r) == "deny"
    assert "held this command" in r["permissionDecisionReason"]
    rid = req_id(r["permissionDecisionReason"])
    assert "2 files" in r["permissionDecisionReason"]

    # retrying before approval does not create a second request
    r2 = call_hook("rm -rf data", project)
    assert req_id(r2["permissionDecisionReason"]) == rid
    assert len(Store().list_requests("pending")) == 1

    assert cli(["approve", rid]) == 0
    r3 = call_hook("rm -rf data", project)
    assert decision_of(r3) == "allow"
    assert "permissionDecision" not in r3            # never widens Claude Code's own permissions
    assert "Restore point saved" in r3["additionalContext"]

    # the approval is single-use
    r4 = call_hook("rm -rf data", project)
    assert decision_of(r4) == "deny"

    subprocess.run(["rm", "-rf", "data"], cwd=project, check=True)
    assert not data.exists()
    snap = Store().snapshots_for(rid)[0]
    assert cli(["undo", snap.id, "--yes"]) == 0
    assert (data / "a.txt").read_text() == "alpha"
    assert (data / "nested" / "b.txt").read_text() == "beta"
    events = [e["event"] for e in audit.entries()]
    assert events[:4] == ["hold", "approve", "run_approved", "hold"]
    assert "restore" in events
    assert audit.verify()[0]


def test_undo_refuses_to_clobber(project):
    make_tree(project)
    rid = req_id(call_hook("rm -rf data", project)["permissionDecisionReason"])
    cli(["approve", rid])
    call_hook("rm -rf data", project)
    snap = Store().snapshots_for(rid)[0]
    # data was NOT deleted, so restoring would overwrite it
    assert cli(["undo", snap.id, "--yes"]) == 1
    assert cli(["undo", snap.id, "--yes", "--force"]) == 0


def test_deny_by_human(project):
    make_tree(project)
    rid = req_id(call_hook("rm -rf data", project)["permissionDecisionReason"])
    assert cli(["deny", rid]) == 0
    r = call_hook("rm -rf data", project)
    assert decision_of(r) == "deny" and "human denied" in r["permissionDecisionReason"]


def test_secrets_denied_and_reads_allowed(project):
    r = call_hook("", project, tool="Read", tool_input={"file_path": str(project / ".env")})
    assert decision_of(r) == "deny" and "Blocked by policy" in r["permissionDecisionReason"]
    assert call_hook("ls -la", project) == {}
    assert call_hook("", project, tool="Read", tool_input={"file_path": str(project / "main.py")}) == {}


def test_allow_with_snapshot_for_single_file(project):
    f = project / "notes.txt"
    f.write_text("keep me")
    r = call_hook("rm notes.txt", project)
    assert decision_of(r) == "allow" and "snap_" in r["additionalContext"]
    f.unlink()
    sid = r["additionalContext"].split("saved: ")[1].split(" ")[0]
    assert cli(["undo", sid, "--yes"]) == 0
    assert f.read_text() == "keep me"


def test_snapshot_failure_blocks_and_can_be_overridden(project, monkeypatch):
    make_tree(project)
    rid = req_id(call_hook("rm -rf data", project)["permissionDecisionReason"])
    cli(["approve", rid])
    from secondkey.snapshots import files

    def boom(*a, **k):
        raise OSError("disk full")
    monkeypatch.setattr(files, "archive", boom)
    r = call_hook("rm -rf data", project)
    assert decision_of(r) == "deny" and "could not be taken" in r["permissionDecisionReason"]
    assert Store().get_request(rid).status == "pending"
    assert cli(["approve", rid, "--no-snapshot"]) == 0
    r = call_hook("rm -rf data", project)
    assert decision_of(r) == "allow"


def test_wait_for_approval(project):
    make_tree(project)
    store = Store()
    # pre-create and approve, then evaluate with a wait: the grant is picked up
    res = gate.evaluate(source="t", tool="Bash", tool_input={"command": "rm -rf data"}, cwd=str(project), wait=0)
    assert res.outcome == "held"
    store.decide(res.request.id, True, "lead", 600)
    res2 = gate.evaluate(source="t", tool="Bash", tool_input={"command": "rm -rf data"}, cwd=str(project), wait=2)
    assert res2.outcome == "allow" and res2.snapshots


def test_agent_prompt_mode(project):
    make_tree(project)
    (project / ".secondkey").mkdir()
    from secondkey.policy import default_policy_text
    (project / ".secondkey" / "policy.yaml").write_text(default_policy_text().replace("via: secondkey", "via: agent"))
    (project / ".git").mkdir()
    r = call_hook("rm -rf data", project)
    assert r["permissionDecision"] == "ask"
    assert "secondkey undo snap_" in r["permissionDecisionReason"]


def test_hook_never_crashes_open(project, monkeypatch):
    def boom(**k):
        raise RuntimeError("bug")
    monkeypatch.setattr(gate, "evaluate", boom)
    r = call_hook("rm -rf /", project)
    assert r["permissionDecision"] == "ask" and "internal error" in r["permissionDecisionReason"]
    out = io.StringIO()
    claude_code.main(io.StringIO("not json"), out, io.StringIO())
    assert json.loads(out.getvalue())["hookSpecificOutput"]["permissionDecision"] == "ask"


def test_exec_wrapper(project, capsys):
    assert cli(["-C", str(project), "exec", "--", "echo", "hi"]) == 0
    assert cli(["-C", str(project), "exec", "--", "cat .env"]) == 126
    make_tree(project)
    assert cli(["-C", str(project), "exec", "--wait", "0", "--", "rm -rf data"]) == 3
    assert (project / "data").exists()


def test_init_installs_hook_idempotently(project):
    (project / ".git").mkdir()
    settings = project / ".claude" / "settings.json"
    settings.parent.mkdir()
    settings.write_text(json.dumps({"permissions": {"allow": ["Bash(npm test)"]},
                                    "hooks": {"PreToolUse": [{"matcher": "Edit", "hooks": [{"type": "command", "command": "fmt"}]}]}}))
    assert cli(["-C", str(project), "init"]) == 0
    assert cli(["-C", str(project), "init"]) == 0
    data = json.loads(settings.read_text())
    assert data["permissions"] == {"allow": ["Bash(npm test)"]}
    cmds = [h["command"] for g in data["hooks"]["PreToolUse"] for h in g["hooks"]]
    assert cmds[0] == "fmt" and sum("hook claude-code" in c for c in cmds) == 1
    assert (project / ".secondkey" / "policy.yaml").exists()
