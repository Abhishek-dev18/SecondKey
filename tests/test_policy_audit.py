import json

import pytest
import yaml

from secondkey import audit
from secondkey.classify import Action
from secondkey.policy import PolicyError, default_policy_text, load_policy, parse_policy


def test_default_policy_loads_and_decides():
    p = load_policy("/nonexistent-dir")
    assert p.source == "built-in default"
    d = lambda *cats: p.evaluate([Action(c, c) for c in cats]).decision  # noqa: E731
    assert d("shell.other") == "allow"
    assert d("sql.drop") == "ask"
    assert d("secrets.read") == "deny"
    assert d("shell.other", "sql.drop") == "ask"          # strictest part wins
    assert d("sql.drop", "secrets.read") == "deny"
    assert d("mcp.supabase.delete_project") == "ask"
    assert d("mcp.supabase.list_projects") == "allow"
    v = p.verdict(Action("fs.delete", "rm x"))
    assert (v.decision, v.snapshot) == ("allow", True)


def test_first_match_wins_and_project_file(tmp_path):
    (tmp_path / ".git").mkdir()
    (tmp_path / ".secondkey").mkdir()
    (tmp_path / ".secondkey" / "policy.yaml").write_text(yaml.safe_dump({
        "default": "ask",
        "rules": [{"match": "git.force_push", "action": "deny"}, {"match": "git.*", "action": "allow"}]}))
    sub = tmp_path / "src"
    sub.mkdir()
    p = load_policy(str(sub))
    assert p.source.endswith("policy.yaml")
    assert p.verdict(Action("git.force_push", "")).decision == "deny"
    assert p.verdict(Action("git.reset_hard", "")).decision == "allow"
    assert p.verdict(Action("shell.other", "")).decision == "ask"


def test_policy_errors():
    with pytest.raises(PolicyError):
        parse_policy({"rules": [{"match": "x", "action": "maybe"}]}, "t")
    with pytest.raises(PolicyError):
        parse_policy({"rules": [{"action": "deny"}]}, "t")
    with pytest.raises(PolicyError):
        parse_policy({"default": "sure"}, "t")


def test_env_interpolation(monkeypatch):
    p = parse_policy(yaml.safe_load(default_policy_text()), "d")
    assert p.slack_webhook() is None
    monkeypatch.setenv("SECONDKEY_SLACK_WEBHOOK", "https://hooks.slack.com/x")
    assert p.slack_webhook() == "https://hooks.slack.com/x"


def test_audit_chain_detects_tampering():
    for i in range(5):
        audit.record("hold", n=i)
    ok, n, _ = audit.verify()
    assert ok and n == 5
    lines = audit.log_path().read_text().splitlines()
    e = json.loads(lines[2])
    e["n"] = 99
    lines[2] = json.dumps(e, sort_keys=True)
    audit.log_path().write_text("\n".join(lines) + "\n")
    ok, _, msg = audit.verify()
    assert not ok and "line 3" in msg


def test_audit_deleted_line_detected():
    for i in range(3):
        audit.record("allow", n=i)
    lines = audit.log_path().read_text().splitlines()
    audit.log_path().write_text("\n".join([lines[0], lines[2]]) + "\n")
    ok, _, msg = audit.verify()
    assert not ok and "chain broken" in msg
