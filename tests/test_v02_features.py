"""Guard rails, prune, Cursor hook, migrations, redaction and the stubbed MySQL / AWS / Docker providers."""

import io
import json
import os
import stat

import pytest

from secondkey import audit
from secondkey.classify import classify_shell
from secondkey.cli import main as cli
from secondkey.hooks import cursor
from secondkey.store import Store
from secondkey.util import redact

from .conftest import call_hook, decision_of


def cats(cmd, env=None, cwd="/tmp"):
    return [a.category for a in classify_shell(cmd, cwd, env or {})]


def fake_bin(dirpath, name, script):
    p = dirpath / name
    p.write_text("#!/bin/sh\n" + script)
    p.chmod(p.stat().st_mode | stat.S_IEXEC)
    return p


@pytest.fixture
def bin_dir(tmp_path, monkeypatch):
    d = tmp_path / "bin"
    d.mkdir()
    monkeypatch.setenv("PATH", f"{d}{os.pathsep}{os.environ['PATH']}")
    return d


# ---------------------------------------------------------------- guard rails

@pytest.mark.parametrize("cmd", [
    "secondkey approve req_1", "python3 -m secondkey deny req_1", "SECONDKEY_USER=boss secondkey approve req_1",
    "secondkey undo snap_1 --yes", "secondkey prune", "secondkey init --force",
    "sqlite3 ~/.secondkey/state.db 'update requests set status=1'", "rm -rf ~/.secondkey",
    "echo {} > .claude/settings.json", "cat evil > .claude/settings.local.json", "sed -i s/ask/allow/ .secondkey/policy.yaml",
    "cp x.yaml ./.secondkey/policy.yaml", "tee .cursor/hooks.json",
])
def test_agent_cannot_hold_the_second_key(cmd, project):
    r = call_hook(cmd, project)
    assert decision_of(r) == "deny", cmd
    assert "Only a human can turn the second key" in r["permissionDecisionReason"]


@pytest.mark.parametrize("cmd", ["secondkey pending", "secondkey check 'rm -rf x'", "cat .secondkey/policy.yaml",
                                 "git add .secondkey/policy.yaml", "secondkey log --verify"])
def test_agent_can_still_read(cmd, project):
    assert decision_of(call_hook(cmd, project)) == "allow"


def test_guard_cannot_be_disabled_by_policy(project):
    (project / ".git").mkdir()
    (project / ".secondkey").mkdir()
    (project / ".secondkey" / "policy.yaml").write_text("default: allow\nrules:\n  - match: '*'\n    action: allow\n")
    assert decision_of(call_hook("secondkey approve req_1", project)) == "deny"
    r = call_hook("", project, tool="Edit", tool_input={"file_path": str(project / ".claude" / "settings.json")})
    assert decision_of(r) == "deny"


def test_state_dir_is_private(sk_home):
    Store()
    assert oct(sk_home.stat().st_mode & 0o777) == "0o700"


# ---------------------------------------------------------------- prune

def _snapshot(project, name, age_days=0):
    f = project / name
    f.write_text("x" * 2000)
    r = call_hook(f"rm {name}", project)
    sid = r["additionalContext"].split("saved: ")[1].split(" ")[0]
    if age_days:
        Store().db.execute("UPDATE snapshots SET created = created - ? WHERE id = ?", (age_days * 86400, sid))
    return sid


def test_prune_by_age_keeps_newest(project, sk_home):
    old = _snapshot(project, "a.txt", age_days=30)
    new = _snapshot(project, "b.txt")
    assert cli(["prune", "--dry-run"]) == 0
    assert Store().get_snapshot(old).status == "ok"
    assert cli(["prune"]) == 0
    assert Store().get_snapshot(old).status == "pruned"
    assert not os.path.exists(Store().get_snapshot(old).path)
    assert Store().get_snapshot(new).status == "ok"
    assert cli(["undo", old, "--yes"]) == 1          # pruned: explains, doesn't crash
    assert any(e["event"] == "prune" for e in audit.entries())


def test_prune_by_size_and_never_the_newest(project):
    ids = [_snapshot(project, f"f{i}.txt") for i in range(3)]
    assert cli(["prune", "--older-than", "0", "--max-mb", "0.000001"]) == 0
    statuses = [Store().get_snapshot(i).status for i in ids]
    assert statuses == ["pruned", "pruned", "ok"]


def test_auto_prune_runs_at_most_daily(project, sk_home):
    _snapshot(project, "old.txt", age_days=40)
    marker = sk_home / ".last_prune"
    if marker.exists():
        marker.unlink()
    _snapshot(project, "new.txt")          # triggers auto-prune
    assert marker.exists()
    assert any(s.status == "pruned" for s in Store().list_snapshots())


# ---------------------------------------------------------------- Cursor

def cursor_call(payload):
    out = io.StringIO()
    assert cursor.main(io.StringIO(json.dumps(payload)), out, io.StringIO()) == 0
    return json.loads(out.getvalue())


def test_cursor_shell_flow(project):
    (project / "data").mkdir()
    (project / "data" / "x").write_text("1")
    base = {"hook_event_name": "beforeShellExecution", "workspace_roots": [str(project)], "cwd": str(project)}
    assert cursor_call({**base, "command": "ls"}) == {"permission": "allow"}
    r = cursor_call({**base, "command": "rm -rf data"})
    assert r["permission"] == "deny" and "secondkey approve req_" in r["user_message"]
    rid = r["agent_message"].split("(request ")[1].split(")")[0]
    cli(["approve", rid])
    r = cursor_call({**base, "command": "rm -rf data"})
    assert r["permission"] == "allow" and "snap_" in r["agent_message"]


def test_cursor_read_and_mcp(project):
    r = cursor_call({"hook_event_name": "beforeReadFile", "file_path": str(project / ".env"), "workspace_roots": [str(project)]})
    assert r["permission"] == "deny"
    r = cursor_call({"hook_event_name": "beforeMCPExecution", "tool_name": "delete_project", "server": "supabase",
                     "tool_input": "{\"id\": 1}", "workspace_roots": [str(project)]})
    assert r["permission"] == "deny" and "held" in r["agent_message"]


def test_cursor_fails_closed(project, monkeypatch):
    from secondkey import gate

    def boom(**k):
        raise RuntimeError("bug")
    monkeypatch.setattr(gate, "evaluate", boom)
    assert cursor_call({"hook_event_name": "beforeShellExecution", "command": "ls", "cwd": str(project)})["permission"] == "deny"
    out = io.StringIO()
    cursor.main(io.StringIO("garbage"), out, io.StringIO())
    assert json.loads(out.getvalue())["permission"] == "deny"


def test_init_cursor(project):
    (project / ".git").mkdir()
    hooks = project / ".cursor" / "hooks.json"
    hooks.parent.mkdir()
    hooks.write_text(json.dumps({"version": 1, "hooks": {"afterFileEdit": [{"command": "fmt"}]}}))
    assert cli(["-C", str(project), "init", "--agent", "cursor"]) == 0
    assert cli(["-C", str(project), "init", "--agent", "cursor"]) == 0
    data = json.loads(hooks.read_text())
    assert data["hooks"]["afterFileEdit"] == [{"command": "fmt"}]
    for ev in ("beforeShellExecution", "beforeReadFile", "beforeMCPExecution"):
        assert sum("secondkey hook cursor" in h["command"] for h in data["hooks"][ev]) == 1
    assert not (project / ".claude").exists() or "secondkey" not in (project / ".claude" / "settings.json").read_text()


# ---------------------------------------------------------------- migrations, runners, redaction

@pytest.mark.parametrize("cmd,cat", [
    ("npx prisma migrate reset --force", "db.reset"),
    ("pnpm dlx prisma db push --accept-data-loss", "db.reset"),
    ("alembic downgrade -1", "db.migrate_down"),
    ("uv run alembic downgrade base", "db.migrate_down"),
    ("python manage.py flush --no-input", "db.reset"),
    ("python manage.py migrate shop zero", "db.migrate_down"),
    ("bin/rails db:drop", "db.reset"),
    ("bundle exec rake db:rollback", "db.migrate_down"),
    ("npx sequelize-cli db:migrate:undo:all", "db.migrate_down"),
    ("supabase db reset", "db.reset"),
    ("goose down", "db.migrate_down"),
    ("npx prisma migrate dev", "shell.other"),
    ("alembic upgrade head", "shell.other"),
])
def test_migrations(cmd, cat):
    assert cats(cmd)[0] == cat


def test_migration_gets_whole_db_snapshot_with_database_url():
    a = classify_shell("alembic downgrade -1", "/tmp", {"DATABASE_URL": "postgresql://u@h/app"})[0]
    assert a.provider == "postgres" and a.target["tables"] == ["*"]
    assert classify_shell("alembic downgrade -1", "/tmp", {})[0].provider is None


def test_redaction(project):
    assert redact("mysql -u app -phunter2 shop") == "mysql -u app -p*** shop"
    assert redact("psql postgresql://app:hunter2@db/shop") == "psql postgresql://app:***@db/shop"
    assert redact("STRIPE_API_KEY=sk_live_1 node x.js") == "STRIPE_API_KEY=*** node x.js"
    call_hook('mysql -u app -phunter2 shop -e "DROP TABLE t"', project)
    assert "hunter2" not in audit.log_path().read_text()
    assert all("hunter2" not in r.command for r in Store().list_requests())


# ---------------------------------------------------------------- MySQL (stubbed client)

def test_mysql_snapshot_and_restore(project, bin_dir):
    state = bin_dir / "rows"
    state.write_text("120")
    fake_bin(bin_dir, "mysql", f"""
for a in "$@"; do last="$a"; done
case "$*" in
  *information_schema*) [ "$(cat {state})" != gone ] && echo orders ;;
  *COUNT*) cat {state} ;;
  *) cat > /dev/null; echo 120 > {state} ;;
esac
""")
    fake_bin(bin_dir, "mysqldump", 'echo "-- dump of $*"; echo "pw=$MYSQL_PWD"')
    cmd = 'mysql -u app -psecret shop -e "DROP TABLE orders"'
    r = call_hook(cmd, project)
    assert "orders: 120 rows" in r["permissionDecisionReason"]
    rid = r["permissionDecisionReason"].split("(request ")[1].split(")")[0]
    cli(["approve", rid])
    assert decision_of(call_hook(cmd, project)) == "allow"
    snap = Store().snapshots_for(rid)[0]
    dump = open(os.path.join(snap.path, "dump.sql")).read()
    assert "shop orders" in dump and "pw=secret" in dump and "-psecret" not in dump
    state.write_text("gone")
    assert cli(["undo", snap.id, "--yes"]) == 0
    assert state.read_text().strip() == "120"


# ---------------------------------------------------------------- AWS (stubbed CLI)

def test_aws_ebs(project, bin_dir, tmp_path):
    log = tmp_path / "aws.log"
    fake_bin(bin_dir, "aws", f"""echo "$*" >> {log}
case "$*" in
  *describe-volumes*) echo '{{"Volumes":[{{"Size":50,"VolumeType":"gp3","AvailabilityZone":"ap-south-1a"}}]}}' ;;
  *create-snapshot*) echo '{{"SnapshotId":"snap-0abc"}}' ;;
  *create-volume*) echo '{{"VolumeId":"vol-0new"}}' ;;
esac""")
    cmd = "aws ec2 delete-volume --volume-id vol-123 --region ap-south-1"
    r = call_hook(cmd, project)
    assert "50 GiB gp3 in ap-south-1a" in r["permissionDecisionReason"]
    rid = r["permissionDecisionReason"].split("(request ")[1].split(")")[0]
    cli(["approve", rid])
    call_hook(cmd, project)
    snap = Store().snapshots_for(rid)[0]
    assert snap.meta["snapshot_id"] == "snap-0abc"
    assert cli(["undo", snap.id, "--yes"]) == 0
    text = log.read_text()
    assert "create-snapshot --volume-id vol-123" in text and "--region ap-south-1" in text
    assert "create-volume --snapshot-id snap-0abc --availability-zone ap-south-1a" in text


def test_aws_s3_rm(project, bin_dir, tmp_path):
    log = tmp_path / "aws.log"
    fake_bin(bin_dir, "aws", f"""echo "$*" >> {log}
case "$*" in
  *summarize*) printf 'Total Objects: 3\\n   Total Size: 1200\\n' ;;
  *"s3 sync s3://"*) mkdir -p "$4"; echo data > "$4/a.json" ;;
esac""")
    cmd = "aws s3 rm s3://logs/2026/ --recursive"
    r = call_hook(cmd, project)
    assert "3 objects" in r["permissionDecisionReason"]
    rid = r["permissionDecisionReason"].split("(request ")[1].split(")")[0]
    cli(["approve", rid])
    call_hook(cmd, project)
    snap = Store().snapshots_for(rid)[0]
    assert os.path.exists(os.path.join(snap.path, "s3", "a.json"))
    assert cli(["undo", snap.id, "--yes"]) == 0
    assert f"s3 sync {snap.path}/s3 s3://logs/2026/" in log.read_text()


# ---------------------------------------------------------------- Docker (stubbed CLI)

def test_docker_volume_rm(project, bin_dir, tmp_path):
    log = tmp_path / "docker.log"
    fake_bin(bin_dir, "docker", f"""echo "$*" >> {log}
case "$1 $2" in
  "volume inspect") exit 0 ;;
esac""")
    cmd = "docker volume rm pgdata"
    r = call_hook(cmd, project)
    assert "1 volume will be archived: pgdata" in r["permissionDecisionReason"]
    rid = r["permissionDecisionReason"].split("(request ")[1].split(")")[0]
    cli(["approve", rid])
    call_hook(cmd, project)
    snap = Store().snapshots_for(rid)[0]
    assert cli(["undo", snap.id, "--yes", "--force"]) == 0
    text = log.read_text()
    assert "pgdata:/from:ro" in text and "tar czf /to/pgdata.tgz" in text
    assert "volume create pgdata" in text and "tar xzf /from/pgdata.tgz" in text


def test_doctor_runs(project):
    rc = cli(["-C", str(project), "doctor"])
    assert rc in (0, 1)


def test_missing_tool_hint(project, monkeypatch):
    monkeypatch.setenv("PATH", "/nonexistent")
    from secondkey.util import CommandError, run
    with pytest.raises(CommandError) as e:
        run(["pg_dump", "--version"])
    assert "install the PostgreSQL client tools" in str(e.value)


@pytest.mark.parametrize("cmd,agent,ok", [
    ("/usr/local/bin/secondkey hook claude-code", "claude-code", True),
    ('"C:/Users/abhis/.local/bin/secondkey.EXE" hook claude-code', "claude-code", True),
    ("'C:\\Users\\abhis\\.local\\bin\\secondkey.EXE' hook claude-code", "claude-code", True),
    ('"C:/Python312/python.exe" -m secondkey hook cursor', "cursor", True),
    ("secondkey hook cursor", "claude-code", False),
    ("prettier --write", "claude-code", False),
])
def test_hook_detection(cmd, agent, ok):
    from secondkey.cli import is_secondkey_hook
    assert is_secondkey_hook(cmd, agent) is ok


def test_init_repairs_old_windows_hook_path(project):
    (project / ".git").mkdir()
    settings = project / ".claude" / "settings.json"
    settings.parent.mkdir()
    old = "'C:\\Users\\abhis\\.local\\bin\\secondkey.EXE' hook claude-code"
    settings.write_text(json.dumps({"hooks": {"PreToolUse": [{"matcher": "*", "hooks": [{"type": "command", "command": old}]}]}}))
    assert cli(["-C", str(project), "init"]) == 0
    cmds = [h["command"] for g in json.loads(settings.read_text())["hooks"]["PreToolUse"] for h in g["hooks"]]
    assert len(cmds) == 1 and cmds[0] != old and "hook claude-code" in cmds[0]


def test_doctor_sees_windows_hook(project, capsys):
    (project / ".git").mkdir()
    settings = project / ".claude" / "settings.json"
    settings.parent.mkdir()
    win = '"C:/Users/abhis/.local/bin/secondkey.EXE" hook claude-code'
    settings.write_text(json.dumps({"hooks": {"PreToolUse": [{"matcher": "*", "hooks": [{"type": "command", "command": win}]}]}}, indent=2))
    from secondkey.cli import hook_installed
    assert hook_installed(settings, "claude-code")
    assert not hook_installed(settings, "cursor")
    cli(["-C", str(project), "doctor"])
    assert "Claude Code (project)" in capsys.readouterr().out
