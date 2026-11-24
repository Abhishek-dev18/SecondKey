from secondkey.cli import main as cli
from secondkey.store import Store

from .conftest import call_hook, decision_of, git


def repo_with_remote(tmp_path):
    remote = tmp_path / "remote.git"
    git(tmp_path, "init", "-q", "--bare", "-b", "main", str(remote))
    work = tmp_path / "work"
    git(tmp_path, "clone", "-q", str(remote), str(work))
    git(work, "checkout", "-q", "-b", "main")
    for i in range(3):
        (work / "f.txt").write_text(f"v{i}")
        git(work, "add", ".")
        git(work, "commit", "-q", "-m", f"c{i}")
    git(work, "push", "-q", "origin", "main")
    return remote, work


def approve_and_run(cmd, cwd):
    r = call_hook(cmd, cwd)
    assert decision_of(r) == "deny", r
    rid = r["permissionDecisionReason"].split("(request ")[1].split(")")[0]
    assert cli(["approve", rid]) == 0
    r = call_hook(cmd, cwd)
    assert decision_of(r) == "allow", r
    git(cwd, *cmd.split()[1:])
    return rid


def test_force_push_undo(tmp_path):
    remote, work = repo_with_remote(tmp_path)
    good = git(work, "rev-parse", "HEAD")
    git(work, "reset", "-q", "--hard", "HEAD~2")
    rid = approve_and_run("git push --force origin main", work)
    assert git(remote, "rev-parse", "main") != good
    assert cli(["undo", rid, "--yes"]) == 0
    assert git(remote, "rev-parse", "main") == good


def test_reset_hard_undo_restores_uncommitted_work(tmp_path):
    _, work = repo_with_remote(tmp_path)
    head = git(work, "rev-parse", "HEAD")
    (work / "f.txt").write_text("precious uncommitted edit")
    rid = approve_and_run("git reset --hard HEAD~1", work)
    assert (work / "f.txt").read_text() == "v1"
    assert cli(["undo", rid, "--yes"]) == 0
    assert git(work, "rev-parse", "HEAD") == head
    assert (work / "f.txt").read_text() == "precious uncommitted edit"


def test_branch_delete_undo(tmp_path):
    _, work = repo_with_remote(tmp_path)
    git(work, "branch", "feature")
    sha = git(work, "rev-parse", "feature")
    rid = approve_and_run("git branch -D feature", work)
    assert cli(["undo", rid, "--yes"]) == 0
    assert git(work, "rev-parse", "feature") == sha


def test_git_clean_undo(tmp_path):
    _, work = repo_with_remote(tmp_path)
    (work / "scratch").mkdir()
    (work / "scratch" / "notes.md").write_text("ideas")
    (work / "todo.txt").write_text("todo")
    rid = approve_and_run("git clean -fd", work)
    assert not (work / "todo.txt").exists()
    assert cli(["undo", rid, "--yes"]) == 0
    assert (work / "scratch" / "notes.md").read_text() == "ideas"
    assert (work / "todo.txt").read_text() == "todo"
    snaps = Store().snapshots_for(rid)
    assert snaps and snaps[0].status == "restored"
