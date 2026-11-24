"""Git snapshots: pin commits with refs under refs/secondkey/ so nothing is garbage-collected."""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

from ..classify import Action
from ..policy import Policy
from ..store import Snapshot
from ..util import CommandError, run
from .base import NothingToProtect, Provider, RestoreError, SnapshotUnavailable
from .files import archive, measure, unarchive


def git(repo: str, *args: str, check: bool = True) -> str:
    return run(["git", "-C", repo, *args], check=check).stdout.strip()


def _repo_root(repo: str) -> str:
    try:
        return git(repo, "rev-parse", "--show-toplevel")
    except CommandError as e:
        raise SnapshotUnavailable(f"not a git repository: {repo}") from e


def _head(repo: str) -> str | None:
    out = run(["git", "-C", repo, "rev-parse", "--verify", "-q", "HEAD"], check=False)
    return out.stdout.strip() or None


def _branch(repo: str) -> str | None:
    out = run(["git", "-C", repo, "symbolic-ref", "--short", "-q", "HEAD"], check=False)
    return out.stdout.strip() or None


def _push_targets(repo: str, target: dict[str, Any]) -> tuple[str, list[str]]:
    remote = target.get("remote") or "origin"
    branches = []
    for ref in target.get("refs") or []:
        dst = ref.split(":", 1)[-1] if ":" in ref else ref
        dst = re.sub(r"^refs/heads/", "", dst.lstrip("+"))
        if dst and dst != "HEAD":
            branches.append(dst)
        elif dst == "HEAD" and _branch(repo):
            branches.append(_branch(repo))  # type: ignore[arg-type]
    if not branches:
        cur = _branch(repo)
        if not cur:
            raise SnapshotUnavailable("can't tell which branch is being pushed (detached HEAD)")
        branches = [cur]
    return remote, branches


def _clean_candidates(repo: str, target: dict[str, Any]) -> list[str]:
    args = ["clean", "-n"]
    if target.get("dirs"):
        args.append("-d")
    if target.get("ignored"):
        args.append("-x")
    out = git(repo, *args)
    root = _repo_root(repo)
    files = []
    for line in out.splitlines():
        if line.startswith("Would remove "):
            files.append(os.path.join(repo, line[len("Would remove "):].rstrip("/")))
    return [f for f in files if os.path.abspath(f).startswith(root)]


class GitProvider(Provider):
    name = "git"

    def plan(self, action: Action, policy: Policy) -> list[str]:
        t, cat = action.target, action.category
        repo = t.get("repo") or os.getcwd()
        _repo_root(repo)
        if cat in ("git.force_push", "git.delete_remote_branch"):
            remote, branches = _push_targets(repo, t)
            return [f"{remote}/{b} will be pinned before it is overwritten" for b in branches]
        if cat == "git.reset_hard":
            dirty = git(repo, "status", "--porcelain", "--untracked-files=no")
            n = len([ln for ln in dirty.splitlines() if ln.strip()])
            return [f"HEAD {(_head(repo) or 'none')[:8]} and {n} uncommitted change{'s' if n != 1 else ''} will be saved"]
        if cat == "git.clean":
            files = _clean_candidates(repo, t)
            total, count, _ = measure(files)
            if total > policy.max_file_snapshot_bytes:
                raise SnapshotUnavailable("untracked files are over the file snapshot limit")
            return [f"{len(files)} untracked path{'s' if len(files) != 1 else ''} ({count} files) will be archived"]
        if cat == "git.branch_delete":
            return [f"branch {b} will be pinned" for b in t.get("branches") or []]
        return [f"HEAD {(_head(repo) or 'none')[:8]} and working-tree changes will be saved"]

    def take(self, action: Action, dest: Path, policy: Policy) -> tuple[str, dict[str, Any]]:
        t, cat = action.target, action.category
        repo = _repo_root(t.get("repo") or os.getcwd())
        sid = dest.name
        meta: dict[str, Any] = {"repo": repo, "category": cat, "head": _head(repo), "branch": _branch(repo)}

        if cat in ("git.force_push", "git.delete_remote_branch"):
            remote, branches = _push_targets(repo, t)
            pinned = []
            for b in branches:
                ref = f"refs/secondkey/{sid}/remote/{b}"
                ls = git(repo, "ls-remote", remote, f"refs/heads/{b}")
                sha = ls.split()[0] if ls else None
                if sha:
                    git(repo, "fetch", "--no-tags", "-q", remote, f"+refs/heads/{b}:{ref}")
                pinned.append({"branch": b, "sha": sha, "ref": ref if sha else None})
            meta.update(remote=remote, branches=pinned)
            label = ", ".join(f"{remote}/{p['branch']}@{(p['sha'] or 'new')[:8]}" for p in pinned)
            return label, meta

        if cat == "git.branch_delete":
            pinned = []
            for b in t.get("branches") or []:
                sha = run(["git", "-C", repo, "rev-parse", "--verify", "-q", f"refs/heads/{b}"], check=False).stdout.strip()
                if sha:
                    git(repo, "update-ref", f"refs/secondkey/{sid}/branch/{b}", sha)
                    pinned.append({"branch": b, "sha": sha})
            if not pinned:
                raise NothingToProtect("none of the branches exist")
            meta["branches"] = pinned
            return ", ".join(f"branch {p['branch']}@{p['sha'][:8]}" for p in pinned), meta

        if cat == "git.clean":
            files = _clean_candidates(repo, t)
            if not files:
                raise NothingToProtect("git clean would not remove anything")
            meta["entries"] = archive(files, dest)
            return f"{len(files)} untracked paths in {os.path.basename(repo)}", meta

        # reset --hard, checkout -- ., restore, stash drop/clear, rebase and other rewrites
        if meta["head"]:
            git(repo, "update-ref", f"refs/secondkey/{sid}/head", meta["head"])
        stash = git(repo, "stash", "create") if meta["head"] else ""
        if stash:
            git(repo, "update-ref", f"refs/secondkey/{sid}/worktree", stash)
        meta["worktree"] = stash or None
        stashes = git(repo, "stash", "list", "--format=%H%x09%gs", check=False)
        meta["stashes"] = [ln.split("\t", 1) for ln in stashes.splitlines() if ln.strip()]
        for i, (sha, _msg) in enumerate(meta["stashes"]):
            git(repo, "update-ref", f"refs/secondkey/{sid}/stash/{i}", sha)
        label = f"{os.path.basename(repo)} HEAD {(meta['head'] or 'none')[:8]}" + (" + uncommitted changes" if stash else "")
        return label, meta

    def describe_restore(self, snap: Snapshot, mode: str | None = None) -> list[str]:
        m, cat = snap.meta, snap.meta["category"]
        if cat in ("git.force_push", "git.delete_remote_branch"):
            return [f"force-push {m['remote']}/{b['branch']} back to {b['sha'][:8]}" if b["sha"]
                    else f"{m['remote']}/{b['branch']} did not exist before; leave it" for b in m["branches"]]
        if cat == "git.branch_delete":
            return [f"recreate branch {b['branch']} at {b['sha'][:8]}" for b in m["branches"]]
        if cat == "git.clean":
            return [f"put back {len(m['entries'])} untracked paths"]
        lines = [f"reset {os.path.basename(m['repo'])} to {(m['head'] or '')[:8]}"]
        if m.get("worktree"):
            lines.append("re-apply the uncommitted changes saved before the command")
        if m.get("stashes"):
            lines.append(f"re-store any of the {len(m['stashes'])} saved stash entries that are missing")
        lines.append("your current uncommitted changes are saved first, so this is itself undoable")
        return lines

    def restore(self, snap: Snapshot, mode: str | None = None, force: bool = False) -> list[str]:
        m, cat, repo = snap.meta, snap.meta["category"], snap.meta["repo"]
        if not os.path.isdir(repo):
            raise RestoreError(f"repository {repo} no longer exists")
        out: list[str] = []
        if cat in ("git.force_push", "git.delete_remote_branch"):
            for b in m["branches"]:
                if not b["sha"]:
                    out.append(f"{m['remote']}/{b['branch']} was new; left as is")
                    continue
                git(repo, "push", "--force", m["remote"], f"{b['ref']}:refs/heads/{b['branch']}")
                out.append(f"{m['remote']}/{b['branch']} restored to {b['sha'][:8]}")
            return out
        if cat == "git.branch_delete":
            for b in m["branches"]:
                exists = run(["git", "-C", repo, "rev-parse", "--verify", "-q", f"refs/heads/{b['branch']}"], check=False).stdout.strip()
                if exists and exists != b["sha"] and not force:
                    raise RestoreError(f"branch {b['branch']} exists again at {exists[:8]}; use --force to move it")
                if exists:
                    git(repo, "branch", "-f", b["branch"], b["sha"])
                else:
                    git(repo, "branch", b["branch"], b["sha"])
                out.append(f"branch {b['branch']} restored at {b['sha'][:8]}")
            return out
        if cat == "git.clean":
            return [f"restored {p}" for p in unarchive(snap.path, m["entries"], force)]

        safety = git(repo, "stash", "create")
        if safety:
            git(repo, "update-ref", f"refs/secondkey/{snap.id}/before-undo", safety)
            out.append(f"saved your current uncommitted changes as {safety[:8]} (refs/secondkey/{snap.id}/before-undo)")
        if m["head"]:
            git(repo, "reset", "-q", "--hard", m["head"])
            out.append(f"HEAD reset to {m['head'][:8]}")
        if m.get("worktree"):
            git(repo, "stash", "apply", "-q", m["worktree"])
            out.append("uncommitted changes re-applied")
        current = {ln.strip() for ln in git(repo, "stash", "list", "--format=%H", check=False).splitlines()}
        for sha, msg in reversed(m.get("stashes") or []):
            if sha not in current:
                git(repo, "stash", "store", "-m", msg or "restored by secondkey", sha)
                out.append(f"stash restored: {msg}")
        return out

    def cleanup(self, snap: Snapshot) -> None:
        repo = snap.meta.get("repo")
        if not repo or not os.path.isdir(repo):
            return
        refs = run(["git", "-C", repo, "for-each-ref", "--format=%(refname)", f"refs/secondkey/{snap.id}/"], check=False).stdout
        for ref in refs.split():
            run(["git", "-C", repo, "update-ref", "-d", ref], check=False)
