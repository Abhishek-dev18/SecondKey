"""secondkey command-line interface."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import shlex
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

from . import __version__, audit, gate
from . import snapshots as snapmod
from .classify import classify_tool
from .policy import PolicyError, default_policy_text, load_policy
from .store import Store
from .util import home, whoami

USE_COLOR = sys.stdout.isatty() and not os.environ.get("NO_COLOR")


def c(text: str, code: str) -> str:
    return f"\033[{code}m{text}\033[0m" if USE_COLOR else text


def orange(t: str) -> str: return c(t, "38;5;208")
def green(t: str) -> str: return c(t, "32")
def red(t: str) -> str: return c(t, "31")
def dim(t: str) -> str: return c(t, "2")
def bold(t: str) -> str: return c(t, "1")


DECISION_COLOR = {"allow": green, "ask": orange, "deny": red}


def ago(ts: float | None) -> str:
    if not ts:
        return "-"
    s = int(dt.datetime.now().timestamp() - ts)
    if s < 60:
        return f"{s}s ago"
    if s < 3600:
        return f"{s // 60}m ago"
    if s < 86400:
        return f"{s // 3600}h ago"
    return dt.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M")


def project_root(start: str) -> Path:
    d = Path(start).resolve()
    for p in [d, *d.parents]:
        if (p / ".git").exists():
            return p
    return d


# ------------------------------------------------------------------ init

HOOK_MARK = "secondkey hook claude-code"


def hook_command(agent: str) -> str:
    """The command an agent should run for the hook.

    On Windows, paths are written with forward slashes and double quotes, which work
    in Git Bash (what Claude Code uses on Windows), cmd.exe and PowerShell alike.
    """
    exe = shutil.which("secondkey")
    if os.name == "nt":
        if exe:
            return f'"{exe.replace(os.sep, "/")}" hook {agent}'
        return f'"{sys.executable.replace(os.sep, "/")}" -m secondkey hook {agent}'
    if exe:
        return f"{shlex.quote(exe)} hook {agent}"
    return f"{shlex.quote(sys.executable)} -m secondkey hook {agent}"


def install_claude_hook(settings_path: Path) -> str:
    settings_path.parent.mkdir(parents=True, exist_ok=True)
    data: dict[str, Any] = {}
    if settings_path.exists():
        try:
            data = json.loads(settings_path.read_text() or "{}")
        except json.JSONDecodeError as e:
            raise SystemExit(f"{settings_path} is not valid JSON ({e}); fix it and re-run init.")
    hooks = data.setdefault("hooks", {})
    pre = hooks.setdefault("PreToolUse", [])
    for group in pre:
        for h in group.get("hooks", []):
            if HOOK_MARK in str(h.get("command", "")):
                return "already installed"
    command = hook_command("claude-code")
    pre.append({"matcher": "*", "hooks": [{"type": "command", "command": command, "timeout": 900}]})
    tmp = settings_path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(data, indent=2) + "\n")
    tmp.replace(settings_path)
    return "installed"


CURSOR_EVENTS = ("beforeShellExecution", "beforeReadFile", "beforeMCPExecution")


def install_cursor_hook(hooks_path: Path) -> str:
    hooks_path.parent.mkdir(parents=True, exist_ok=True)
    data: dict[str, Any] = {"version": 1, "hooks": {}}
    if hooks_path.exists():
        try:
            data = json.loads(hooks_path.read_text() or "{}")
        except json.JSONDecodeError as e:
            raise SystemExit(f"{hooks_path} is not valid JSON ({e}); fix it and re-run init.")
    data.setdefault("version", 1)
    hooks = data.setdefault("hooks", {})
    command = hook_command("cursor")
    added = 0
    for ev in CURSOR_EVENTS:
        entries = hooks.setdefault(ev, [])
        if not any("secondkey hook cursor" in str(e.get("command", "")) for e in entries):
            entries.append({"command": command, "timeout": 900})
            added += 1
    tmp = hooks_path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(data, indent=2) + "\n")
    tmp.replace(hooks_path)
    return "installed" if added else "already installed"


def cmd_init(a: argparse.Namespace) -> int:
    root = project_root(a.cwd)
    if a.scope == "user":
        policy_path, settings = home() / "policy.yaml", Path.home() / ".claude" / "settings.json"
        cursor_hooks = Path.home() / ".cursor" / "hooks.json"
    else:
        policy_path, settings = root / ".secondkey" / "policy.yaml", root / ".claude" / "settings.json"
        cursor_hooks = root / ".cursor" / "hooks.json"
    policy_path.parent.mkdir(parents=True, exist_ok=True)
    if policy_path.exists() and not a.force:
        print(f"policy     {policy_path} {dim('(kept existing; --force to overwrite)')}")
    else:
        text = default_policy_text()
        if a.via_agent:
            text = text.replace("via: secondkey", "via: agent")
        policy_path.write_text(text)
        print(f"policy     {policy_path} {green('written')}")
    if not a.no_hook:
        agents = a.agent or ["claude-code"]
        if "claude-code" in agents:
            print(f"hook       {settings} {green(install_claude_hook(settings))}")
        if "cursor" in agents:
            print(f"hook       {cursor_hooks} {green(install_cursor_hook(cursor_hooks))}")
    print(f"state      {home()}")
    print()
    print("Next: start Claude Code in this project. Try asking it to run")
    example = 'psql $DB -c "DROP TABLE x"'
    print(f"  {bold('rm -rf ./some-folder')}  or  {bold(example)}")
    print(f"and approve with {bold('secondkey pending')} / {bold('secondkey approve <id>')}.")
    preview = 'secondkey check "<command>"'
    print(f"Preview any command first: {bold(preview)}")
    return 0


# ------------------------------------------------------------------ check / exec / hook

def cmd_check(a: argparse.Namespace) -> int:
    command = " ".join(a.command)
    policy = load_policy(a.cwd, a.policy)
    tool_input = json.loads(command) if a.tool != "Bash" else {"command": command}
    actions = classify_tool(a.tool, tool_input, a.cwd)
    decision = policy.evaluate(actions)
    impact, problems = ([], [])
    if decision.decision != "deny" and decision.snapshot_actions and not a.no_probe:
        impact, problems = snapmod.plan(decision.snapshot_actions, policy)
    if a.json:
        print(json.dumps({"decision": decision.decision, "reason": decision.reason, "policy": policy.source,
                          "actions": [{**v.action.to_dict(), "decision": v.decision, "snapshot": v.snapshot, "rule": v.rule}
                                      for v in decision.verdicts], "impact": impact, "not_protected": problems}, indent=2))
        return 0
    color = DECISION_COLOR[decision.decision]
    print(f"{bold(color(decision.decision.upper()))}  {dim('policy: ' + policy.source)}")
    for v in decision.verdicts:
        snap = " + snapshot" if v.snapshot and v.decision != "deny" else ""
        print(f"  {DECISION_COLOR[v.decision](v.decision):>5}{snap}  {v.action.category:<24} {v.action.summary}")
    for line in impact:
        print(f"  impact   {line}")
    for p in problems:
        print(f"  {orange('not protected')}  {p}")
    return 0


def cmd_exec(a: argparse.Namespace) -> int:
    command = " ".join(a.command) if len(a.command) > 1 else (a.command[0] if a.command else "")
    if not command:
        print("usage: secondkey exec -- <command>", file=sys.stderr)
        return 2
    policy = load_policy(a.cwd, a.policy)
    wait = a.wait if a.wait is not None else max(policy.wait_seconds, 300.0)
    if wait > 0 and sys.stderr.isatty():
        print(dim(f"secondkey: checking… (waiting up to {int(wait)}s if approval is needed)"), file=sys.stderr)
    result = gate.evaluate(source="exec", tool="Bash", tool_input={"command": command}, cwd=a.cwd, policy=policy,
                           wait=wait, native_ask=False)
    if result.outcome == "deny":
        print(red(result.message), file=sys.stderr)
        return 126
    if result.outcome == "held":
        print(orange(result.message), file=sys.stderr)
        return 3
    if result.message:
        print(dim(result.message), file=sys.stderr)
    return subprocess.run(command, shell=True, cwd=a.cwd).returncode


def cmd_hook(a: argparse.Namespace) -> int:
    if a.agent == "cursor":
        from .hooks import cursor
        return cursor.main()
    from .hooks import claude_code
    return claude_code.main()


# ------------------------------------------------------------------ requests

def _print_request(r: Any, verbose: bool = False) -> None:
    status_color = {"pending": orange, "approved": green, "executed": green, "denied": red}.get(r.status, dim)
    print(f"{bold(r.id)}  {status_color(r.status)}  {dim(ago(r.created))}  {dim(r.source)}  {dim(r.cwd)}")
    print(f"  {r.command if verbose else r.command[:200]}")
    if r.reason:
        print(f"  {dim('why:')} {r.reason}")
    for i in r.impact:
        print(f"  {dim('impact:')} {i}")
    if r.decided_by:
        print(f"  {dim('decided by')} {r.decided_by} {dim(ago(r.decided_at))}")
    if r.snapshot_ids:
        print(f"  {dim('snapshots:')} {' '.join(r.snapshot_ids)}")


def cmd_pending(a: argparse.Namespace) -> int:
    store = Store()
    reqs = store.list_requests(None if a.all else "pending", a.limit)
    if not reqs:
        print("No requests waiting for approval." if not a.all else "No requests yet.")
        return 0
    for r in reqs:
        _print_request(r)
        print()
    if not a.all:
        print(dim("approve: secondkey approve <id>    deny: secondkey deny <id>"))
    return 0


def cmd_show(a: argparse.Namespace) -> int:
    r = Store().get_request(a.id)
    if not r:
        print(f"no request {a.id}", file=sys.stderr)
        return 1
    _print_request(r, verbose=True)
    return 0


def _decide(a: argparse.Namespace, approve: bool) -> int:
    store = Store()
    r = store.get_request(a.id)
    if not r:
        print(f"no request {a.id}", file=sys.stderr)
        return 1
    policy = load_policy(r.cwd)
    by = a.by or whoami()
    try:
        r = store.decide(a.id, approve, by, policy.ttl_seconds, skip_snapshot=getattr(a, "no_snapshot", False))
    except ValueError as e:
        print(str(e), file=sys.stderr)
        return 1
    audit.record("approve" if approve else "reject", request=r.id, by=by, command=r.command[:2000], cwd=r.cwd,
                 without_snapshot=r.skip_snapshot)
    if approve:
        mins = int(policy.ttl_seconds // 60)
        print(f"{green('approved')} {r.id} by {by}. The agent can now retry the exact same command (valid {mins} min).")
        if r.skip_snapshot:
            print(orange("No restore point will be taken for this one."))
    else:
        print(f"{red('denied')} {r.id} by {by}. The agent will be told not to retry.")
    return 0


# ------------------------------------------------------------------ log / snapshots / undo

def cmd_log(a: argparse.Namespace) -> int:
    if a.verify:
        ok, n, msg = audit.verify()
        print((green("OK ") if ok else red("TAMPERED ")) + msg)
        return 0 if ok else 1
    rows = list(audit.entries())[-a.limit:]
    if a.json:
        for e in rows:
            print(json.dumps(e))
        return 0
    if not rows:
        print("Audit log is empty.")
        return 0
    color = {"deny": red, "reject": red, "hold": orange, "approve": green, "run_approved": green, "restore": green,
             "allow": dim, "snapshot_failed": red, "ask_agent_prompt": orange}
    for e in rows:
        when = dt.datetime.fromtimestamp(e["ts"]).strftime("%m-%d %H:%M:%S")
        ev = color.get(e["event"], str)(f"{e['event']:<14}")
        detail = e.get("command") or e.get("snapshot") or ""
        extra = []
        if e.get("request"):
            extra.append(e["request"])
        if e.get("by") or e.get("approved_by"):
            extra.append("by " + str(e.get("by") or e.get("approved_by")))
        if e.get("snapshots"):
            extra.append("snap " + ",".join(e["snapshots"]))
        print(f"{dim(when)}  {ev} {detail[:90]}  {dim(' · '.join(extra))}")
    return 0


def cmd_snapshots(a: argparse.Namespace) -> int:
    snaps = Store().list_snapshots(a.limit)
    if not snaps:
        print("No snapshots yet.")
        return 0
    for s in snaps:
        status = green(s.status) if s.status == "ok" else dim(s.status)
        if s.status == "pruned" and not a.all:
            continue
        print(f"{bold(s.id)}  {status:<8} {dim(ago(s.created)):<10} {s.provider:<9} {s.label}"
              + (f" {dim('(' + s.request_id + ')')}" if s.request_id else ""))
    return 0


def cmd_undo(a: argparse.Namespace) -> int:
    store = Store()
    if a.id.startswith("req_"):
        snaps = store.snapshots_for(a.id)
        if not snaps:
            print(f"request {a.id} has no snapshots", file=sys.stderr)
            return 1
    else:
        s = store.get_snapshot(a.id)
        if not s:
            print(f"no snapshot {a.id}", file=sys.stderr)
            return 1
        snaps = [s]
    rc = 0
    for s in snaps:
        if s.status == "pruned":
            print(f"{s.id} was pruned (older than the retention window); its files are gone.")
            rc = 1
            continue
        if s.status == "restored" and not a.force:
            print(f"{s.id} was already restored {ago(s.restored_at)} by {s.restored_by}; use --force to restore again.")
            continue
        print(f"{bold(s.id)}  {s.provider}  {s.label}")
        try:
            plan = snapmod.describe(s, a.mode)
        except Exception as e:  # noqa: BLE001
            plan = [f"(couldn't describe: {e})"]
        for line in plan:
            print(f"  will: {line}")
        if a.dry_run:
            continue
        if not a.yes:
            if not sys.stdin.isatty():
                print("refusing to restore without confirmation; pass --yes", file=sys.stderr)
                return 1
            if input("Restore? [y/N] ").strip().lower() not in ("y", "yes"):
                print("skipped")
                continue
        try:
            done = snapmod.restore(s, a.mode, a.force)
        except snapmod.RestoreError as e:
            print(red(f"  restore failed: {e}"), file=sys.stderr)
            audit.record("restore_failed", snapshot=s.id, error=str(e)[:500], by=whoami())
            rc = 1
            continue
        except Exception as e:  # noqa: BLE001
            print(red(f"  restore failed: {e.__class__.__name__}: {e}"), file=sys.stderr)
            audit.record("restore_failed", snapshot=s.id, error=str(e)[:500], by=whoami())
            rc = 1
            continue
        by = whoami()
        store.mark_restored(s.id, by)
        audit.record("restore", snapshot=s.id, request=s.request_id, provider=s.provider, by=by, mode=a.mode)
        for line in done:
            print(f"  {green('✓')} {line}")
    return rc


def cmd_prune(a: argparse.Namespace) -> int:
    policy = load_policy(a.cwd)
    store = Store()
    max_bytes = int(a.max_mb * 1024 * 1024) if a.max_mb is not None else None
    removed = snapmod.prune(store, policy, a.older_than, max_bytes, dry_run=a.dry_run)
    live = store.live_snapshots()
    if not removed:
        print(f"Nothing to prune. {len(live)} snapshot(s) kept.")
        return 0
    from .util import human_size
    for s, reason, size in removed:
        print(f"{'would remove' if a.dry_run else red('removed')}  {s.id}  {human_size(size):>8}  {dim(reason)}  {s.label[:60]}")
    total = sum(b for _, _, b in removed)
    print(f"{'Would free' if a.dry_run else 'Freed'} {human_size(total)}.")
    if not a.dry_run:
        audit.record("prune", snapshots=[s.id for s, _, _ in removed], by=whoami(), bytes=total)
    return 0


def cmd_doctor(a: argparse.Namespace) -> int:
    import platform
    from .util import human_size, run
    ok_mark, warn_mark, bad_mark = green("✓"), orange("!"), red("✗")
    problems = 0

    def line(mark: str, label: str, detail: str) -> None:
        print(f"  {mark} {label:<26} {detail}")

    print(bold("SecondKey doctor"))
    line(ok_mark, "version", f"secondkey {__version__}, Python {platform.python_version()}, {platform.system()}")
    try:
        p = load_policy(a.cwd)
        line(ok_mark, "policy", f"{p.source} ({len(p.rules)} rules, approvals via {p.approval.get('via', 'secondkey')})")
    except PolicyError as e:
        line(bad_mark, "policy", str(e))
        problems += 1
        p = None
    h = home()
    if os.name == "nt":
        # POSIX mode bits mean nothing on Windows; the user profile's ACLs keep it private.
        line(ok_mark, "state directory", f"{h} (inside your Windows user profile)")
    else:
        mode = h.stat().st_mode & 0o777
        line(ok_mark if not mode & 0o077 else warn_mark, "state directory", f"{h} (permissions {oct(mode)[2:]})")
    root = project_root(a.cwd)
    hooks = []
    for name, path in (("Claude Code (project)", root / ".claude" / "settings.json"),
                       ("Claude Code (user)", Path.home() / ".claude" / "settings.json"),
                       ("Cursor (project)", root / ".cursor" / "hooks.json"),
                       ("Cursor (user)", Path.home() / ".cursor" / "hooks.json")):
        try:
            if path.exists() and "secondkey hook" in path.read_text():
                hooks.append(name)
        except OSError:
            pass
    if hooks:
        line(ok_mark, "agent hooks", ", ".join(hooks))
    else:
        line(bad_mark, "agent hooks", "none installed: run `secondkey init` (or `secondkey init --agent cursor`)")
        problems += 1
    tools = [("git", "git snapshots"), ("psql", "Postgres impact + restore"), ("pg_dump", "Postgres snapshots"),
             ("pg_restore", "Postgres undo"), ("mysqldump", "MySQL snapshots"), ("kubectl", "Kubernetes snapshots"),
             ("terraform", "Terraform state backup"), ("aws", "AWS EBS/RDS/S3 snapshots"), ("docker", "Docker volume snapshots"),
             ("neonctl", "Neon branch snapshots")]
    for tool, feature in tools:
        path = shutil.which(tool)
        if path:
            ver = ""
            if tool in ("pg_dump", "psql"):
                import re as _re
                m = _re.search(r"\d+\.\d+", run([tool, "--version"], check=False).stdout)
                ver = f" (v{m.group(0)})" if m else ""
            line(ok_mark, tool, f"{feature}{ver}")
        else:
            line(dim("·"), tool, dim(f"not found: {feature} unavailable"))
    if p is not None:
        line(ok_mark if p.slack_webhook() else dim("·"), "slack", "notifications on" if p.slack_webhook() else dim("off (set SECONDKEY_SLACK_WEBHOOK)"))
    ok, n, msg = audit.verify()
    line(ok_mark if ok else bad_mark, "audit log", msg)
    problems += 0 if ok else 1
    store = Store()
    live = store.live_snapshots()
    size = sum(snapmod.dir_size(s.path) for s in live if os.path.isdir(s.path))
    line(ok_mark, "snapshots", f"{len(live)} kept, {human_size(size)} on disk")
    pend = store.list_requests("pending")
    line(orange("!") if pend else ok_mark, "pending approvals", f"{len(pend)}" + (" (run `secondkey pending`)" if pend else ""))
    print()
    print(green("All good.") if not problems else orange(f"{problems} problem(s) found."))
    return 0 if not problems else 1


def cmd_policy(a: argparse.Namespace) -> int:
    p = load_policy(a.cwd, a.policy)
    if a.default:
        print(default_policy_text(), end="")
        return 0
    print(f"policy: {p.source}")
    for i, r in enumerate(p.rules):
        snap = " + snapshot" if r.snapshot and r.action != "deny" else ""
        print(f"  {DECISION_COLOR[r.action](r.action):>5}{snap:<11} {', '.join(r.match)}")
    print(f"  {DECISION_COLOR[p.default](p.default):>5}{'':<11} (everything else)")
    print(f"approval via {p.approval.get('via', 'secondkey')}, wait {int(p.wait_seconds)}s, approvals valid {int(p.ttl_seconds // 60)} min")
    print(f"slack notifications: {'on' if p.slack_webhook() else 'off'}")
    return 0


# ------------------------------------------------------------------ parser

def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="secondkey", description="The second key for every AI agent action.")
    ap.add_argument("--version", action="version", version=f"secondkey {__version__}")
    ap.add_argument("-C", dest="cwd", default=os.getcwd(), help="run as if started in this directory")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("init", help="write a policy and install the Claude Code hook")
    p.add_argument("--scope", choices=["project", "user"], default="project")
    p.add_argument("--no-hook", action="store_true", help="only write the policy")
    p.add_argument("--force", action="store_true", help="overwrite an existing policy")
    p.add_argument("--via-agent", action="store_true", help="approve in the agent's own prompt instead of `secondkey approve`")
    p.add_argument("--agent", action="append", choices=["claude-code", "cursor"],
                   help="which agent to hook (repeatable; default claude-code)")
    p.set_defaults(fn=cmd_init)

    p = sub.add_parser("check", help="show what SecondKey would decide for a command (nothing is run)")
    p.add_argument("command", nargs="+")
    p.add_argument("--tool", default="Bash", help="tool name; for non-Bash tools pass tool_input JSON as the command")
    p.add_argument("--policy")
    p.add_argument("--json", action="store_true")
    p.add_argument("--no-probe", action="store_true", help="don't connect to databases/clusters to estimate impact")
    p.set_defaults(fn=cmd_check)

    p = sub.add_parser("exec", help="run a command through the gate (for agents without hook support)")
    p.add_argument("command", nargs=argparse.REMAINDER)
    p.add_argument("--wait", type=float, default=None, help="seconds to wait for approval (default 300)")
    p.add_argument("--policy")
    p.set_defaults(fn=cmd_exec)

    p = sub.add_parser("hook", help="agent hook entry point (used by `init`)")
    p.add_argument("agent", choices=["claude-code", "cursor"])
    p.set_defaults(fn=cmd_hook)

    p = sub.add_parser("pending", help="list commands waiting for approval")
    p.add_argument("--all", action="store_true", help="include decided requests")
    p.add_argument("-n", "--limit", type=int, default=30)
    p.set_defaults(fn=cmd_pending)

    p = sub.add_parser("show", help="show one request")
    p.add_argument("id")
    p.set_defaults(fn=cmd_show)

    p = sub.add_parser("approve", help="turn the second key for a held command")
    p.add_argument("id")
    p.add_argument("--by", help="approver name (default: current user)")
    p.add_argument("--no-snapshot", action="store_true", help="run without taking a restore point")
    p.set_defaults(fn=lambda a: _decide(a, True))

    p = sub.add_parser("deny", help="reject a held command")
    p.add_argument("id")
    p.add_argument("--by")
    p.set_defaults(fn=lambda a: _decide(a, False))

    p = sub.add_parser("log", help="show the audit log")
    p.add_argument("-n", "--limit", type=int, default=40)
    p.add_argument("--verify", action="store_true", help="check the hash chain for tampering")
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_log)

    p = sub.add_parser("snapshots", help="list restore points")
    p.add_argument("-n", "--limit", type=int, default=30)
    p.add_argument("--all", action="store_true", help="include pruned ones")
    p.set_defaults(fn=cmd_snapshots)

    p = sub.add_parser("undo", help="restore a snapshot (or every snapshot of a request)")
    p.add_argument("id", help="snap_... or req_...")
    p.add_argument("--mode", choices=["full", "data", "exact"],
                   help="postgres: data = put saved rows back, keep newer ones (default when tables exist); "
                        "exact = also remove rows written since; full = drop and recreate the tables")
    p.add_argument("--force", action="store_true", help="overwrite things that exist again / restore twice")
    p.add_argument("--yes", "-y", action="store_true", help="don't ask for confirmation")
    p.add_argument("--dry-run", action="store_true", help="only show what would happen")
    p.set_defaults(fn=cmd_undo)

    p = sub.add_parser("prune", help="delete old restore points (also runs automatically once a day)")
    p.add_argument("--older-than", type=float, metavar="DAYS", help="default: snapshots.retention_days")
    p.add_argument("--max-mb", type=float, help="default: snapshots.max_total_mb")
    p.add_argument("--dry-run", action="store_true")
    p.set_defaults(fn=cmd_prune)

    p = sub.add_parser("proxy", help="run a Postgres proxy that gates every query (scripts, ORMs, migrations)")
    p.add_argument("--listen", default="127.0.0.1:6543", help="host:port to listen on (default 127.0.0.1:6543)")
    p.add_argument("--upstream", required=True, help="the real database: host:port or a unix socket path")
    p.add_argument("--upstream-ssl", action="store_true", help="use TLS to the upstream database (Python 3.11+)")
    p.add_argument("--wait", type=float, default=0, help="seconds to wait for an approval before failing the query")
    p.add_argument("--snapshot-dsn", help="connection string pg_dump should use (default: upstream + client's db/user)")
    p.set_defaults(fn=lambda a: __import__("secondkey.proxy", fromlist=["run_proxy"]).run_proxy(
        __import__("secondkey.proxy", fromlist=["config_from_args"]).config_from_args(a)))

    p = sub.add_parser("doctor", help="check the installation, hooks, tools and state")
    p.set_defaults(fn=cmd_doctor)

    p = sub.add_parser("policy", help="show the effective policy")
    p.add_argument("--policy")
    p.add_argument("--default", action="store_true", help="print the built-in default policy")
    p.set_defaults(fn=cmd_policy)
    return ap


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if getattr(args, "command", None) and args.cmd == "exec" and args.command[:1] == ["--"]:
        args.command = args.command[1:]
    try:
        return int(args.fn(args) or 0)
    except PolicyError as e:
        print(red(f"policy error: {e}"), file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130
    except BrokenPipeError:  # e.g. `secondkey log | head`
        try:
            sys.stdout = open(os.devnull, "w")
        except OSError:
            pass
        return 0
