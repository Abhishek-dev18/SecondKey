"""Turn an agent tool call into a list of classified actions.

An *action* has a dotted category (``sql.drop``, ``git.force_push``,
``secrets.read`` ...) that policies match against, a human summary, and the
details a snapshot provider needs to take a restore point.
"""

from __future__ import annotations

import fnmatch
import glob
import os
import re
import shlex
from dataclasses import dataclass, field
from typing import Any

from .sql import classify_sql

SHELL_OPS = {";", "&&", "||", "|", "&", "\n", "|&"}
WRAPPERS = {"sudo", "nohup", "time", "nice", "ionice", "command", "exec", "doas"}
WRAPPER_VALUE_FLAGS = {"sudo": ("-u", "-g", "-C", "-D", "-p", "-r", "-t", "-U", "-h", "-T"),
                       "doas": ("-u", "-C"), "nice": ("-n",), "ionice": ("-c", "-n", "-p")}
SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "fish"}
READERS = {"cat", "less", "more", "head", "tail", "grep", "rg", "egrep", "fgrep", "base64", "xxd", "od",
           "strings", "cp", "scp", "rsync", "nl", "awk", "sed", "jq", "yq", "source", ".", "bat", "tac",
           "openssl", "gpg", "curl", "wget", "nc", "python", "python3", "node"}
SECRET_PATTERNS = [".env", ".env.*", "*.env", "id_rsa*", "id_ed25519*", "id_ecdsa*", "*.pem", "*.key", "*.p12",
                   "*.pfx", "credentials", "credentials.json", ".npmrc", ".pypirc", ".netrc", ".pgpass",
                   "secrets.yaml", "secrets.yml", "secrets.json", "service-account*.json", "*.tfvars", "kubeconfig"]
SECRET_DIRS = ("/.ssh/", "/.aws/", "/.gnupg/", "/.config/gcloud/", "/.kube/", "/.docker/config")
SAFE_SECRET_NAMES = {".env.example", ".env.sample", ".env.template", ".env.dist"}


@dataclass
class Action:
    category: str
    summary: str
    provider: str | None = None          # snapshot provider able to protect this action
    target: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {"category": self.category, "summary": self.summary, "provider": self.provider, "target": self.target}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Action":
        return cls(d["category"], d["summary"], d.get("provider"), d.get("target") or {})


# ---------------------------------------------------------------- helpers

def is_secret_path(path: str) -> bool:
    if not path or path.startswith("-"):
        return False
    p = os.path.expanduser(path).replace("\\", "/")
    base = os.path.basename(p.rstrip("/"))
    if base in SAFE_SECRET_NAMES:
        return False
    if any(d in "/" + p.lstrip("/") for d in SECRET_DIRS):
        return True
    return any(fnmatch.fnmatch(base, pat) for pat in SECRET_PATTERNS)


def _pipelines(command: str) -> list[tuple[list[str], str]]:
    """Return (argv, operator-after) pairs so we can see `curl ... | sh`."""
    try:
        lex = shlex.shlex(command, posix=True, punctuation_chars=";&|")
        lex.whitespace_split = True
        lex.commenters = "#"
        tokens = list(lex)
    except ValueError:
        return []
    out: list[tuple[list[str], str]] = []
    cur: list[str] = []
    for t in tokens:
        if t and set(t) <= set(";&|"):
            out.append((cur, t))
            cur = []
        else:
            cur.append(t)
    out.append((cur, ""))
    return [(a, op) for a, op in out if a]


def _unwrap(argv: list[str]) -> list[str]:
    i = 0
    while i < len(argv):
        a = argv[i]
        if re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", a):
            i += 1
            continue
        base = os.path.basename(a)
        if base in WRAPPERS:
            i += 1
            while i < len(argv) and argv[i].startswith("-"):
                takes = WRAPPER_VALUE_FLAGS.get(base, ())
                i += 2 if argv[i] in takes else 1
            continue
        if base == "env":
            i += 1
            while i < len(argv) and (argv[i].startswith("-") or "=" in argv[i]):
                i += 1
            continue
        break
    return argv[i:]


def _expand(arg: str, env: dict[str, str]) -> str:
    def rep(m: re.Match) -> str:
        name = m.group(1) or m.group(2)
        return env.get(name, m.group(0))
    return re.sub(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)", rep, os.path.expanduser(arg))


def _opt_value(argv: list[str], shorts: tuple[str, ...], longs: tuple[str, ...]) -> list[str]:
    vals, i = [], 0
    while i < len(argv):
        a = argv[i]
        if a in shorts or a in longs:
            if i + 1 < len(argv):
                vals.append(argv[i + 1])
            i += 2
            continue
        for lo in longs:
            if a.startswith(lo + "="):
                vals.append(a[len(lo) + 1:])
        for sh in shorts:
            if len(sh) == 2 and a.startswith(sh) and len(a) > 2 and not a.startswith("--"):
                vals.append(a[2:])
        i += 1
    return vals


# ---------------------------------------------------------------- per-program classifiers

def _psql(argv: list[str], cwd: str, env: dict[str, str]) -> list[Action]:
    args = [_expand(a, env) for a in argv[1:]]
    sql_parts = _opt_value(args, ("-c",), ("--command",))
    for f in _opt_value(args, ("-f",), ("--file",)):
        path = os.path.join(cwd, f)
        try:
            with open(path, encoding="utf-8") as fh:
                sql_parts.append(fh.read())
        except OSError:
            return [Action("sql.other", f"psql -f {f} (file not readable, contents unknown)")]
    conn: dict[str, str] = {}
    for key, shorts, longs in (("dbname", ("-d",), ("--dbname",)), ("host", ("-h",), ("--host",)),
                               ("port", ("-p",), ("--port",)), ("user", ("-U",), ("--username",))):
        v = _opt_value(args, shorts, longs)
        if v:
            conn[key] = v[-1]
    takes_value = {"-c", "-f", "-d", "-h", "-p", "-U", "-v", "-o", "-L", "-P", "-T", "-F", "-R", "--command",
                   "--file", "--dbname", "--host", "--port", "--username", "--set", "--variable", "--output"}
    positional, skip = [], False
    for a in args:
        if skip:
            skip = False
            continue
        if a in takes_value:
            skip = True
            continue
        if a.startswith("-"):
            continue
        positional.append(a)
    if positional and "dbname" not in conn:
        conn["dbname"] = positional[0]
    if len(positional) > 1 and "user" not in conn:
        conn["user"] = positional[1]
    if not sql_parts:
        return [Action("sql.interactive", "psql interactive session (statements unknown)")]
    actions = []
    for st in classify_sql("\n;\n".join(sql_parts)):
        target = {"conn": conn, "tables": st.tables, "sql": st.text, "where": st.where, "kind": st.category}
        provider = "postgres" if st.tables and st.category in ("sql.drop", "sql.truncate", "sql.delete", "sql.update", "sql.alter") else None
        label = st.text if len(st.text) <= 120 else st.text[:117] + "..."
        actions.append(Action(st.category, label, provider, target))
    return actions


def _generic_sql(prog: str, argv: list[str], env: dict[str, str]) -> list[Action]:
    args = [_expand(a, env) for a in argv[1:]]
    flags = {"mysql": (("-e",), ("--execute",)), "mariadb": (("-e",), ("--execute",)),
             "sqlite3": ((), ()), "duckdb": (("-c",), ())}
    shorts, longs = flags.get(prog, ((), ()))
    parts = _opt_value(args, shorts, longs)
    if prog == "sqlite3":
        pos = [a for a in args if not a.startswith("-")]
        parts = pos[1:]
    if not parts:
        return [Action("sql.interactive", f"{prog} session (statements unknown)")]
    return [Action(s.category, s.text[:120], None, {"tables": s.tables, "client": prog})
            for s in classify_sql("\n;\n".join(parts))]


def _rm(argv: list[str], cwd: str, env: dict[str, str]) -> list[Action]:
    recursive, targets, end = False, [], False
    for a in argv[1:]:
        if not end and a == "--":
            end = True
            continue
        if not end and a.startswith("-") and a != "-":
            if a in ("--recursive",) or (not a.startswith("--") and re.search(r"[rR]", a)):
                recursive = True
            continue
        targets.append(_expand(a, env))
    paths: list[str] = []
    for t in targets:
        full = t if os.path.isabs(t) else os.path.join(cwd, t)
        matches = glob.glob(full) if any(c in t for c in "*?[") else [full]
        paths.extend(os.path.normpath(m) for m in matches)
    critical = {"/", os.path.expanduser("~"), os.path.normpath(cwd)}
    roots = {os.path.normpath(p) for p in paths}
    if roots & critical or any(p in ("/*", "~/*") for p in targets) or any(is_secret_path(p) for p in paths):
        cat = "fs.delete_critical"
    else:
        cat = "fs.delete_recursive" if recursive else "fs.delete"
    shown = " ".join(targets) if targets else "(no targets)"
    return [Action(cat, f"rm {'-r ' if recursive else ''}{shown}", "files" if paths else None,
                   {"paths": paths, "cwd": cwd})]


def _git(argv: list[str], cwd: str, env: dict[str, str]) -> list[Action]:
    args, repo = argv[1:], cwd
    while args and args[0].startswith("-"):
        if args[0] == "-C" and len(args) > 1:
            repo = os.path.join(repo, _expand(args[1], env))
            args = args[2:]
            continue
        if args[0] in ("-c", "--git-dir", "--work-tree") and len(args) > 1:
            args = args[2:]
            continue
        args = args[1:]
    if not args:
        return [Action("git.read", "git")]
    sub, rest = args[0], args[1:]
    t: dict[str, Any] = {"repo": repo, "args": rest}
    flags = [a for a in rest if a.startswith("-")]
    pos = [a for a in rest if not a.startswith("-")]
    if sub == "push":
        force = any(f in ("-f", "--force", "--mirror") or f.startswith("--force-with-lease") or f.startswith("--force-if-includes")
                    for f in flags) or any(p.startswith("+") for p in pos[1:])
        deleting = "--delete" in flags or "-d" in flags or any(p.startswith(":") for p in pos[1:])
        remote = pos[0] if pos else None
        refs = [p.lstrip("+") for p in pos[1:]]
        t.update(remote=remote, refs=refs)
        if deleting:
            return [Action("git.delete_remote_branch", "git push " + " ".join(rest), "git", t)]
        if force:
            return [Action("git.force_push", "git push " + " ".join(rest), "git", t)]
        return [Action("git.push", "git push " + " ".join(rest))]
    if sub == "reset" and "--hard" in flags:
        return [Action("git.reset_hard", "git reset " + " ".join(rest), "git", t)]
    if sub == "clean" and any(f.startswith("-") and "f" in f.lstrip("-") or f == "--force" for f in flags):
        t["ignored"] = any(f in ("-x", "-X") or ("x" in f.lstrip("-") and not f.startswith("--")) for f in flags)
        t["dirs"] = any("d" in f.lstrip("-") and not f.startswith("--") for f in flags)
        return [Action("git.clean", "git clean " + " ".join(rest), "git", t)]
    if sub == "branch" and any(f in ("-D", "-d", "--delete") for f in flags):
        t["branches"] = pos
        return [Action("git.branch_delete", "git branch " + " ".join(rest), "git", t)]
    if (sub == "checkout" and ("--" in rest and ("." in rest or len(rest) > 1))) or \
       (sub == "restore" and "--staged" not in flags) or (sub == "stash" and pos[:1] in (["drop"], ["clear"])):
        return [Action("git.discard", f"git {sub} " + " ".join(rest), "git", t)]
    if sub in ("rebase", "filter-branch", "filter-repo", "update-ref", "reflog", "gc", "prune") and \
       (sub != "reflog" or (pos[:1] in (["expire"], ["delete"]))):
        return [Action("git.rewrite", f"git {sub} " + " ".join(rest), "git", t)]
    if sub in ("status", "log", "diff", "show", "fetch", "branch", "remote", "rev-parse", "ls-files", "blame",
               "describe", "tag", "config", "grep", "shortlog", "ls-remote", "reflog"):
        return [Action("git.read", f"git {sub}")]
    return [Action("git.write", f"git {sub} " + " ".join(rest)[:80])]


def _terraform(argv: list[str], cwd: str, env: dict[str, str]) -> list[Action]:
    prog, args, wd = os.path.basename(argv[0]), argv[1:], cwd
    for a in list(args):
        if a.startswith("-chdir="):
            wd = os.path.join(cwd, a.split("=", 1)[1])
            args.remove(a)
    sub = next((a for a in args if not a.startswith("-")), "")
    t = {"cwd": wd, "binary": prog}
    if sub == "destroy" or (sub == "apply" and "-destroy" in args):
        return [Action("tf.destroy", f"{prog} " + " ".join(args), "terraform", t)]
    if sub == "apply":
        return [Action("tf.apply", f"{prog} " + " ".join(args), "terraform", t)]
    if sub == "state" and len(args) > 1 and args[1] in ("rm", "mv", "push", "replace-provider"):
        return [Action("tf.state_write", f"{prog} " + " ".join(args), "terraform", t)]
    if sub == "import" or sub == "taint" or sub == "untaint":
        return [Action("tf.state_write", f"{prog} " + " ".join(args), "terraform", t)]
    return [Action("tf.read", f"{prog} {sub}")]


def _kubectl(argv: list[str], cwd: str, env: dict[str, str]) -> list[Action]:
    args = argv[1:]
    verb = next((a for a in args if not a.startswith("-")), "")
    t = {"args": args, "cwd": cwd}
    if verb == "delete":
        return [Action("k8s.delete", "kubectl " + " ".join(args), "k8s", t)]
    if verb in ("drain", "cordon", "scale", "rollout", "apply", "replace", "patch", "edit", "set", "label",
                "annotate", "create", "expose", "run", "taint", "autoscale"):
        if verb == "scale" and any(re.fullmatch(r"--replicas=0", a) for a in args):
            return [Action("k8s.scale_to_zero", "kubectl " + " ".join(args), "k8s", t)]
        return [Action("k8s.write", "kubectl " + " ".join(args)[:100])]
    if verb == "exec":
        return [Action("k8s.exec", "kubectl " + " ".join(args)[:100])]
    return [Action("k8s.read", f"kubectl {verb}")]


def _helm(argv: list[str]) -> list[Action]:
    verb = next((a for a in argv[1:] if not a.startswith("-")), "")
    if verb in ("uninstall", "delete", "del", "un"):
        return [Action("k8s.delete", "helm " + " ".join(argv[1:]))]
    if verb in ("install", "upgrade", "rollback"):
        return [Action("k8s.write", "helm " + " ".join(argv[1:]))]
    return [Action("k8s.read", f"helm {verb}")]


def _docker(argv: list[str]) -> list[Action]:
    args = [a for a in argv[1:] if not a.startswith("-")]
    joined = " ".join(args[:2])
    if args[:1] in (["rm"], ["rmi"]) or joined in ("system prune", "volume rm", "volume prune", "container prune",
                                                    "image prune", "network rm", "container rm", "image rm",
                                                    "compose down", "builder prune"):
        return [Action("docker.delete", "docker " + " ".join(argv[1:]))]
    return [Action("docker.other", "docker " + joined)]


def _cloud(prog: str, argv: list[str]) -> list[Action]:
    words = [a for a in argv[1:] if not a.startswith("-")]
    text = " ".join(words)
    if re.search(r"\b(delete|terminate|destroy|remove|purge|rb|rm|deregister|revoke)\b|\bdelete-[\w-]+|\bterminate-[\w-]+", text):
        return [Action("cloud.delete", f"{prog} {text}"[:120])]
    if re.search(r"\b(describe|list|get|show|ls|info)\b|\b(describe|list|get)-[\w-]+", text):
        return [Action("cloud.read", f"{prog} {text}"[:120])]
    return [Action("cloud.write", f"{prog} {text}"[:120])]


# ---------------------------------------------------------------- public API

def classify_shell(command: str, cwd: str, env: dict[str, str] | None = None, _depth: int = 0) -> list[Action]:
    env = dict(os.environ if env is None else env)
    pipes = _pipelines(command)
    if not pipes:
        return [Action("shell.unparsed", f"unparsable shell command: {command[:100]}")]
    actions: list[Action] = []
    for idx, (raw, op) in enumerate(pipes):
        argv = _unwrap(raw)
        if not argv:
            continue
        prog = os.path.basename(argv[0])
        prev_prog = os.path.basename(_unwrap(pipes[idx - 1][0])[0]) if idx and pipes[idx - 1][1] == "|" and _unwrap(pipes[idx - 1][0]) else ""
        if prog in SHELLS and prev_prog in ("curl", "wget"):
            actions.append(Action("shell.pipe_to_shell", f"{prev_prog} ... | {prog}"))
            continue
        if prog in SHELLS and "-c" in argv and _depth < 3:
            inner = argv[argv.index("-c") + 1] if argv.index("-c") + 1 < len(argv) else ""
            actions.extend(classify_shell(inner, cwd, env, _depth + 1))
            continue
        if prog == "eval" and _depth < 3:
            actions.extend(classify_shell(" ".join(argv[1:]), cwd, env, _depth + 1))
            continue
        candidates = [a for a in argv[1:] if not a.startswith("-")]
        if prog in ("cp", "scp", "rsync") and candidates:
            candidates = candidates[:-1]  # the last argument is the destination
        if prog in READERS and any(is_secret_path(_expand(a, env).lstrip("@")) for a in candidates):
            actions.append(Action("secrets.read", f"{prog} reads a secret file: " + " ".join(argv[1:])[:100]))
            continue
        if prog in ("printenv",) or (prog in ("env", "export", "set") and len(argv) == 1):
            actions.append(Action("secrets.env_dump", f"{prog} (prints environment variables)"))
            continue
        if prog == "psql":
            actions.extend(_psql(argv, cwd, env))
        elif prog in ("mysql", "mariadb", "sqlite3", "duckdb"):
            actions.extend(_generic_sql(prog, argv, env))
        elif prog in ("dropdb", "dropuser"):
            actions.append(Action("sql.drop_database", " ".join(argv)))
        elif prog in ("rm", "unlink", "rmdir", "shred"):
            actions.extend(_rm(argv if prog != "shred" else ["rm"] + argv[1:], cwd, env))
        elif prog == "find" and ("-delete" in argv or "-exec" in argv and "rm" in argv):
            actions.append(Action("fs.delete_recursive", "find ... -delete"))
        elif prog == "git":
            actions.extend(_git(argv, cwd, env))
        elif prog in ("terraform", "tofu", "terragrunt"):
            actions.extend(_terraform(argv, cwd, env))
        elif prog in ("kubectl", "oc"):
            actions.extend(_kubectl(argv, cwd, env))
        elif prog == "helm":
            actions.extend(_helm(argv))
        elif prog in ("docker", "podman"):
            actions.extend(_docker(argv))
        elif prog in ("aws", "gcloud", "az", "gsutil", "doctl", "flyctl", "fly", "vercel", "heroku", "railway", "supabase", "neonctl"):
            actions.extend(_cloud(prog, argv))
        elif prog in ("mkfs", "dd", "fdisk", "parted", "wipefs", "shutdown", "reboot", "halt", "poweroff") or prog.startswith("mkfs."):
            actions.append(Action("system.destructive", " ".join(argv)[:120]))
        elif prog in ("chmod", "chown") and "-R" in argv and any(a in ("/", "~") for a in argv):
            actions.append(Action("system.destructive", " ".join(argv)[:120]))
        else:
            actions.append(Action("shell.other", " ".join(argv)[:120]))
    return actions or [Action("shell.other", command[:120])]


def classify_tool(tool_name: str, tool_input: dict[str, Any], cwd: str, env: dict[str, str] | None = None) -> list[Action]:
    """Classify a Claude Code / MCP tool call."""
    if tool_name in ("Bash", "PowerShell", "shell", "run_shell_command"):
        return classify_shell(str(tool_input.get("command", "")), cwd, env)
    path = str(tool_input.get("file_path") or tool_input.get("path") or tool_input.get("notebook_path") or "")
    if tool_name in ("Read", "Grep", "Glob", "NotebookRead", "LS"):
        if path and is_secret_path(path):
            return [Action("secrets.read", f"{tool_name} {path}")]
        pattern = str(tool_input.get("pattern", ""))
        if tool_name == "Glob" and is_secret_path(pattern):
            return [Action("secrets.read", f"Glob {pattern}")]
        return [Action("fs.read", f"{tool_name} {path}".strip())]
    if tool_name in ("Write", "Edit", "MultiEdit", "NotebookEdit"):
        if path and is_secret_path(path):
            return [Action("secrets.write", f"{tool_name} {path}")]
        return [Action("fs.write", f"{tool_name} {path}".strip())]
    if tool_name.startswith("mcp__"):
        parts = tool_name.split("__")
        server = parts[1] if len(parts) > 1 else "unknown"
        tool = "__".join(parts[2:]) or "unknown"
        return [Action(f"mcp.{server}.{tool}", f"MCP {server}: {tool}")]
    return [Action(f"tool.{tool_name}", tool_name)]
