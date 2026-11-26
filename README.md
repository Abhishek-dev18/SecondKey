<p align="center">
  <img src="https://raw.githubusercontent.com/Abhishek-dev18/SecondKey/main/assets/logo-wordmark.svg" alt="SecondKey" width="280">
</p>

<h3 align="center">Agents hold the first key. You hold the second.</h3>

<p align="center">
  Approve, snapshot and undo every destructive command an AI agent runs.
</p>

<p align="center">
  <a href="https://pypi.org/project/secondkey/"><img src="https://img.shields.io/pypi/v/secondkey?color=ff5a1f&label=pypi" alt="PyPI"></a>
  <a href="https://github.com/Abhishek-dev18/SecondKey/actions/workflows/test.yml"><img src="https://github.com/Abhishek-dev18/SecondKey/actions/workflows/test.yml/badge.svg" alt="tests"></a>
  <img src="https://img.shields.io/badge/python-3.9%2B-3776ab" alt="Python 3.9+">
  <img src="https://img.shields.io/badge/works%20with-Claude%20Code%20%C2%B7%20Cursor-0e0d0b" alt="Works with Claude Code and Cursor">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-informational" alt="Apache-2.0"></a>
</p>

<p align="center">
  <a href="https://abhishek-dev18.github.io/SecondKey/">Website</a> ·
  <a href="#quick-start">Quick start</a> ·
  <a href="https://github.com/Abhishek-dev18/SecondKey/blob/main/docs/policy-cookbook.md">Policy cookbook</a> ·
  <a href="https://github.com/Abhishek-dev18/SecondKey/blob/main/docs/try-it-with-claude-code.md">5-minute tour</a>
</p>

<p align="center">
  <img src="https://raw.githubusercontent.com/Abhishek-dev18/SecondKey/main/assets/demo.gif" alt="Claude Code tries rm -rf data; SecondKey holds it; the human approves; a restore point is taken; secondkey undo brings the folder back" width="880">
</p>
<p align="center"><sub>A real run on Windows with Claude Code: held → approved → snapshot → undone. <a href="https://github.com/Abhishek-dev18/SecondKey/raw/main/assets/secondkey-demo.mp4">Download the MP4</a></sub></p>

---

## Why

AI agents with real credentials keep destroying real data:

| When | What happened |
|---|---|
| Jul 2025 | **Replit**: an agent deleted a production database during an explicit code freeze |
| Feb 2026 | **DataTalks.Club**: an agent ran `terraform destroy` against live infrastructure |
| Apr 2026 | **PocketOS**: database and backups gone in 9 seconds, via a token unrelated to the task |

A rule in the prompt doesn't stop an agent. **A gate the command has to pass through does.** SecondKey is that gate, and because it takes a restore point right before anything destructive runs, even a wrong "yes" can be undone.

## Quick start

```bash
pipx install secondkey
cd your-project
secondkey init      # adds the hook to Claude Code (--agent cursor for Cursor)
secondkey doctor    # checks hooks, tools and state
```

Now ask your agent to do something destructive. It gets held:

```text
SecondKey held this command for human approval (request req_37f20e).
Why: fs.delete_recursive → ask. Impact: 1 file, 10 B in 1 path.
```

You decide in your terminal:

```console
$ secondkey pending                 # what's waiting, with the blast radius
$ secondkey approve req_37f20e      # turn the second key (or: secondkey deny)
$ secondkey undo snap_be3d7b        # changed your mind? put it back
```

## How it works

<p align="center">
  <img src="https://raw.githubusercontent.com/Abhishek-dev18/SecondKey/main/assets/how-it-works.svg" alt="Agent → classify → policy → deny / allow / ask → you approve → snapshot → runs; every decision goes to the audit log" width="900">
</p>

- **Classify.** Every shell command, SQL statement and tool call becomes a category: `sql.drop`, `git.force_push`, `secrets.read`, `db.reset`, ... (`secondkey check "<cmd>"` shows it).
- **Decide.** A YAML policy says allow, ask or deny. First match wins; `a && b` gets the strictest verdict.
- **Hold.** Asked-for commands wait for `secondkey approve`. The approval is single-use, for the exact same command, for 15 minutes.
- **Snapshot, then run.** The restore point is taken at the last moment, after approval. If it can't be taken, nothing runs.
- **Record.** Every decision goes to a hash-chained audit log (`secondkey log --verify` detects tampering).

## What can be undone

| Target | Restore point | Undo |
|---|---|---|
| **Postgres** `DROP` `TRUNCATE` `DELETE` `UPDATE` `ALTER` | `pg_dump` of the tables, row counts, and the foreign keys a `CASCADE` would remove | Tables recreated with indexes, constraints and sequences; FKs re-added; for tables that still exist, saved rows merged back by primary key while rows written since are kept. One transaction, verified |
| **Migrations** `prisma migrate reset`, `alembic downgrade`, `rails db:drop`, `manage.py flush` and 10 more | Whole-database dump (needs a Postgres `DATABASE_URL`) | Whole database restored |
| **Neon** (`postgres_strategy: neon`) | Just a timestamp, for any size | Branch rewound to that moment; current state kept as a branch |
| **MySQL / MariaDB** | `mysqldump` of the tables | Replayed and row counts verified |
| **Files** `rm`, `rm -rf`, `del`, `Remove-Item` | tar.gz of the paths | Put back (won't overwrite without `--force`) |
| **Git** force push, `reset --hard`, `clean`, `branch -D`, stash drop | Commits pinned under `refs/secondkey/`, uncommitted work saved | Remote restored, branch recreated, edits re-applied |
| **AWS** `delete-volume`, `delete-db-instance`, `s3 rm/rb` | EBS / RDS snapshot, or S3 objects downloaded | New volume, instance restored, objects uploaded back |
| **Docker** `volume rm`, `volume prune` | Volume contents archived | Volume recreated and unpacked |
| **Kubernetes** `kubectl delete` | Objects exported as YAML | `kubectl apply` (volume data not included) |
| **Terraform** `destroy`, `apply`, `state rm/mv` | State + config commit | State surgery reversed; for destroy, it tells you how to recreate, and doesn't pretend |

**Can't be undone, so denied or held without a snapshot:** sent emails, payments and webhooks, `DROP DATABASE`, cloud deletes without a provider, anything reading secrets. Before you approve, you see the blast radius: row counts per table, and for `DELETE … WHERE` how many rows match.

## Beyond shell commands: the Postgres proxy

Hooks see the commands an agent runs, but not a Python script it writes or an ORM it calls. Put the proxy in front of the database:

```bash
secondkey proxy --upstream db.internal:5432 --upstream-ssl
# give the agent: DATABASE_URL=postgresql://app:PASS@127.0.0.1:6543/shop
```

Every query from any client is checked. Held queries fail with a normal Postgres error that names the request to approve, and transactions stay consistent.

## Built so the agent can't switch it off

- **The agent can't turn the second key.** A built-in guard, which no policy can disable, denies an agent that runs `secondkey approve/deny/undo/prune`, touches `~/.secondkey/`, or edits `.secondkey/policy.yaml`, `.claude/settings*.json` or `.cursor/hooks.json`.
- **Never widens permissions.** For allowed commands it returns no decision, so Claude Code's own permission rules still apply.
- **Fails safe.** If SecondKey errors, the hook answers `ask` (Claude Code) or `deny` (Cursor) instead of crashing, because a crashing hook would let the command run.
- **No secrets in logs.** Passwords and tokens are masked before anything is stored, logged or sent to Slack.

## Commands

| Command | What it does |
|---|---|
| `secondkey init` | Write a policy and install the hook (`--agent cursor`, `--scope user`) |
| `secondkey check "<cmd>"` | Show the category, decision and impact. Runs nothing |
| `secondkey pending` | List held commands (`--all` for history) |
| `secondkey approve <req>` / `deny <req>` | Turn the second key, or refuse |
| `secondkey snapshots` / `undo <snap or req>` | List restore points, restore one (`--dry-run`, `--mode`) |
| `secondkey log` | Audit log (`--verify` checks the hash chain) |
| `secondkey proxy --upstream host:5432` | Gate every query to a Postgres database |
| `secondkey exec -- <cmd>` | Run a command through the gate, for agents without hooks |
| `secondkey prune` | Delete old restore points (also daily, automatically) |
| `secondkey doctor` / `policy` | Check the setup / show the effective policy |

## Policy

`secondkey init` writes `.secondkey/policy.yaml`:

```yaml
rules:
  - match: ["secrets.*", "shell.pipe_to_shell", "sql.drop_database"]
    action: deny
  - match: ["sql.drop", "sql.delete", "git.force_push", "tf.destroy", "k8s.delete", "db.reset"]
    action: ask                  # snapshot before running is the default for ask
  - match: ["fs.delete"]         # deleting single files
    action: allow
    snapshot: true               # run, but keep a restore point
default: allow

approval:
  via: secondkey     # or "agent": snapshot, then let Claude Code's own prompt ask you
  ttl_minutes: 15
notify:
  slack_webhook: "${SECONDKEY_SLACK_WEBHOOK}"
```

More recipes (gate all prod SQL, block force pushes, Neon, retention) in the [policy cookbook](https://github.com/Abhishek-dev18/SecondKey/blob/main/docs/policy-cookbook.md).

## Known limits

- Other databases and APIs called from agent-written code aren't covered (use the Postgres proxy and scoped credentials).
- An agent's own script could edit SecondKey's files directly; the guard covers tool calls and shell commands. Running the agent as a separate OS user closes this.
- MCP tools are gated by name; their effects can't be snapshotted automatically.
- Approvals happen in the CLI; Slack sends notifications (buttons are planned).
- Snapshots are local; Postgres dumps over 2 GB and file snapshots over 500 MB are refused and reported (use the Neon strategy for big databases).
- Tested on Linux and on Windows with Claude Code (desktop app, Git Bash, PowerShell). On Windows, Claude Code often runs commands through PowerShell and the classifier is still Bash-oriented. macOS should work but is untested.

<details>
<summary><b>Development</b></summary>

```bash
pip install -e ".[dev]"
pytest -q                                   # unit, git, files, stubbed k8s/terraform/aws/docker/mysql
SECONDKEY_TEST_PG='postgresql://postgres:postgres@localhost:5432/postgres' pytest -q   # + real Postgres and the proxy
```

Releases: push a tag like `v0.2.2` and `.github/workflows/release.yml` publishes to PyPI via trusted publishing.

| Path | What it is |
|---|---|
| `src/secondkey/` | The CLI: `classify.py`, `policy.py`, `gate.py`, `snapshots/`, `hooks/`, `proxy.py` |
| `docs/` | Policy cookbook and a 5-minute Claude Code tour |
| `tests/` | Test suite |
| `index.html`, `assets/` | Website and logo, diagram and demo files |

</details>

Licensed under [Apache-2.0](LICENSE).
