<p align="center">
  <img src="assets/logo-wordmark.svg" alt="SecondKey" width="260">
</p>

<p align="center"><b>Agents hold the first key. You hold the second.</b></p>

SecondKey is a change-control gate for AI agents. It sits between Claude Code (or any agent that runs shell commands) and your infrastructure:

- **Safe commands pass straight through.** Reads, tests and plans run with no delay.
- **Destructive commands stop at the gate.** `DROP TABLE`, `DELETE`, `rm -rf`, `git push --force`, `terraform destroy`, `kubectl delete` and more are held until a human approves.
- **A restore point is taken right before an approved command runs.** If the approval was a mistake, `secondkey undo` puts things back.
- **Secrets are never read.** `.env`, cloud credentials, SSH keys and `curl | sh` are denied by policy.
- **Everything is logged** in a hash-chained audit log, so tampering is detectable.

> Status: v0.1, early. Works with Claude Code today; other agents can use `secondkey exec`.

## Install

```bash
pipx install git+https://github.com/Abhishek-dev18/SecondKey
cd your-project
secondkey init          # writes .secondkey/policy.yaml and adds the Claude Code hook
```

`init --scope user` installs it for every project instead. Requires Python 3.9+. For Postgres snapshots, `psql`, `pg_dump` and `pg_restore` must be on your PATH (same major version as your server or newer).

## What it looks like

The agent tries something destructive:

```
psql $PROD_DB -c "DROP TABLE users CASCADE;"
```

Claude Code is told:

```
SecondKey held this command for human approval (request req_880c0e).
Why: sql.drop → ask. Impact: users: 5,000 rows.
A restore point will be taken right before it runs, so it can be undone.
Ask the user to review it and run `secondkey approve req_880c0e` ...
```

You look and decide:

```console
$ secondkey pending
req_880c0e  pending  12s ago  claude-code  /home/riya/shop
  psql $PROD_DB -c "DROP TABLE users CASCADE;"
  why: sql.drop → ask
  impact: users: 5,000 rows

$ secondkey approve req_880c0e
approved req_880c0e by riya. The agent can now retry the exact same command (valid 15 min).
```

The agent retries, SecondKey dumps `users` (plus the foreign keys on other tables that `CASCADE` will remove), and the command runs. If that was a mistake:

```console
$ secondkey undo req_880c0e
snap_453a77  postgres  users (5,000 rows)
  will: users: recreate the table with 5,000 rows, indexes and constraints
  will: re-add foreign key orders_user_id_fkey on orders if it's missing
  will: re-add foreign key carts_user_id_fkey on carts if it's missing
Restore? [y/N] y
  ✓ tables recreated from the snapshot: users
  ✓ foreign key orders_user_id_fkey on orders re-added
  ✓ foreign key carts_user_id_fkey on carts re-added
  ✓ verified users: 5,000 rows
```

## Commands

| Command | What it does |
|---|---|
| `secondkey init` | Write a policy and install the Claude Code `PreToolUse` hook (merges with your existing settings) |
| `secondkey check "<cmd>"` | Show how a command is classified and what the policy decides, with its impact. Runs nothing |
| `secondkey pending` | List held commands (`--all` for history) |
| `secondkey approve <req>` | Turn the second key. Valid once, for the exact same command, for 15 minutes |
| `secondkey deny <req>` | Reject. The agent is told not to retry |
| `secondkey snapshots` | List restore points |
| `secondkey undo <snap or req>` | Restore. Shows what it will do and asks first (`--yes`, `--dry-run`, `--mode`) |
| `secondkey log` | Audit log. `--verify` checks the hash chain |
| `secondkey policy` | Show the effective policy |
| `secondkey exec -- <cmd>` | Run a command through the gate, for agents without hook support. Waits up to 5 min for approval |

## How it works

```
agent proposes a command
  → classify  shell/SQL/tool call → actions like sql.drop, git.force_push, secrets.read
  → policy    first matching rule: allow / ask / deny  (a && b gets the strictest)
  → deny      blocked, agent told not to work around it
  → allow     runs (some rules, like single-file rm, take a quiet snapshot first)
  → ask       held as a request; Slack ping if configured
              human approves → agent retries → snapshot → runs
  → audit     every decision appended to a hash-chained log
```

SecondKey never widens what Claude Code allows on its own: for allowed commands it returns no decision, so Claude Code's normal permission rules still apply. If SecondKey itself errors, the hook answers `ask` rather than crashing, because a crashing hook would let the command run.

### What can be undone

| Target | Snapshot | Undo |
|---|---|---|
| **Postgres** `DROP`, `TRUNCATE`, `DELETE`, `UPDATE`, `ALTER` via `psql` | `pg_dump` of the affected tables, row counts, foreign keys on other tables that point at them | Dropped tables are recreated with indexes, constraints and sequences, and foreign keys are re-added. For tables that still exist, saved rows are put back by primary key and rows written since are kept (`--mode exact` removes them). Verified inside the transaction; if anything fails, nothing changes |
| **Files** `rm`, `rm -rf` | tar.gz of the paths | Put back; refuses to overwrite paths that exist again unless `--force` |
| **Git** force push, delete remote branch, `reset --hard`, `checkout -- .`, `clean`, `branch -D`, stash drop | Commits pinned under `refs/secondkey/…`, uncommitted changes saved with `git stash create`, untracked files archived | Force-push the old commit back, reset and re-apply changes, recreate branches, restore files. Your current changes are saved first |
| **Kubernetes** `kubectl delete` | `kubectl get -o yaml`, cleaned of server fields | `kubectl apply`. Data in deleted volumes is not restored |
| **Terraform** `destroy`, `apply`, `state rm/mv` | `terraform state pull` and the config's git commit | State surgery: state pushed back. Destroy: explains how to recreate from the saved config. Cloud resources can't be un-destroyed, and SecondKey won't pretend otherwise |

**Cannot be undone, so they're denied or held without a snapshot:** emails, payments and webhooks; `DROP DATABASE`; cloud deletes (`aws … delete`, `terminate-instances`); `docker system prune`; anything that reads secrets.

Blast radius is shown before you approve: row counts per table, and for `DELETE`/`UPDATE … WHERE` how many rows match (estimated in a read-only transaction).

## Policy

`secondkey init` writes `.secondkey/policy.yaml`. Rules are checked top to bottom and the first match wins:

```yaml
rules:
  - match: ["secrets.*", "shell.pipe_to_shell", "sql.drop_database"]
    action: deny
  - match: ["sql.drop", "sql.delete", "sql.truncate", "git.force_push", "tf.destroy", "k8s.delete"]
    action: ask                 # snapshot: true is the default for ask
  - match: ["fs.delete"]        # rm of single files
    action: allow
    snapshot: true              # run, but keep a restore point
default: allow

approval:
  via: secondkey      # or "agent": snapshot, then let Claude Code's own prompt ask you
  wait_seconds: 0     # how long the hook waits for an approval before replying "held"
  ttl_minutes: 15
  require_snapshot: true

notify:
  slack_webhook: "${SECONDKEY_SLACK_WEBHOOK}"
```

Run `secondkey check "<command>"` to see the category of any command. Policy lookup order: `$SECONDKEY_POLICY`, `.secondkey/policy.yaml` in the project (searching upward to the git root), `~/.secondkey/policy.yaml`, then the built-in default.

State (approvals, snapshots, audit log) lives in `~/.secondkey/` (override with `SECONDKEY_HOME`).

## Known limits (v0.1)

- SecondKey sees the commands an agent runs through its tools. An agent that connects to a database from its own code (say, a Python script it writes and runs) only shows up as `python script.py`. A SQL proxy is planned; until then, give agents scoped credentials.
- SQL is classified for `psql` (snapshots), and `mysql`, `sqlite3` and `duckdb` (gating only). MCP tools are gated by name.
- Approvals happen in the CLI, or Slack (notification only for now; buttons come with the hosted version).
- Snapshots are local. Large tables mean large dumps; file snapshots above 500 MB are refused and reported as unprotected.

## Development

```bash
pip install -e ".[dev]"
pytest -q                                   # unit + git + files + stubbed k8s/terraform
SECONDKEY_TEST_PG='postgresql://postgres:postgres@localhost:5432/postgres' pytest -q   # + real Postgres
```

## This repo

| Path | What it is |
|---|---|
| `src/secondkey/` | The CLI and hook (`classify.py`, `policy.py`, `gate.py`, `snapshots/`, `hooks/claude_code.py`) |
| `tests/` | Test suite |
| `index.html`, `assets/` | Landing page (live demo of the gate) and logo files |

The landing page is a single static file. Enable GitHub Pages for the `main` branch to publish it.
