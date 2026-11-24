# Policy cookbook

Policies live in `.secondkey/policy.yaml` (project) or `~/.secondkey/policy.yaml` (user). Rules are checked top to bottom and the **first match wins**. A command made of several parts (`a && b | c`) gets the **strictest** verdict of its parts.

Find the category of any command with:

```console
$ secondkey check "npx prisma migrate reset --force"
ASK  policy: .secondkey/policy.yaml
    ask + snapshot  db.reset                 prisma migrate reset --force
```

## Categories

| Area | Categories |
|---|---|
| SQL | `sql.read` `sql.write` `sql.drop` `sql.truncate` `sql.delete` `sql.update` `sql.alter` `sql.drop_other` `sql.drop_database` `sql.other` `sql.interactive` |
| Migrations | `db.reset` (prisma migrate reset, rails db:drop, manage.py flush, supabase db reset …) `db.migrate_down` (alembic downgrade, rake db:rollback, knex migrate:rollback …) |
| Files | `fs.read` `fs.write` `fs.delete` `fs.delete_recursive` `fs.delete_critical` |
| Git | `git.read` `git.write` `git.push` `git.force_push` `git.delete_remote_branch` `git.reset_hard` `git.clean` `git.branch_delete` `git.discard` `git.rewrite` |
| Infra | `tf.read` `tf.apply` `tf.destroy` `tf.state_write` `k8s.read` `k8s.write` `k8s.delete` `k8s.scale_to_zero` `k8s.exec` `docker.delete` `docker.other` `cloud.read` `cloud.write` `cloud.delete` |
| Secrets | `secrets.read` `secrets.write` `secrets.env_dump` |
| Other | `shell.other` `shell.unparsed` `shell.pipe_to_shell` `system.destructive` `mcp.<server>.<tool>` `tool.<Name>` |
| SecondKey itself | `secondkey.read` (allowed) `secondkey.self_approve` `secondkey.admin` `secondkey.tamper` (always denied, can't be overridden) |

## Recipes

**Let the agent run anything in development, but gate production.** Use two policies: a relaxed one in the dev project, and the default in anything with prod credentials. Or make the prod one stricter:

```yaml
default: allow
rules:
  - match: ["secrets.*", "sql.drop_database", "shell.pipe_to_shell"]
    action: deny
  - match: ["sql.*"]          # every write to the prod DB needs a second key
    action: ask
  - match: ["sql.read"]       # ...except reads (put more specific rules first!)
    action: allow
```

Order matters: put `sql.read → allow` **above** `sql.* → ask`, or the read rule never matches.

**Never allow force pushes at all:**

```yaml
rules:
  - match: ["git.force_push", "git.delete_remote_branch"]
    action: deny
    reason: "Force pushes are disabled in this repo. Open a PR instead."
```

**Quiet safety net for file deletes** (runs immediately, keeps a restore point):

```yaml
rules:
  - match: ["fs.delete", "fs.delete_recursive"]
    action: allow
    snapshot: true
```

**Gate a specific MCP server completely:**

```yaml
rules:
  - match: ["mcp.supabase.*"]
    action: ask
    snapshot: false     # MCP calls can't be snapshotted automatically
```

**Approve on the spot in Claude Code instead of with `secondkey approve`:**

```yaml
approval:
  via: agent     # snapshot first, then Claude Code's own permission prompt asks you
```

**Let the agent wait for you instead of failing fast** (good with Slack notifications):

```yaml
approval:
  wait_seconds: 120
notify:
  slack_webhook: "${SECONDKEY_SLACK_WEBHOOK}"
```

**Big Postgres databases on Neon** (no dumps; undo rewinds the branch to the moment before the command):

```yaml
snapshots:
  postgres_strategy: neon
  neon_project_id: your-project-id
  neon_branch: main
```

**Keep restore points longer / use more disk:**

```yaml
snapshots:
  retention_days: 30
  max_total_mb: 20000
```

## Gating database writes from scripts (the proxy)

Hooks only see the commands an agent runs. A script the agent writes (`python fix_data.py`) or an ORM talks to the database directly. Put the proxy in between:

```console
$ secondkey proxy --upstream db.internal:5432 --upstream-ssl
secondkey proxy listening on 127.0.0.1:6543 -> db.internal:5432 (TLS)
```

Then give the agent `DATABASE_URL=postgresql://app:PASS@127.0.0.1:6543/shop` instead of the real host. Held or denied queries fail with a normal Postgres error that tells the agent (and you) what to approve. Transactions stay consistent because the server raises the error itself.

For snapshots, the proxy runs `pg_dump` against the upstream with the client's database and user; set `PGPASSWORD` (or a `~/.pgpass` entry) for the proxy process, or pass `--snapshot-dsn`.
