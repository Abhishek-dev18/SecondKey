<p align="center">
  <img src="assets/logo-wordmark.svg" alt="SecondKey" width="260">
</p>

<p align="center"><b>Agents hold the first key. You hold the second.</b></p>

SecondKey is a change-control gate for AI agents. It sits between coding and ops agents (Claude Code, Cursor, MCP agents) and your infrastructure:

- **Safe commands pass straight through.** Reads, tests and plans run with no delay.
- **Destructive commands stop at the gate.** `DROP TABLE`, `terraform destroy`, `kubectl delete` and `git push --force` are snapshotted first, then sent to a human for approval.
- **A wrong "yes" can be undone.** `secondkey undo <snapshot>` restores from the restore point taken before the command ran.
- **Secrets are never read.** Access to `.env`, cloud credentials and keys is denied by policy.
- **Everything is logged.** Which agent, which command, which rule, who approved and which snapshot.

> Status: concept and landing page. The CLI is not released yet.

## How it works

```
agent proposes a command
  → intercept   (Claude Code PreToolUse hook, MCP wrapper or SQL proxy)
  → classify    (read-only / destructive / secret)
  → policy      (allow / ask / deny from policy.yaml)
  → snapshot    (pg_dump or Neon branch, tfstate backup, git ref, disk snapshot)
  → approve     (Slack card with command, target and blast radius)
  → execute or reject
  → audit log   (append-only)
```

Example policy:

```yaml
allow: [SELECT, git commit, terraform plan]
ask:   [DROP, DELETE, terraform destroy, kubectl delete, git push --force]
deny:  [read .env, read ~/.aws]
snapshot: before ask
budget: $20/session
```

## This repo

| Path | What it is |
|---|---|
| `index.html` | The landing page, a single static file with a live, interactive demo of the gate |
| `assets/logo-mark.svg` | Logo mark for dark backgrounds |
| `assets/logo-mark-light.svg` | Logo mark for light backgrounds |
| `assets/logo-wordmark.svg` | Mark plus wordmark |
| `assets/favicon.svg` | Favicon |

To view the page locally, open `index.html` in a browser. To publish it, enable GitHub Pages for the `main` branch (Settings → Pages → Deploy from a branch).

The demo on the page is a simulation with sample commands. Nothing real is touched, and the waitlist form does not send or store anything yet.

## Logo

Two lock cylinders. The first (the agent's) sits upright; the second, in orange, has been turned. An action only goes through once a human turns the second key.

Colours: warm black `#0e0d0b`, bone `#f2efe8`, signal orange `#ff5a1f`. Type: Geist and Geist Mono.
