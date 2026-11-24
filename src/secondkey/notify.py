"""Approval notifications. Failures are logged, never fatal."""

from __future__ import annotations

import json
import sys
import urllib.request

from .store import Request


def approval_text(req: Request, impact: list[str], problems: list[str]) -> str:
    lines = [f"*SecondKey: approval needed* (`{req.id}`)",
             f"{req.source} wants to run in `{req.cwd}`:",
             f"```{req.command[:1500]}```"]
    if req.reason:
        lines.append(f"Why it's held: {req.reason}")
    if impact:
        lines.append("Impact: " + "; ".join(impact[:8]))
    if problems:
        lines.append("Not protected by a snapshot: " + "; ".join(problems[:4]))
    else:
        lines.append("A snapshot is taken right before it runs, so it can be undone.")
    lines.append(f"Approve: `secondkey approve {req.id}`   Deny: `secondkey deny {req.id}`")
    return "\n".join(lines)


def slack(webhook: str, text: str, timeout: float = 5.0) -> bool:
    body = json.dumps({"text": text, "mrkdwn": True}).encode()
    req = urllib.request.Request(webhook, data=body, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return 200 <= resp.status < 300
    except Exception as e:  # network errors must never break the gate
        print(f"secondkey: Slack notification failed: {e}", file=sys.stderr)
        return False
