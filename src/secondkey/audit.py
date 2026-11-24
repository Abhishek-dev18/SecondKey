"""Append-only, hash-chained audit log (JSON lines).

Each entry stores the hash of the previous entry, so editing or deleting a
line breaks the chain and `secondkey log --verify` reports where.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any, Iterator

from .util import home, now

try:
    import fcntl  # POSIX only
except ImportError:  # pragma: no cover
    fcntl = None  # type: ignore

GENESIS = "0" * 64


def log_path() -> Path:
    return home() / "audit.jsonl"


def _digest(entry: dict[str, Any]) -> str:
    body = {k: v for k, v in entry.items() if k != "hash"}
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _last_hash(fh) -> str:
    fh.seek(0, os.SEEK_END)
    size = fh.tell()
    if size == 0:
        return GENESIS
    block, data = 4096, b""
    pos = size
    while pos > 0:
        step = min(block, pos)
        pos -= step
        fh.seek(pos)
        data = fh.read(step) + data
        lines = data.rstrip(b"\n").split(b"\n")
        if len(lines) > 1 or pos == 0:
            return json.loads(lines[-1])["hash"]
    return GENESIS  # pragma: no cover


def record(event: str, **fields: Any) -> dict[str, Any]:
    path = log_path()
    with open(path, "a+b") as fh:
        if fcntl:
            fcntl.flock(fh, fcntl.LOCK_EX)
        try:
            entry = {"ts": round(now(), 3), "event": event, **fields, "prev": _last_hash(fh)}
            entry["hash"] = _digest(entry)
            fh.seek(0, os.SEEK_END)
            fh.write((json.dumps(entry, sort_keys=True) + "\n").encode())
            fh.flush()
        finally:
            if fcntl:
                fcntl.flock(fh, fcntl.LOCK_UN)
    return entry


def entries(path: Path | None = None) -> Iterator[dict[str, Any]]:
    p = path or log_path()
    if not p.exists():
        return
    with open(p, encoding="utf-8") as fh:
        for line in fh:
            if line.strip():
                yield json.loads(line)


def verify(path: Path | None = None) -> tuple[bool, int, str]:
    """Return (ok, entries_checked, message)."""
    prev, n = GENESIS, 0
    p = path or log_path()
    if not p.exists():
        return True, 0, "no audit log yet"
    with open(p, encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
            if not line.strip():
                continue
            try:
                e = json.loads(line)
            except json.JSONDecodeError:
                return False, n, f"line {lineno}: not valid JSON"
            if e.get("prev") != prev:
                return False, n, f"line {lineno}: chain broken (an entry before it was changed or removed)"
            if _digest(e) != e.get("hash"):
                return False, n, f"line {lineno}: contents were modified"
            prev, n = e["hash"], n + 1
    return True, n, f"{n} entries, chain intact"
