"""SQLite-backed state: approval requests and snapshots."""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Iterator

from .util import home, new_id, now

SCHEMA = """
CREATE TABLE IF NOT EXISTS requests (
  id TEXT PRIMARY KEY,
  created REAL NOT NULL,
  updated REAL NOT NULL,
  status TEXT NOT NULL,              -- pending | approved | denied | executed | expired | failed
  source TEXT NOT NULL,              -- claude-code | exec | ...
  cwd TEXT NOT NULL,
  tool TEXT NOT NULL,
  command TEXT NOT NULL,
  fingerprint TEXT NOT NULL,
  actions TEXT NOT NULL,             -- JSON list of actions that need protecting
  reason TEXT,
  impact TEXT,                       -- JSON list of human-readable impact lines
  decided_by TEXT,
  decided_at REAL,
  expires REAL,
  skip_snapshot INTEGER DEFAULT 0,
  snapshot_ids TEXT DEFAULT '[]'
);
CREATE INDEX IF NOT EXISTS requests_fp ON requests(fingerprint, status);
CREATE TABLE IF NOT EXISTS snapshots (
  id TEXT PRIMARY KEY,
  created REAL NOT NULL,
  request_id TEXT,
  provider TEXT NOT NULL,
  label TEXT NOT NULL,
  path TEXT NOT NULL,
  meta TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'ok', -- ok | restored | failed
  restored_at REAL,
  restored_by TEXT
);
"""


@dataclass
class Request:
    id: str
    created: float
    updated: float
    status: str
    source: str
    cwd: str
    tool: str
    command: str
    fingerprint: str
    actions: list[dict[str, Any]]
    reason: str | None = None
    impact: list[str] = field(default_factory=list)
    decided_by: str | None = None
    decided_at: float | None = None
    expires: float | None = None
    skip_snapshot: bool = False
    snapshot_ids: list[str] = field(default_factory=list)


@dataclass
class Snapshot:
    id: str
    created: float
    request_id: str | None
    provider: str
    label: str
    path: str
    meta: dict[str, Any]
    status: str = "ok"
    restored_at: float | None = None
    restored_by: str | None = None


class Store:
    def __init__(self, path: str | None = None):
        self.path = path or str(home() / "state.db")
        self.db = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.executescript(SCHEMA)

    @contextmanager
    def tx(self) -> Iterator[sqlite3.Connection]:
        self.db.execute("BEGIN IMMEDIATE")
        try:
            yield self.db
            self.db.execute("COMMIT")
        except BaseException:
            self.db.execute("ROLLBACK")
            raise

    # ----------------------------------------------------------- requests
    @staticmethod
    def _req(row: sqlite3.Row) -> Request:
        d = dict(row)
        d["actions"] = json.loads(d["actions"])
        d["impact"] = json.loads(d["impact"] or "[]")
        d["snapshot_ids"] = json.loads(d["snapshot_ids"] or "[]")
        d["skip_snapshot"] = bool(d["skip_snapshot"])
        return Request(**d)

    def expire_old(self) -> None:
        t = now()
        self.db.execute("UPDATE requests SET status='expired', updated=? WHERE status='approved' AND expires IS NOT NULL AND expires < ?", (t, t))
        self.db.execute("UPDATE requests SET status='expired', updated=? WHERE status='pending' AND created < ?", (t, t - 24 * 3600))

    def create_request(self, *, source: str, cwd: str, tool: str, command: str, fingerprint: str,
                       actions: list[dict[str, Any]], reason: str, impact: list[str]) -> tuple[Request, bool]:
        """Create a pending request, or return the existing pending one for the same call."""
        with self.tx() as db:
            row = db.execute("SELECT * FROM requests WHERE fingerprint=? AND status='pending' ORDER BY created DESC LIMIT 1",
                             (fingerprint,)).fetchone()
            if row:
                return self._req(row), False
            rid, t = new_id("req"), now()
            db.execute("INSERT INTO requests (id, created, updated, status, source, cwd, tool, command, fingerprint, actions, reason, impact)"
                       " VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                       (rid, t, t, "pending", source, cwd, tool, command, fingerprint, json.dumps(actions), reason, json.dumps(impact)))
            return self.get_request(rid), True

    def get_request(self, rid: str) -> Request | None:
        row = self.db.execute("SELECT * FROM requests WHERE id=?", (rid,)).fetchone()
        return self._req(row) if row else None

    def list_requests(self, status: str | None = None, limit: int = 50) -> list[Request]:
        self.expire_old()
        if status:
            rows = self.db.execute("SELECT * FROM requests WHERE status=? ORDER BY created DESC LIMIT ?", (status, limit))
        else:
            rows = self.db.execute("SELECT * FROM requests ORDER BY created DESC LIMIT ?", (limit,))
        return [self._req(r) for r in rows]

    def decide(self, rid: str, approve: bool, by: str, ttl: float, skip_snapshot: bool = False) -> Request:
        with self.tx() as db:
            row = db.execute("SELECT * FROM requests WHERE id=?", (rid,)).fetchone()
            if not row:
                raise KeyError(rid)
            if row["status"] != "pending":
                raise ValueError(f"{rid} is already {row['status']}")
            t = now()
            db.execute("UPDATE requests SET status=?, decided_by=?, decided_at=?, updated=?, expires=?, skip_snapshot=? WHERE id=?",
                       ("approved" if approve else "denied", by, t, t, t + ttl if approve else None, int(skip_snapshot), rid))
        return self.get_request(rid)

    def recent_denial(self, fingerprint: str, within: float) -> Request | None:
        row = self.db.execute("SELECT * FROM requests WHERE fingerprint=? AND status='denied' AND decided_at >= ?"
                              " ORDER BY decided_at DESC LIMIT 1", (fingerprint, now() - within)).fetchone()
        return self._req(row) if row else None

    def claim_grant(self, fingerprint: str) -> Request | None:
        """Atomically take a valid approval for this exact call, if one exists."""
        self.expire_old()
        with self.tx() as db:
            row = db.execute("SELECT * FROM requests WHERE fingerprint=? AND status='approved' AND (expires IS NULL OR expires >= ?)"
                             " ORDER BY decided_at DESC LIMIT 1", (fingerprint, now())).fetchone()
            if not row:
                return None
            db.execute("UPDATE requests SET status='executing', updated=? WHERE id=?", (now(), row["id"]))
        return self.get_request(row["id"])

    def finish(self, rid: str, status: str, snapshot_ids: list[str] | None = None, reason: str | None = None) -> None:
        fields, vals = ["status=?", "updated=?"], [status, now()]
        if snapshot_ids is not None:
            fields.append("snapshot_ids=?")
            vals.append(json.dumps(snapshot_ids))
        if reason is not None:
            fields.append("reason=?")
            vals.append(reason)
        self.db.execute(f"UPDATE requests SET {', '.join(fields)} WHERE id=?", (*vals, rid))

    # ----------------------------------------------------------- snapshots
    def add_snapshot(self, s: Snapshot) -> None:
        self.db.execute("INSERT INTO snapshots (id, created, request_id, provider, label, path, meta, status) VALUES (?,?,?,?,?,?,?,?)",
                        (s.id, s.created, s.request_id, s.provider, s.label, s.path, json.dumps(s.meta), s.status))

    @staticmethod
    def _snap(row: sqlite3.Row) -> Snapshot:
        d = dict(row)
        d["meta"] = json.loads(d["meta"])
        return Snapshot(**d)

    def get_snapshot(self, sid: str) -> Snapshot | None:
        row = self.db.execute("SELECT * FROM snapshots WHERE id=?", (sid,)).fetchone()
        return self._snap(row) if row else None

    def snapshots_for(self, rid: str) -> list[Snapshot]:
        return [self._snap(r) for r in self.db.execute("SELECT * FROM snapshots WHERE request_id=? ORDER BY created", (rid,))]

    def list_snapshots(self, limit: int = 50) -> list[Snapshot]:
        return [self._snap(r) for r in self.db.execute("SELECT * FROM snapshots ORDER BY created DESC LIMIT ?", (limit,))]

    def set_snapshot_status(self, sid: str, status: str) -> None:
        self.db.execute("UPDATE snapshots SET status=? WHERE id=?", (status, sid))

    def live_snapshots(self) -> list[Snapshot]:
        """Snapshots whose files still exist on disk, oldest first."""
        return [self._snap(r) for r in self.db.execute(
            "SELECT * FROM snapshots WHERE status IN ('ok', 'restored', 'unused') ORDER BY created")]

    def mark_restored(self, sid: str, by: str) -> None:
        self.db.execute("UPDATE snapshots SET status='restored', restored_at=?, restored_by=? WHERE id=?", (now(), by, sid))
