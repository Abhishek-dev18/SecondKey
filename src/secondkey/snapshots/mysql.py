"""MySQL / MariaDB snapshots with mysqldump.

Restore replays the dump (DROP TABLE IF EXISTS + CREATE + INSERT) inside the
client, so rows written to those tables after the snapshot are replaced.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Any

from ..classify import Action
from ..policy import Policy
from ..store import Snapshot
from ..util import CommandError, run
from .base import NothingToProtect, Provider, RestoreError, SnapshotUnavailable


def _args(conn: dict[str, str]) -> list[str]:
    a = []
    for key, flag in (("host", "-h"), ("port", "-P"), ("user", "-u")):
        if conn.get(key):
            a += [flag, str(conn[key])]
    return a


def _env(conn: dict[str, str]) -> dict[str, str]:
    env = dict(os.environ)
    if conn.get("password"):
        env["MYSQL_PWD"] = conn["password"]  # keeps the password off the process list
    return env


def _bare(table: str) -> str:
    return table.split(".")[-1].strip("`\"")


def _query(conn: dict[str, str], sql: str) -> list[list[str]]:
    try:
        out = run(["mysql", "-N", "-B", *_args(conn), conn["database"], "-e", sql], env=_env(conn), timeout=60).stdout
    except CommandError as e:
        raise SnapshotUnavailable(f"can't query MySQL: {e.stderr.strip()[:300]}") from e
    return [ln.split("\t") for ln in out.splitlines() if ln]


class MySQLProvider(Provider):
    name = "mysql"

    def _present(self, conn: dict[str, str], tables: list[str]) -> list[str]:
        names = ",".join("'" + _bare(t).replace("'", "''") + "'" for t in tables)
        rows = _query(conn, f"SELECT table_name FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name IN ({names})")
        found = {r[0] for r in rows}
        return [t for t in tables if _bare(t) in found]

    def plan(self, action: Action, policy: Policy) -> list[str]:
        conn, tables = action.target.get("conn") or {}, action.target.get("tables") or []
        if not conn.get("database") or not tables:
            raise SnapshotUnavailable("no database or table names found")
        present = self._present(conn, tables)
        lines = [f"{t}: does not exist (nothing to lose)" for t in tables if t not in present]
        for t in present:
            n = int(_query(conn, f"SELECT COUNT(*) FROM `{_bare(t)}`")[0][0])
            lines.append(f"{t}: {n:,} rows")
        return lines

    def take(self, action: Action, dest: Path, policy: Policy) -> tuple[str, dict[str, Any]]:
        conn, tables = action.target.get("conn") or {}, action.target.get("tables") or []
        present = self._present(conn, tables)
        if not present:
            raise NothingToProtect("none of the tables exist")
        counts = {t: int(_query(conn, f"SELECT COUNT(*) FROM `{_bare(t)}`")[0][0]) for t in present}
        dump = dest / "dump.sql"
        try:
            with open(dump, "w") as fh:
                proc = subprocess.run(["mysqldump", "--single-transaction", "--add-drop-table", *_args(conn),
                                       conn["database"], *[_bare(t) for t in present]],
                                      stdout=fh, stderr=subprocess.PIPE, text=True, env=_env(conn), timeout=3600)
        except FileNotFoundError as e:
            raise SnapshotUnavailable("mysqldump not found on PATH; install the MySQL client tools") from e
        if proc.returncode != 0:
            raise SnapshotUnavailable(f"mysqldump failed: {proc.stderr.strip()[:300]}")
        label = ", ".join(f"{t} ({n:,} rows)" for t, n in counts.items())
        return label, {"conn": conn, "tables": present, "counts": counts}

    def describe_restore(self, snap: Snapshot, mode: str | None = None) -> list[str]:
        return [f"{t}: replace with the {n:,} rows saved before the command" for t, n in snap.meta["counts"].items()] + \
               ["rows written to these tables after the snapshot will be lost"]

    def restore(self, snap: Snapshot, mode: str | None = None, force: bool = False) -> list[str]:
        conn = snap.meta["conn"]
        with open(Path(snap.path) / "dump.sql") as fh:
            proc = subprocess.run(["mysql", *_args(conn), conn["database"]], stdin=fh, capture_output=True, text=True,
                                  env=_env(conn), timeout=7200)
        if proc.returncode != 0:
            raise RestoreError(f"mysql restore failed: {proc.stderr.strip()[:400]}")
        out = []
        for t, n in snap.meta["counts"].items():
            got = int(_query(conn, f"SELECT COUNT(*) FROM `{_bare(t)}`")[0][0])
            if got != n:
                raise RestoreError(f"{t}: expected {n:,} rows after restore, found {got:,}")
            out.append(f"verified {t}: {got:,} rows")
        return out
