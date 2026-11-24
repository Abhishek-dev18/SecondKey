"""Postgres snapshots with pg_dump / pg_restore.

Before a DROP, TRUNCATE, DELETE, UPDATE or ALTER runs, the affected tables
are dumped (schema + data), their row counts recorded, and any foreign keys
from *other* tables that point at them saved, since a CASCADE drop removes
those. `undo` restores the tables, re-adds those foreign keys and checks the
row counts match.
"""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path
from typing import Any

from ..classify import Action
from ..policy import Policy
from ..store import Snapshot
from ..util import CommandError, run
from .base import NothingToProtect, Provider, RestoreError, SnapshotUnavailable


def conn_args(conn: dict[str, str]) -> list[str]:
    args = []
    if conn.get("dbname"):
        args += ["--dbname", conn["dbname"]]
    if conn.get("host"):
        args += ["--host", conn["host"]]
    if conn.get("port"):
        args += ["--port", str(conn["port"])]
    if conn.get("user"):
        args += ["--username", conn["user"]]
    return args


def _quote_literal(s: str) -> str:
    return "'" + s.replace("'", "''") + "'"


def psql(conn: dict[str, str], *statements: str, read_only: bool = False, timeout_ms: int = 10000) -> list[list[str]]:
    """Run statements in one psql session; return rows of the last one (tab-separated)."""
    cmds = ["SET statement_timeout = %d" % timeout_ms]
    if read_only:
        cmds.append("BEGIN READ ONLY")
    cmds.extend(statements)
    if read_only:
        cmds.append("ROLLBACK")
    argv = ["psql", "-X", "-q", "-A", "-t", "-F", "\t", "-v", "ON_ERROR_STOP=1", "-w", *conn_args(conn)]
    for c in cmds:
        argv += ["-c", c]
    try:
        out = run(argv, timeout=timeout_ms / 1000 + 20).stdout
    except CommandError as e:
        raise SnapshotUnavailable(f"can't query Postgres: {e.stderr.strip()[:300]}") from e
    return [line.split("\t") for line in out.splitlines() if line != ""]


def _exists(conn: dict[str, str], table: str) -> bool:
    rows = psql(conn, f"SELECT to_regclass({_quote_literal(table)}) IS NOT NULL", read_only=True)
    return bool(rows) and rows[-1][0] == "t"


def _count(conn: dict[str, str], table: str, where: str | None = None) -> int:
    if where and ";" in where:
        raise SnapshotUnavailable("WHERE clause too complex to estimate safely")
    q = f"SELECT count(*) FROM {table}" + (f" WHERE {where}" if where else "")
    rows = psql(conn, q, read_only=True)
    return int(rows[-1][0])


def _referencing_fks(conn: dict[str, str], table: str) -> list[dict[str, str]]:
    rows = psql(conn, "SELECT conrelid::regclass::text, conname, pg_get_constraintdef(oid) FROM pg_constraint "
                      f"WHERE contype = 'f' AND confrelid = to_regclass({_quote_literal(table)}) "
                      f"AND conrelid <> to_regclass({_quote_literal(table)})", read_only=True)
    return [{"table": r[0], "name": r[1], "def": r[2]} for r in rows if len(r) == 3]


class PostgresProvider(Provider):
    name = "postgres"

    def plan(self, action: Action, policy: Policy) -> list[str]:
        t = action.target
        conn, tables, kind = t.get("conn") or {}, t.get("tables") or [], t.get("kind")
        if not tables:
            raise SnapshotUnavailable("no table names found in the statement")
        lines = []
        for table in tables:
            if not _exists(conn, table):
                lines.append(f"{table}: does not exist (nothing to lose)")
                continue
            total = _count(conn, table)
            if kind in ("sql.delete", "sql.update") and t.get("where"):
                try:
                    hit = _count(conn, table, t["where"])
                    lines.append(f"{table}: {hit:,} of {total:,} rows match")
                except SnapshotUnavailable:
                    lines.append(f"{table}: {total:,} rows (couldn't evaluate the WHERE clause)")
            elif kind in ("sql.delete", "sql.update"):
                lines.append(f"{table}: all {total:,} rows (no WHERE clause)")
            elif kind == "sql.alter":
                lines.append(f"{table}: {total:,} rows, schema change")
            else:
                lines.append(f"{table}: {total:,} rows")
        return lines

    def take(self, action: Action, dest: Path, policy: Policy) -> tuple[str, dict[str, Any]]:
        t = action.target
        conn, tables = t.get("conn") or {}, t.get("tables") or []
        present = [tb for tb in tables if _exists(conn, tb)]
        if not present:
            raise NothingToProtect("none of the tables exist, so there is nothing to protect")
        counts = {tb: _count(conn, tb) for tb in present}
        fks = [fk for tb in present for fk in _referencing_fks(conn, tb)]
        dump = dest / "dump.pgc"
        argv = ["pg_dump", "-Fc", "-w", "-f", str(dump), *conn_args(conn)]
        for tb in present:
            argv += ["-t", tb]
        try:
            run(argv, timeout=3600)
        except CommandError as e:
            raise SnapshotUnavailable(f"pg_dump failed: {e.stderr.strip()[:300]}") from e
        size = dump.stat().st_size
        label = ", ".join(f"{tb} ({n:,} rows)" for tb, n in counts.items())
        return label, {"conn": conn, "tables": present, "counts": counts, "fks": fks,
                       "statement": t.get("sql"), "kind": t.get("kind"), "bytes": size}

    # ------------------------------------------------------------ restore
    def _mode(self, snap: Snapshot, mode: str | None) -> tuple[str, dict[str, bool]]:
        conn = snap.meta["conn"]
        present = {tb: _exists(conn, tb) for tb in snap.meta["tables"]}
        if mode == "full":
            return "full", present
        if mode in ("data", "exact"):
            return "data", present
        return ("data" if all(present.values()) else "full"), present

    def describe_restore(self, snap: Snapshot, mode: str | None = None) -> list[str]:
        m = snap.meta
        try:
            chosen, present = self._mode(snap, mode)
        except SnapshotUnavailable as e:
            return [f"can't reach the database right now: {e}"]
        lines = []
        for tb in m["tables"]:
            n = m["counts"][tb]
            if chosen == "data":
                lines.append(f"{tb}: put back the {n:,} saved rows by primary key (changed rows reverted, deleted rows re-inserted)")
            elif present[tb]:
                lines.append(f"{tb}: drop the current table and recreate it with {n:,} rows")
            else:
                lines.append(f"{tb}: recreate the table with {n:,} rows, indexes and constraints")
        for fk in m.get("fks") or []:
            lines.append(f"re-add foreign key {fk['name']} on {fk['table']} if it's missing")
        if chosen == "data":
            lines.append("rows written after the snapshot are " + ("REMOVED (--mode exact)" if mode == "exact"
                                                                  else "kept (use --mode exact to remove them)"))
        elif any(present.values()):
            lines.append("rows written to these tables after the snapshot will be lost")
        return lines

    def restore(self, snap: Snapshot, mode: str | None = None, force: bool = False) -> list[str]:
        m = snap.meta
        conn, dump = m["conn"], str(Path(snap.path) / "dump.pgc")
        chosen, present = self._mode(snap, mode)
        out = []
        env = dict(os.environ)
        if chosen == "full":
            argv = ["pg_restore", "--single-transaction", "--exit-on-error", "-w", *conn_args(conn)]
            if any(present.values()):
                argv += ["--clean", "--if-exists"]
            argv.append(dump)
            try:
                run(argv, env=env, timeout=3600)
            except CommandError as e:
                raise RestoreError(f"pg_restore failed, nothing was changed: {e.stderr.strip()[:400]}") from e
            out.append("tables recreated from the snapshot: " + ", ".join(m["tables"]))
        else:
            out.extend(self._merge_restore(conn, dump, m["tables"], exact=(mode == "exact")))
        for fk in m.get("fks") or []:
            exists = psql(conn, "SELECT 1 FROM pg_constraint WHERE conname = %s AND conrelid = to_regclass(%s)"
                          % (_quote_literal(fk["name"]), _quote_literal(fk["table"])), read_only=True)
            if exists:
                continue
            try:
                psql(conn, f'ALTER TABLE {fk["table"]} ADD CONSTRAINT "{fk["name"]}" {fk["def"]}')
                out.append(f"foreign key {fk['name']} on {fk['table']} re-added")
            except SnapshotUnavailable as e:
                out.append(f"WARNING: couldn't re-add foreign key {fk['name']} on {fk['table']}: {e}")

        if chosen == "full":
            bad = []
            for tb, expected in m["counts"].items():
                got = _count(conn, tb)
                if got != expected:
                    bad.append(f"{tb}: expected {expected:,} rows, found {got:,}")
                else:
                    out.append(f"verified {tb}: {got:,} rows")
            if bad:
                raise RestoreError("restore finished but row counts don't match: " + "; ".join(bad))
        return out

    # Merge restore: put back saved rows by primary key, keep rows written since.
    def _merge_restore(self, conn: dict[str, str], dump: str, tables: list[str], exact: bool) -> list[str]:
        try:
            data_sql = run(["pg_restore", "--data-only", "-f", "-", dump], timeout=3600).stdout
        except CommandError as e:
            raise RestoreError(f"couldn't read the snapshot: {e.stderr.strip()[:300]}") from e
        info = {}
        for i, tb in enumerate(tables):
            rows = psql(conn, "SELECT quote_ident(n.nspname) || '.' || quote_ident(c.relname) FROM pg_class c "
                              f"JOIN pg_namespace n ON n.oid = c.relnamespace WHERE c.oid = to_regclass({_quote_literal(tb)})",
                        read_only=True)
            qual = rows[0][0]
            pk = [r[0] for r in psql(conn, "SELECT quote_ident(a.attname) FROM pg_index i JOIN pg_attribute a "
                                           "ON a.attrelid = i.indrelid AND a.attnum = ANY(i.indkey) "
                                           f"WHERE i.indrelid = to_regclass({_quote_literal(tb)}) AND i.indisprimary "
                                           "ORDER BY array_position(i.indkey, a.attnum)", read_only=True)]
            info[qual] = {"name": tb, "tmp": f"secondkey_restore_{i}", "pk": pk, "cols": None}

        lines, script = data_sql.splitlines(keepends=True), []
        for ln in lines:
            m = re.match(r"^COPY (\S+) \((.*)\) FROM stdin;", ln)
            if m and m.group(1) in info:
                t = info[m.group(1)]
                t["cols"] = [c.strip() for c in m.group(2).split(",")]
                script.append(f"COPY {t['tmp']} ({m.group(2)}) FROM stdin;\n")
                continue
            sv = re.match(r"^SELECT pg_catalog\.setval\('([^']+)', (\d+), (true|false)\);", ln)
            if sv:
                seq = sv.group(1).replace("'", "''")
                script.append(f"SELECT pg_catalog.setval('{seq}', GREATEST({sv.group(2)}, (SELECT last_value FROM {sv.group(1)})), true);\n")
                continue
            script.append(ln)

        pre = ["SET statement_timeout = 0;\n"]
        post = []
        for qual, t in info.items():
            pre.append(f"CREATE TEMP TABLE {t['tmp']} (LIKE {qual} INCLUDING DEFAULTS) ON COMMIT DROP;\n")
            cols = t["cols"] or []
            if not cols:
                continue
            col_list = ", ".join(cols)
            s_cols = ", ".join(f"s.{c}" for c in cols)
            d_cols = ", ".join(f"d.{c}" for c in cols)
            if t["pk"]:
                join = " AND ".join(f"d.{k} = s.{k}" for k in t["pk"])
                upd = [c for c in cols if c not in t["pk"]]
                if upd:
                    post.append(f"UPDATE {qual} AS d SET ({', '.join(upd)}) = ROW({', '.join('s.' + c for c in upd)}) "
                                f"FROM {t['tmp']} s WHERE {join} AND ROW({', '.join('d.' + c for c in upd)}) "
                                f"IS DISTINCT FROM ROW({', '.join('s.' + c for c in upd)});\n")
                post.append(f"INSERT INTO {qual} ({col_list}) OVERRIDING SYSTEM VALUE SELECT {s_cols} FROM {t['tmp']} s "
                            f"WHERE NOT EXISTS (SELECT 1 FROM {qual} d WHERE {join});\n")
                newer = f"FROM {qual} d WHERE NOT EXISTS (SELECT 1 FROM {t['tmp']} s WHERE {join})"
                if exact:
                    post.append(f"DELETE {newer.replace('FROM ' + qual + ' d', 'FROM ' + qual + ' AS d', 1)};\n")
                post.append(f"SELECT 'newer:{t['name']}:' || count(*) {newer};\n")
            else:
                post.append(f"DELETE FROM {qual};\n")
                post.append(f"INSERT INTO {qual} ({col_list}) OVERRIDING SYSTEM VALUE SELECT {col_list} FROM {t['tmp']};\n")
            post.append(
                "DO $sk$ BEGIN IF EXISTS (SELECT 1 FROM " + t["tmp"] + " s WHERE NOT EXISTS (SELECT 1 FROM " + qual
                + f" d WHERE ROW({d_cols}) IS NOT DISTINCT FROM ROW({s_cols}))) THEN "
                + f"RAISE EXCEPTION 'secondkey: verification failed for {t['name']}'; END IF; END $sk$;\n")
            post.append(f"SELECT 'saved:{t['name']}:' || count(*) FROM {t['tmp']};\n")

        full = "".join(pre) + "".join(script) + "".join(post)
        proc = subprocess.run(["psql", "-X", "-q", "-A", "-t", "-w", "-v", "ON_ERROR_STOP=1", "--single-transaction",
                               *conn_args(conn), "-f", "-"], input=full, capture_output=True, text=True)
        if proc.returncode != 0:
            raise RestoreError("restore failed and was rolled back, nothing was changed: "
                               + (proc.stderr.strip()[:500] or "unknown error")
                               + ". If the table's columns changed, try `--mode full`.")
        result, saved, newer = [], {}, {}
        for ln in proc.stdout.splitlines():
            parts = ln.strip().split(":")
            if len(parts) == 3 and parts[0] in ("saved", "newer"):
                (saved if parts[0] == "saved" else newer)[parts[1]] = int(parts[2])
        for qual, t in info.items():
            n = t["name"]
            line = f"verified {n}: all {saved.get(n, 0):,} saved rows are back"
            if t["pk"] and newer.get(n):
                line += (f", {newer[n]:,} rows written after the snapshot were removed" if exact
                         else f", {newer[n]:,} rows written after the snapshot were kept")
            if not t["pk"]:
                line += " (no primary key: table contents replaced)"
            result.append(line)
        return result
