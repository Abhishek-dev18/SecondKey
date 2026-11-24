"""A Postgres wire-protocol proxy that puts the gate in front of a database.

Point an agent's DATABASE_URL at the proxy instead of the database. Every
query, whether from psql, a script the agent wrote, an ORM or a migration
tool, is classified and checked against the policy:

* allowed queries are forwarded untouched;
* held or denied queries are swapped for a statement that makes the server
  itself raise an error carrying SecondKey's message. Because the server
  produces the error, transaction state stays correct for every client;
* once a human approves, the next identical query gets a snapshot and runs.

The proxy speaks plain text to clients (run it on localhost) and can use TLS
to the upstream database (--upstream-ssl, Python 3.11+).
"""

from __future__ import annotations

import asyncio
import os
import ssl
import struct
import sys
from dataclasses import dataclass, field
from typing import Any

from . import gate
from .classify import Action
from .policy import Policy, load_policy
from .sql import classify_sql

SSL_REQUEST = 80877103
GSSENC_REQUEST = 80877104
CANCEL_REQUEST = 80877102
PROTECTABLE = ("sql.drop", "sql.truncate", "sql.delete", "sql.update", "sql.alter")


@dataclass
class ProxyConfig:
    listen_host: str = "127.0.0.1"
    listen_port: int = 6543
    upstream: str = "127.0.0.1:5432"     # host:port or a unix socket path
    upstream_ssl: bool = False
    wait: float = 0.0
    cwd: str = field(default_factory=os.getcwd)
    snapshot_dsn: str | None = None      # overrides how pg_dump connects

    def upstream_parts(self) -> tuple[str | None, str | None, str | None]:
        """(host, port, unix_path)"""
        if self.upstream.startswith("/"):
            d, name = os.path.split(self.upstream)
            port = name.rsplit(".", 1)[-1] if name.startswith(".s.PGSQL.") else None
            return d, port, self.upstream
        host, _, port = self.upstream.rpartition(":")
        return (host or "127.0.0.1"), (port or "5432"), None


def classify_query(sql: str, conn: dict[str, str]) -> list[Action]:
    out = []
    for st in classify_sql(sql):
        provider = "postgres" if st.tables and st.category in PROTECTABLE else None
        out.append(Action(st.category, st.text[:120], provider,
                          {"conn": conn, "tables": st.tables, "sql": st.text, "where": st.where, "kind": st.category}))
    return out or [Action("sql.read", "empty query")]


def _quote_lit(s: str) -> str:
    return "'" + s.replace("'", "''") + "'"


def raise_statement(message: str) -> str:
    msg = message.replace("$sk$", "$ sk $")
    return f"DO $sk$ BEGIN RAISE EXCEPTION USING MESSAGE = {_quote_lit(msg)}, ERRCODE = '42501'; END $sk$"


def parse_error_statement(short: str) -> str:
    # Extended protocol: the error must happen at Parse time, so reference a relation whose
    # name is the message. Postgres reports: relation "<message>" does not exist.
    ident = short[:63].replace('"', "'")
    return f'SELECT * FROM "{ident}"'


async def _read_msg(r: asyncio.StreamReader) -> tuple[bytes, bytes]:
    head = await r.readexactly(5)
    length = struct.unpack("!I", head[1:])[0]
    return head[:1], await r.readexactly(length - 4)


def _msg(typ: bytes, body: bytes) -> bytes:
    return typ + struct.pack("!I", len(body) + 4) + body


class Session:
    def __init__(self, cfg: ProxyConfig, policy: Policy, params: dict[str, str]):
        self.cfg, self.policy, self.params = cfg, policy, params
        host, port, _ = cfg.upstream_parts()
        db = params.get("database") or params.get("user") or "postgres"
        if cfg.snapshot_dsn:
            self.conn = {"dbname": cfg.snapshot_dsn}
        else:
            self.conn = {"dbname": db, "host": host or "", "port": port or "", "user": params.get("user", "")}
            self.conn = {k: v for k, v in self.conn.items() if v}
        self.db = db
        self.skip_until_sync = False

    def decide(self, sql: str) -> tuple[bool, str, str]:
        """Return (allowed, long message, short message). Runs in a worker thread."""
        actions = classify_query(sql, self.conn)
        decision = self.policy.evaluate(actions)
        if decision.decision == "allow" and not decision.snapshot_actions:
            return True, "", ""
        result = gate.evaluate(source="pg-proxy", tool="SQL",
                               tool_input={"command": sql, "database": self.db, "user": self.params.get("user", ""),
                                           "conn": self.conn},
                               cwd=f"{self.cfg.cwd}", policy=self.policy, wait=self.cfg.wait, native_ask=False)
        if result.outcome == "allow":
            return True, result.message, ""
        if result.outcome == "held" and result.request is not None:
            rid = result.request.id
            impact = ("; ".join(result.request.impact[:3]) + ". ") if result.request.impact else ""
            return (False, f"SecondKey held this query for human approval (request {rid}). {impact}"
                           f"Ask a human to run `secondkey approve {rid}`, then run the same query again.",
                    f"secondkey: held {rid}, run: secondkey approve {rid}")
        return False, result.message, "secondkey: blocked by policy, see: secondkey log"


async def _open_upstream(cfg: ProxyConfig) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    host, port, unix = cfg.upstream_parts()
    if unix:
        r, w = await asyncio.open_unix_connection(unix)
    else:
        r, w = await asyncio.open_connection(host, int(port or 5432))
    if cfg.upstream_ssl:
        if not hasattr(w, "start_tls"):
            raise RuntimeError("--upstream-ssl needs Python 3.11+")
        w.write(struct.pack("!II", 8, SSL_REQUEST))
        await w.drain()
        if await r.readexactly(1) != b"S":
            raise RuntimeError("upstream refused TLS")
        await w.start_tls(ssl.create_default_context(), server_hostname=host)
    return r, w


async def _pump(src: asyncio.StreamReader, dst: asyncio.StreamWriter) -> None:
    try:
        while True:
            data = await src.read(65536)
            if not data:
                break
            dst.write(data)
            await dst.drain()
    except (ConnectionError, asyncio.IncompleteReadError):
        pass
    finally:
        try:
            dst.close()
        except Exception:
            pass


async def handle_client(cfg: ProxyConfig, policy: Policy, cr: asyncio.StreamReader, cw: asyncio.StreamWriter) -> None:
    uw: asyncio.StreamWriter | None = None
    try:
        while True:
            length = struct.unpack("!I", await cr.readexactly(4))[0]
            body = await cr.readexactly(length - 4)
            code = struct.unpack("!I", body[:4])[0]
            if code in (SSL_REQUEST, GSSENC_REQUEST):
                cw.write(b"N")  # plain text to the client; keep the proxy on localhost
                await cw.drain()
                continue
            break
        startup = struct.pack("!I", length) + body
        ur, uw = await _open_upstream(cfg)
        uw.write(startup)
        await uw.drain()
        if code == CANCEL_REQUEST:
            return
        parts = body[4:].split(b"\x00")
        params = {parts[i].decode(): parts[i + 1].decode() for i in range(0, len(parts) - 1, 2) if parts[i]}
        session = Session(cfg, policy, params)
        server_to_client = asyncio.create_task(_pump(ur, cw))
        try:
            while True:
                typ, payload = await _read_msg(cr)
                if typ == b"Q":
                    sql = payload[:-1].decode(errors="replace")
                    allowed, long_msg, _ = await asyncio.to_thread(session.decide, sql)
                    if not allowed:
                        payload = raise_statement(long_msg).encode() + b"\x00"
                elif typ == b"P":
                    name_end = payload.index(b"\x00")
                    q_end = payload.index(b"\x00", name_end + 1)
                    sql = payload[name_end + 1:q_end].decode(errors="replace")
                    allowed, _, short = await asyncio.to_thread(session.decide, sql)
                    if not allowed:
                        payload = payload[:name_end + 1] + parse_error_statement(short).encode() + b"\x00" + struct.pack("!H", 0)
                elif typ == b"X":
                    uw.write(_msg(typ, payload))
                    await uw.drain()
                    break
                uw.write(_msg(typ, payload))
                await uw.drain()
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        finally:
            server_to_client.cancel()
    except (asyncio.IncompleteReadError, ConnectionError, OSError, RuntimeError) as e:
        print(f"secondkey proxy: connection error: {e}", file=sys.stderr)
    finally:
        for w in (cw, uw):
            if w is not None:
                try:
                    w.close()
                except Exception:
                    pass


async def serve(cfg: ProxyConfig, ready: asyncio.Event | None = None) -> None:
    policy = load_policy(cfg.cwd)
    server = await asyncio.start_server(lambda r, w: handle_client(cfg, policy, r, w), cfg.listen_host, cfg.listen_port)
    if ready:
        ready.set()
    async with server:
        await server.serve_forever()


def run_proxy(cfg: ProxyConfig) -> int:
    host, port, unix = cfg.upstream_parts()
    print(f"secondkey proxy listening on {cfg.listen_host}:{cfg.listen_port} -> {unix or f'{host}:{port}'}"
          f"{' (TLS)' if cfg.upstream_ssl else ''}", file=sys.stderr)
    print(f"point the agent at it, e.g. DATABASE_URL=postgresql://USER:PASS@{cfg.listen_host}:{cfg.listen_port}/DBNAME",
          file=sys.stderr)
    try:
        asyncio.run(serve(cfg))
    except KeyboardInterrupt:
        return 0
    return 0


def config_from_args(a: Any) -> ProxyConfig:
    lh, _, lp = a.listen.rpartition(":")
    return ProxyConfig(listen_host=lh or "127.0.0.1", listen_port=int(lp), upstream=a.upstream, upstream_ssl=a.upstream_ssl,
                       wait=a.wait, cwd=a.cwd, snapshot_dsn=a.snapshot_dsn)
