"""Postgres integration tests.

Run against a disposable server:  SECONDKEY_TEST_PG='postgresql:///postgres?host=/tmp&port=5433&user=postgres'
Each test creates (and drops) its own database.
"""

import os
import subprocess
import uuid
from urllib.parse import urlsplit

import pytest

from secondkey.cli import main as cli
from secondkey.store import Store

from .conftest import call_hook, decision_of

ADMIN = os.environ.get("SECONDKEY_TEST_PG")
pytestmark = pytest.mark.skipif(not ADMIN, reason="set SECONDKEY_TEST_PG to run Postgres tests")


def sql(dsn, q):
    return subprocess.run(["psql", "-X", "-At", "-v", "ON_ERROR_STOP=1", dsn, "-c", q], check=True,
                          capture_output=True, text=True).stdout.strip()


@pytest.fixture
def db():
    name = "sk_" + uuid.uuid4().hex[:8]
    sql(ADMIN, f"CREATE DATABASE {name}")
    parts = urlsplit(ADMIN)
    dsn = f"{parts.scheme}://{parts.netloc}/{name}" + (f"?{parts.query}" if parts.query else "")
    sql(dsn, """
      CREATE TABLE users (id serial PRIMARY KEY, email text UNIQUE NOT NULL);
      CREATE TABLE orders (id serial PRIMARY KEY, user_id int REFERENCES users(id), total numeric);
      CREATE TABLE carts (id serial PRIMARY KEY, user_id int REFERENCES users(id), age int);
      INSERT INTO users(email) SELECT 'u'||g FROM generate_series(1,500) g;
      INSERT INTO orders(user_id,total) SELECT 1+(g%500), g FROM generate_series(1,2000) g;
      INSERT INTO carts(user_id,age) SELECT 1+(g%500), g%120 FROM generate_series(1,600) g;""")
    yield dsn
    sql(ADMIN, f"DROP DATABASE {name} WITH (FORCE)")


def run_through_gate(cmd, cwd, env_db):
    os.environ["SK_DB"] = env_db
    r = call_hook(cmd, cwd)
    assert decision_of(r) == "deny", r
    reason = r["permissionDecisionReason"]
    rid = reason.split("(request ")[1].split(")")[0]
    assert cli(["approve", rid]) == 0
    r = call_hook(cmd, cwd)
    assert decision_of(r) == "allow", r
    subprocess.run(cmd, shell=True, cwd=cwd, check=True, capture_output=True)
    return rid, reason


def test_drop_cascade_then_undo(db, tmp_path):
    rid, reason = run_through_gate('psql "$SK_DB" -c "DROP TABLE users CASCADE"', tmp_path, db)
    assert "users: 500 rows" in reason
    assert sql(db, "SELECT count(*) FROM pg_constraint WHERE contype='f'") == "0"
    assert cli(["undo", rid, "--yes"]) == 0
    assert sql(db, "SELECT count(*) FROM users") == "500"
    assert sql(db, "SELECT count(*) FROM pg_constraint WHERE contype='f'") == "2"
    # the id sequence came back too: a new user gets 501, not a clash
    assert sql(db, "INSERT INTO users(email) VALUES ('new') RETURNING id").splitlines()[0] == "501"


def test_delete_where_shows_blast_radius_and_undo_reloads_rows(db, tmp_path):
    rid, reason = run_through_gate('psql "$SK_DB" -c "DELETE FROM carts WHERE age > 90"', tmp_path, db)
    assert "carts: 145 of 600 rows match" in reason
    assert sql(db, "SELECT count(*) FROM carts") == "455"
    assert cli(["undo", rid, "--yes"]) == 0
    assert sql(db, "SELECT count(*) FROM carts") == "600"


def test_truncate_undo(db, tmp_path):
    rid, _ = run_through_gate('psql "$SK_DB" -c "TRUNCATE orders"', tmp_path, db)
    assert sql(db, "SELECT count(*) FROM orders") == "0"
    assert cli(["undo", rid, "--yes"]) == 0
    assert sql(db, "SELECT sum(total) FROM orders") == str(sum(range(1, 2001)))


def test_update_without_where_undo(db, tmp_path):
    rid, reason = run_through_gate("""psql "$SK_DB" -c "UPDATE users SET email = email || '-oops'" """.strip(), tmp_path, db)
    assert "all 500 rows (no WHERE clause)" in reason
    assert sql(db, "SELECT count(*) FROM users WHERE email LIKE '%-oops'") == "500"
    assert cli(["undo", rid, "--yes"]) == 0
    assert sql(db, "SELECT count(*) FROM users WHERE email LIKE '%-oops'") == "0"
    assert sql(db, "SELECT email FROM users WHERE id = 7") == "u7"


def test_drop_if_exists_on_missing_table_needs_no_snapshot(db, tmp_path):
    os.environ["SK_DB"] = db
    r = call_hook('psql "$SK_DB" -c "DROP TABLE IF EXISTS ghosts"', tmp_path)
    rid = r["permissionDecisionReason"].split("(request ")[1].split(")")[0]
    assert "ghosts: does not exist" in r["permissionDecisionReason"]
    cli(["approve", rid])
    assert decision_of(call_hook('psql "$SK_DB" -c "DROP TABLE IF EXISTS ghosts"', tmp_path)) == "allow"
    assert Store().snapshots_for(rid) == []


def test_delete_undo_keeps_rows_written_afterwards(db, tmp_path):
    rid, _ = run_through_gate('psql "$SK_DB" -c "DELETE FROM carts WHERE age > 90"', tmp_path, db)
    sql(db, "INSERT INTO carts(user_id, age) VALUES (1, 5), (2, 6)")   # app keeps writing
    assert cli(["undo", rid, "--yes"]) == 0
    assert sql(db, "SELECT count(*) FROM carts") == "602"
    assert sql(db, "INSERT INTO carts(user_id, age) VALUES (3, 1) RETURNING id").splitlines()[0] == "603"


def test_exact_mode_removes_newer_rows(db, tmp_path):
    rid, _ = run_through_gate('psql "$SK_DB" -c "DELETE FROM carts WHERE age > 90"', tmp_path, db)
    sql(db, "INSERT INTO carts(user_id, age) VALUES (1, 5)")
    assert cli(["undo", rid, "--yes", "--mode", "exact"]) == 0
    assert sql(db, "SELECT count(*) FROM carts") == "600"


# ---------------------------------------------------------------- proxy, migrations, neon

import asyncio
import socket
import stat
import threading
from urllib.parse import parse_qs

pg8000 = pytest.importorskip("pg8000.native")


def _upstream_and_auth(dsn):
    parts = urlsplit(dsn)
    q = {k: v[0] for k, v in parse_qs(parts.query).items()}
    host = q.get("host") or parts.hostname or "127.0.0.1"
    port = q.get("port") or str(parts.port or 5432)
    user = q.get("user") or parts.username or "postgres"
    upstream = f"{host}/.s.PGSQL.{port}" if host.startswith("/") else f"{host}:{port}"
    return upstream, user, parts.password, parts.path.lstrip("/")


@pytest.fixture
def proxy(db, tmp_path):
    from secondkey.proxy import ProxyConfig, serve
    upstream, user, password, dbname = _upstream_and_auth(db)
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    cfg = ProxyConfig(listen_port=port, upstream=upstream, cwd=str(tmp_path))
    loop = asyncio.new_event_loop()
    ready = threading.Event()

    def run():
        asyncio.set_event_loop(loop)
        ev = asyncio.Event()
        task = loop.create_task(serve(cfg, ev))
        loop.run_until_complete(ev.wait())
        ready.set()
        try:
            loop.run_until_complete(task)
        except asyncio.CancelledError:
            pass
    t = threading.Thread(target=run, daemon=True)
    t.start()
    assert ready.wait(10)
    if password:
        os.environ["PGPASSWORD"] = password
    yield lambda: pg8000.Connection(user, host="127.0.0.1", port=port, database=dbname, password=password)
    loop.call_soon_threadsafe(lambda: [t.cancel() for t in asyncio.all_tasks(loop)])


def test_proxy_holds_script_queries_then_approve_and_undo(proxy, db):
    con = proxy()
    assert con.run("SELECT count(*) FROM orders")[0][0] == 2000
    with pytest.raises(Exception) as e:
        con.run("DELETE FROM orders WHERE total < :t", t=1001)
    assert "secondkey: held req_" in str(e.value)
    assert con.run("SELECT 1")[0][0] == 1                      # connection still healthy
    rid = str(e.value).split("held ")[1].split(",")[0]
    assert cli(["approve", rid]) == 0
    con.run("DELETE FROM orders WHERE total < :t", t=1001)
    assert sql(db, "SELECT count(*) FROM orders") == "1000"
    snap = Store().snapshots_for(rid)[0]
    assert cli(["undo", snap.id, "--yes"]) == 0
    assert sql(db, "SELECT count(*) FROM orders") == "2000"


def test_proxy_simple_protocol_and_transactions(proxy, db):
    con = proxy()
    con.run("BEGIN")
    con.run("INSERT INTO carts(user_id, age) VALUES (1, 1)")
    with pytest.raises(Exception) as e:
        con.run("DROP TABLE carts")
    assert "secondkey" in str(e.value).lower()
    con.run("ROLLBACK")
    assert sql(db, "SELECT count(*) FROM carts") == "600"
    with pytest.raises(Exception):
        con.run("DROP DATABASE postgres")                     # denied outright
    assert con.run("SELECT count(*) FROM users")[0][0] == 500


def test_migration_whole_database_snapshot(db, tmp_path):
    os.environ["DATABASE_URL"] = db
    try:
        r = call_hook("alembic downgrade -1", tmp_path)
        assert "whole database" in r["permissionDecisionReason"]
        rid = r["permissionDecisionReason"].split("(request ")[1].split(")")[0]
        cli(["approve", rid])
        assert decision_of(call_hook("alembic downgrade -1", tmp_path)) == "allow"
        sql(db, "DROP TABLE carts; DROP TABLE orders; ALTER TABLE users ADD COLUMN junk int")   # what the downgrade did
        assert cli(["undo", rid, "--yes"]) == 0
        assert sql(db, "SELECT count(*) FROM orders") == "2000"
        assert sql(db, "SELECT count(*) FROM information_schema.columns WHERE table_name = 'users' AND column_name = 'junk'") == "0"
    finally:
        del os.environ["DATABASE_URL"]


def test_neon_strategy_records_point_in_time(db, tmp_path, monkeypatch):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    log = tmp_path / "neon.log"
    p = bin_dir / "neonctl"
    p.write_text(f"#!/bin/sh\necho \"$*\" >> {log}\n")
    p.chmod(p.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ['PATH']}")
    proj = tmp_path / "app"
    (proj / ".secondkey").mkdir(parents=True)
    (proj / ".git").mkdir()
    from secondkey.policy import default_policy_text
    (proj / ".secondkey" / "policy.yaml").write_text(default_policy_text().replace(
        "postgres_strategy: dump", "postgres_strategy: neon\n  neon_project_id: proj-1\n  neon_branch: main"))
    rid, reason = run_through_gate('psql "$SK_DB" -c "TRUNCATE carts"', proj, db)
    assert "Neon branch main point-in-time" not in reason  # table actions show row counts
    snap = Store().snapshots_for(rid)[0]
    assert snap.meta["strategy"] == "neon" and snap.meta["timestamp"].endswith("Z")
    assert not os.path.exists(os.path.join(snap.path, "dump.pgc"))      # no copy needed
    cli(["undo", snap.id, "--yes"])
    assert f"branches restore main ^self@{snap.meta['timestamp']} --preserve-under-name main_before_{snap.id} --project-id proj-1" in log.read_text()
