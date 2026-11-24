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
