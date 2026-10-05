import sqlite3
from datetime import datetime, timezone

from agent.database import SCHEMA_VERSION, connect, init_db, prune, store_cycle


def sample(ts):
    return {
        "timestamp": ts,
        "hostname": "h",
        "cpu_percent": 10.0,
        "memory_percent": 20.0,
        "load1": 0.5,
        "disk_used_percent": 30.0,
    }


def task(task_id, **kw):
    t = {
        "task_id": task_id,
        "category": "process",
        "name": task_id,
        "command": task_id,
        "unit": None,
        "pid": 1,
        "raw_status": "sleeping",
        "status": "ok",
        "process_count": 1,
        "cpu_percent": None,
        "memory_percent": 1.0,
        "rss_bytes": 10,
        "num_threads": 1,
        "num_fds": 3,
        "metadata": "{}",
    }
    t.update(kw)
    return t


def test_fresh_database_is_at_current_schema(db_path):
    init_db()
    conn = connect()
    assert conn.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION
    cols = {r["name"] for r in conn.execute("PRAGMA table_info(tasks)")}
    assert {"state", "unit"} <= cols
    init_db()  # idempotent


def test_v1_database_is_migrated_in_place(db_path):
    old = sqlite3.connect(db_path)
    old.executescript(
        """CREATE TABLE samples(id INTEGER PRIMARY KEY AUTOINCREMENT,timestamp TEXT NOT NULL,
        hostname TEXT NOT NULL,cpu_percent REAL NOT NULL,memory_percent REAL NOT NULL,load1 REAL,
        disk_used_percent REAL);
        CREATE TABLE tasks(task_id TEXT PRIMARY KEY,category TEXT NOT NULL,name TEXT NOT NULL,
        command TEXT,first_seen TEXT NOT NULL,last_seen TEXT NOT NULL,status TEXT NOT NULL,
        metadata TEXT DEFAULT '{}');
        CREATE TABLE task_samples(id INTEGER PRIMARY KEY AUTOINCREMENT,task_id TEXT NOT NULL,
        sample_id INTEGER NOT NULL,timestamp TEXT NOT NULL,pid INTEGER,status TEXT,
        cpu_percent REAL DEFAULT 0,memory_percent REAL DEFAULT 0,rss_bytes INTEGER DEFAULT 0);
        CREATE INDEX idx_task_samples_task ON task_samples(task_id);
        INSERT INTO tasks VALUES('a','process','a','a','t','t','sleeping','{}');
        INSERT INTO task_samples(task_id,sample_id,timestamp,status)
        VALUES('a',1,'t','sleeping');"""
    )
    old.close()
    init_db()
    conn = connect()
    row = conn.execute("SELECT status,state FROM tasks WHERE task_id='a'").fetchone()
    assert (row["status"], row["state"]) == ("ok", "active")
    assert conn.execute("SELECT raw_status FROM task_samples").fetchone()[0] == "sleeping"
    tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"findings", "disk_samples"} <= tables
    sample_cols = {r["name"] for r in conn.execute("PRAGMA table_info(samples)")}
    assert {"psi_memory_some", "oom_kill_total", "swap_percent"} <= sample_cols


def test_store_cycle_upserts_and_marks_gone(db_path):
    init_db()
    conn = connect()
    store_cycle(conn, sample("2026-01-01T00:00:00Z"), [task("a"), task("b")])
    store_cycle(conn, sample("2026-01-01T00:00:15Z"), [task("a", cpu_percent=5.0)])
    rows = {r["task_id"]: r for r in conn.execute("SELECT * FROM tasks")}
    assert rows["a"]["state"] == "active" and rows["a"]["last_seen"] == "2026-01-01T00:00:15Z"
    assert rows["a"]["first_seen"] == "2026-01-01T00:00:00Z"
    assert (rows["b"]["state"], rows["b"]["status"]) == ("gone", "gone")
    store_cycle(conn, sample("2026-01-01T00:00:30Z"), [task("b")])
    assert conn.execute("SELECT state FROM tasks WHERE task_id='b'").fetchone()[0] == "active"
    per_sample = conn.execute(
        "SELECT sample_id, COUNT(*) FROM task_samples WHERE task_id='a' GROUP BY sample_id"
    ).fetchall()
    assert all(r[1] == 1 for r in per_sample)


def test_prune_applies_retention(db_path):
    init_db()
    conn = connect()
    store_cycle(conn, sample("2026-01-01T00:00:00Z"), [task("old")])
    store_cycle(conn, sample("2026-01-03T00:00:00Z"), [task("new")])
    deleted = prune(conn, 24, 30, now=datetime(2026, 1, 3, 1, tzinfo=timezone.utc))
    assert deleted == {
        "task_samples": 1,
        "samples": 0,
        "tasks": 1,
        "disk_samples": 0,
        "findings": 0,
    }
    assert [r[0] for r in conn.execute("SELECT task_id FROM tasks")] == ["new"]
