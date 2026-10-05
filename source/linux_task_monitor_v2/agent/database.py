import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone

from .config import load_settings

SCHEMA_VERSION = 2
TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

BASE_SCHEMA = [
    """CREATE TABLE IF NOT EXISTS samples(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        hostname TEXT NOT NULL,
        cpu_percent REAL NOT NULL,
        memory_percent REAL NOT NULL,
        load1 REAL,
        disk_used_percent REAL)""",
    """CREATE TABLE IF NOT EXISTS tasks(
        task_id TEXT PRIMARY KEY,
        category TEXT NOT NULL,
        name TEXT NOT NULL,
        command TEXT,
        first_seen TEXT NOT NULL,
        last_seen TEXT NOT NULL,
        status TEXT NOT NULL,
        metadata TEXT DEFAULT '{}')""",
    """CREATE TABLE IF NOT EXISTS task_samples(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        task_id TEXT NOT NULL,
        sample_id INTEGER NOT NULL,
        timestamp TEXT NOT NULL,
        pid INTEGER,
        status TEXT,
        cpu_percent REAL DEFAULT 0,
        memory_percent REAL DEFAULT 0,
        rss_bytes INTEGER DEFAULT 0)""",
    "CREATE INDEX IF NOT EXISTS idx_task_samples_task ON task_samples(task_id)",
]

MIGRATIONS = {
    2: [
        "ALTER TABLE tasks ADD COLUMN state TEXT NOT NULL DEFAULT 'active'",
        "ALTER TABLE tasks ADD COLUMN unit TEXT",
        "ALTER TABLE task_samples RENAME COLUMN status TO raw_status",
        "ALTER TABLE task_samples ADD COLUMN process_count INTEGER",
        "ALTER TABLE task_samples ADD COLUMN num_threads INTEGER",
        "ALTER TABLE task_samples ADD COLUMN num_fds INTEGER",
        "DROP INDEX IF EXISTS idx_task_samples_task",
        "CREATE INDEX idx_task_samples_task_ts ON task_samples(task_id, timestamp)",
        "CREATE INDEX idx_task_samples_sample ON task_samples(sample_id)",
        "CREATE INDEX idx_task_samples_ts ON task_samples(timestamp)",
        "CREATE INDEX idx_samples_ts ON samples(timestamp)",
        "CREATE INDEX idx_tasks_state ON tasks(state, last_seen)",
        """UPDATE tasks SET status = CASE
            WHEN status IN ('ok', 'warning', 'critical', 'gone') THEN status ELSE 'ok' END""",
    ],
}


def connect(db_path=None):
    path = db_path or load_settings().db_path
    conn = sqlite3.connect(path, timeout=30, isolation_level=None, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def get_connection():
    return connect()


@contextmanager
def transaction(conn):
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield conn
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    conn.execute("COMMIT")


def init_db(conn=None):
    own = conn is None
    conn = conn or connect()
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        with transaction(conn):
            version = conn.execute("PRAGMA user_version").fetchone()[0]
            if version < SCHEMA_VERSION:
                for statement in BASE_SCHEMA:
                    conn.execute(statement)
                for target in sorted(MIGRATIONS):
                    if target > version:
                        for statement in MIGRATIONS[target]:
                            conn.execute(statement)
                conn.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
    finally:
        if own:
            conn.close()


def store_cycle(conn, sample, tasks):
    """Persist one collection cycle atomically and mark unseen tasks as gone."""
    ts = sample["timestamp"]
    with transaction(conn):
        sample_id = conn.execute(
            "INSERT INTO samples(timestamp,hostname,cpu_percent,memory_percent,load1,"
            "disk_used_percent) VALUES(?,?,?,?,?,?)",
            (
                ts,
                sample["hostname"],
                sample["cpu_percent"],
                sample["memory_percent"],
                sample["load1"],
                sample["disk_used_percent"],
            ),
        ).lastrowid
        conn.executemany(
            """INSERT INTO tasks(task_id,category,name,command,unit,first_seen,last_seen,
                                 status,state,metadata)
               VALUES(:task_id,:category,:name,:command,:unit,:ts,:ts,:status,'active',:metadata)
               ON CONFLICT(task_id) DO UPDATE SET
                 name=excluded.name, command=excluded.command, unit=excluded.unit,
                 last_seen=excluded.last_seen, status=excluded.status, state='active',
                 metadata=excluded.metadata""",
            [{**t, "ts": ts} for t in tasks],
        )
        conn.executemany(
            """INSERT INTO task_samples(task_id,sample_id,timestamp,pid,raw_status,cpu_percent,
                                        memory_percent,rss_bytes,process_count,num_threads,num_fds)
               VALUES(:task_id,:sample_id,:ts,:pid,:raw_status,:cpu_percent,:memory_percent,
                      :rss_bytes,:process_count,:num_threads,:num_fds)""",
            [{**t, "ts": ts, "sample_id": sample_id} for t in tasks],
        )
        conn.execute(
            "UPDATE tasks SET state='gone', status='gone' WHERE state='active' AND last_seen<>?",
            (ts,),
        )
    return sample_id


def _cutoff(now, delta):
    return (now - delta).strftime(TIMESTAMP_FORMAT)


def prune(conn, task_samples_hours, samples_days, now=None):
    now = now or datetime.now(timezone.utc)
    task_samples_cutoff = _cutoff(now, timedelta(hours=task_samples_hours))
    samples_cutoff = _cutoff(now, timedelta(days=samples_days))
    with transaction(conn):
        deleted = {
            "task_samples": conn.execute(
                "DELETE FROM task_samples WHERE timestamp<?", (task_samples_cutoff,)
            ).rowcount,
            "samples": conn.execute(
                "DELETE FROM samples WHERE timestamp<?", (samples_cutoff,)
            ).rowcount,
            "tasks": conn.execute(
                "DELETE FROM tasks WHERE state='gone' AND last_seen<?", (task_samples_cutoff,)
            ).rowcount,
        }
    return deleted
