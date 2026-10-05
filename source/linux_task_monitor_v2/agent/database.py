import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone

from .config import load_settings

SCHEMA_VERSION = 4
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
    3: [
        *[
            f"ALTER TABLE samples ADD COLUMN {column}"
            for column in (
                "load5 REAL",
                "load15 REAL",
                "cpu_count INTEGER",
                "mem_total_bytes INTEGER",
                "mem_available_bytes INTEGER",
                "swap_percent REAL",
                "iowait_percent REAL",
                "psi_cpu_some REAL",
                "psi_memory_some REAL",
                "psi_io_some REAL",
                "oom_kill_total INTEGER",
            )
        ],
        *[
            f"ALTER TABLE task_samples ADD COLUMN {column}"
            for column in (
                "zombie_children INTEGER",
                "dstate_count INTEGER",
                "fd_usage_percent REAL",
                "restarts INTEGER",
            )
        ],
        """CREATE TABLE disk_samples(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sample_id INTEGER NOT NULL,
            timestamp TEXT NOT NULL,
            mountpoint TEXT NOT NULL,
            device TEXT,
            fstype TEXT,
            total_bytes INTEGER,
            used_bytes INTEGER,
            free_bytes INTEGER,
            used_percent REAL,
            inodes_percent REAL)""",
        "CREATE INDEX idx_disk_samples_mount_ts ON disk_samples(mountpoint, timestamp)",
        "CREATE INDEX idx_disk_samples_ts ON disk_samples(timestamp)",
        """CREATE TABLE findings(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key TEXT NOT NULL,
            detector TEXT NOT NULL,
            severity TEXT NOT NULL,
            subject_type TEXT NOT NULL,
            subject TEXT NOT NULL,
            task_id TEXT,
            title TEXT NOT NULL,
            evidence TEXT NOT NULL DEFAULT '{}',
            status TEXT NOT NULL DEFAULT 'open',
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            resolved_at TEXT,
            misses INTEGER NOT NULL DEFAULT 0)""",
        "CREATE UNIQUE INDEX idx_findings_open_key ON findings(key) WHERE status='open'",
        "CREATE INDEX idx_findings_status ON findings(status, severity)",
        "CREATE INDEX idx_findings_task ON findings(task_id)",
    ],
    4: [
        "ALTER TABLE findings ADD COLUMN context TEXT",
        "ALTER TABLE findings ADD COLUMN acked_until TEXT",
    ],
}

SEVERITY_RANK = {"ok": 0, "info": 0, "warning": 1, "critical": 2}

SAMPLE_COLUMNS = [
    "timestamp",
    "hostname",
    "cpu_percent",
    "memory_percent",
    "load1",
    "load5",
    "load15",
    "disk_used_percent",
    "cpu_count",
    "mem_total_bytes",
    "mem_available_bytes",
    "swap_percent",
    "iowait_percent",
    "psi_cpu_some",
    "psi_memory_some",
    "psi_io_some",
    "oom_kill_total",
]
TASK_SAMPLE_COLUMNS = [
    "pid",
    "raw_status",
    "cpu_percent",
    "memory_percent",
    "rss_bytes",
    "process_count",
    "num_threads",
    "num_fds",
    "zombie_children",
    "dstate_count",
    "fd_usage_percent",
    "restarts",
]
DISK_COLUMNS = [
    "mountpoint",
    "device",
    "fstype",
    "total_bytes",
    "used_bytes",
    "free_bytes",
    "used_percent",
    "inodes_percent",
]


def _insert_sql(table, columns):
    names = ",".join(columns)
    values = ",".join(f":{c}" for c in columns)
    return f"INSERT INTO {table}({names}) VALUES({values})"


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


def apply_task_status(conn):
    """Raise tasks.status to the highest severity of their open findings."""
    rows = conn.execute(
        """SELECT t.task_id, t.status, f.severity FROM tasks t
           JOIN findings f ON f.task_id = t.task_id
           WHERE f.status = 'open' AND t.state = 'active'"""
    ).fetchall()
    worst = {}
    for r in rows:
        current = worst.get(r["task_id"], r["status"])
        if SEVERITY_RANK.get(r["severity"], 0) > SEVERITY_RANK.get(current, 0):
            current = r["severity"]
        worst[r["task_id"]] = current
    conn.executemany(
        "UPDATE tasks SET status=? WHERE task_id=? AND status<>?",
        [(status, task_id, status) for task_id, status in worst.items()],
    )


def store_cycle(conn, sample, tasks, disks=()):
    """Persist one collection cycle atomically and mark unseen tasks as gone."""
    ts = sample["timestamp"]
    with transaction(conn):
        sample_id = conn.execute(
            _insert_sql("samples", SAMPLE_COLUMNS), {c: sample.get(c) for c in SAMPLE_COLUMNS}
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
            _insert_sql(
                "task_samples", ["task_id", "sample_id", "timestamp", *TASK_SAMPLE_COLUMNS]
            ),
            [
                {
                    "task_id": t["task_id"],
                    "sample_id": sample_id,
                    "timestamp": ts,
                    **{c: t.get(c) for c in TASK_SAMPLE_COLUMNS},
                }
                for t in tasks
                if t.get("store_sample", True)
            ],
        )
        conn.executemany(
            _insert_sql("disk_samples", ["sample_id", "timestamp", *DISK_COLUMNS]),
            [
                {"sample_id": sample_id, "timestamp": ts, **{c: d.get(c) for c in DISK_COLUMNS}}
                for d in disks
            ],
        )
        conn.execute(
            "UPDATE tasks SET state='gone', status='gone' WHERE state='active' AND last_seen<>?",
            (ts,),
        )
        apply_task_status(conn)
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
            "disk_samples": conn.execute(
                "DELETE FROM disk_samples WHERE timestamp<?", (samples_cutoff,)
            ).rowcount,
            "findings": conn.execute(
                "DELETE FROM findings WHERE status='resolved' AND resolved_at<?", (samples_cutoff,)
            ).rowcount,
        }
    return deleted
