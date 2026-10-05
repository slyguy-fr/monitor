from .database import get_connection
from .findings import decode

SEVERITY_ORDER = "CASE severity WHEN 'critical' THEN 0 WHEN 'warning' THEN 1 ELSE 2 END"


def open_findings(conn, task_id=None):
    sql = "SELECT * FROM findings WHERE status = 'open'"
    params = []
    if task_id:
        sql += " AND task_id = ?"
        params.append(task_id)
    sql += f" ORDER BY {SEVERITY_ORDER}, first_seen"
    return [decode(r) for r in conn.execute(sql, params)]


def analyze_latest():
    """Open findings, most severe first."""
    c = get_connection()
    try:
        return open_findings(c)
    finally:
        c.close()


def analyze_task(tid):
    """Return statistics and open findings for a task, or None if the task does not exist."""
    c = get_connection()
    try:
        t = c.execute("SELECT * FROM tasks WHERE task_id=?", (tid,)).fetchone()
        if not t:
            return None
        s = c.execute(
            "SELECT COUNT(*) samples,AVG(cpu_percent) avg_cpu,MAX(cpu_percent) max_cpu,"
            "AVG(memory_percent) avg_memory,MAX(memory_percent) max_memory,"
            "MAX(rss_bytes) max_rss_bytes FROM task_samples WHERE task_id=?",
            (tid,),
        ).fetchone()
        return {"task": dict(t), "statistics": dict(s), "findings": open_findings(c, tid)}
    finally:
        c.close()
