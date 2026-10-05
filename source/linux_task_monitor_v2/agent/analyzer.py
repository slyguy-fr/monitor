from .collector import utc_timestamp
from .database import get_connection
from .findings import FINDING_SELECT, NOT_ACKED, SEVERITY_ORDER, decode
from .recommendations import recommend


def open_findings(
    conn, task_id=None, include_acked=False, severity=None, with_recommendation=False
):
    sql = FINDING_SELECT + " WHERE f.status = 'open'"
    params = []
    if task_id:
        sql += " AND f.task_id = ?"
        params.append(task_id)
    if severity:
        sql += " AND f.severity = ?"
        params.append(severity)
    if not include_acked:
        sql += " AND " + NOT_ACKED
        params.append(utc_timestamp())
    sql += f" ORDER BY {SEVERITY_ORDER}, f.first_seen"
    findings = [decode(r) for r in conn.execute(sql, params)]
    if with_recommendation:
        for f in findings:
            f["recommendation"] = recommend(f)
    return findings


def analyze_latest():
    """Open, non-acknowledged findings, most severe first."""
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
        return {
            "task": dict(t),
            "statistics": dict(s),
            "findings": open_findings(c, tid, include_acked=True, with_recommendation=True),
        }
    finally:
        c.close()
