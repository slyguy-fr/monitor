from .database import get_connection

TASK_CPU_THRESHOLD = 80


def analyze_latest():
    c = get_connection()
    try:
        s = c.execute("SELECT * FROM samples ORDER BY id DESC LIMIT 1").fetchone()
        if not s:
            return []
        alerts = []
        if s["cpu_percent"] > 90:
            alerts.append(
                {
                    "severity": "warning",
                    "type": "high_cpu",
                    "message": f"CPU élevée: {s['cpu_percent']:.1f}%",
                }
            )
        if s["memory_percent"] > 90:
            alerts.append(
                {
                    "severity": "warning",
                    "type": "high_memory",
                    "message": f"Mémoire élevée: {s['memory_percent']:.1f}%",
                }
            )
        if s["disk_used_percent"] > 85:
            alerts.append(
                {
                    "severity": "warning",
                    "type": "disk_usage",
                    "message": f"Disque utilisé: {s['disk_used_percent']:.1f}%",
                }
            )
        rows = c.execute(
            "SELECT task_id,name,cpu_percent FROM task_samples JOIN tasks USING(task_id) "
            "WHERE sample_id=? AND cpu_percent>? ORDER BY cpu_percent DESC LIMIT 10",
            (s["id"], TASK_CPU_THRESHOLD),
        )
        for r in rows:
            alerts.append(
                {
                    "severity": "warning",
                    "type": "task_cpu",
                    "task_id": r["task_id"],
                    "message": f"{r['name']} utilise {r['cpu_percent']:.1f}% CPU",
                }
            )
        return alerts
    finally:
        c.close()


def analyze_task(tid):
    """Return statistics and alerts for a task, or None if the task does not exist."""
    c = get_connection()
    try:
        t = c.execute("SELECT * FROM tasks WHERE task_id=?", (tid,)).fetchone()
        if not t:
            return None
        s = c.execute(
            "SELECT COUNT(*) samples,AVG(cpu_percent) avg_cpu,MAX(cpu_percent) max_cpu,"
            "AVG(memory_percent) avg_memory,MAX(memory_percent) max_memory "
            "FROM task_samples WHERE task_id=?",
            (tid,),
        ).fetchone()
        r = {"task": dict(t), "statistics": dict(s), "alerts": []}
        if s["max_cpu"] and s["max_cpu"] > 80:
            r["alerts"].append("La tâche a atteint plus de 80% CPU.")
        if s["max_memory"] and s["max_memory"] > 80:
            r["alerts"].append("La tâche a atteint plus de 80% de mémoire.")
        return r
    finally:
        c.close()
