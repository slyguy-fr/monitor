from .database import get_connection


def analyze_latest():
    c = get_connection()
    s = c.execute("SELECT * FROM samples ORDER BY id DESC LIMIT 1").fetchone()
    alerts = []
    if not s:
        return []
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
    for r in c.execute(
        "SELECT task_id,name,cpu_percent FROM task_samples JOIN tasks USING(task_id) WHERE sample_id=? ORDER BY cpu_percent DESC LIMIT 10",
        (s["id"],),
    ):
        if (r["cpu_percent"] or 0) > 80:
            alerts.append(
                {
                    "severity": "warning",
                    "type": "task_cpu",
                    "task_id": r["task_id"],
                    "message": f"{r['name']} utilise {r['cpu_percent']:.1f}% CPU",
                }
            )
    c.close()
    return alerts


def analyze_task(tid):
    c = get_connection()
    t = c.execute("SELECT * FROM tasks WHERE task_id=?", (tid,)).fetchone()
    if not t:
        c.close()
        return {"error": "Task not found"}
    s = c.execute(
        "SELECT COUNT(*) samples,AVG(cpu_percent) avg_cpu,MAX(cpu_percent) max_cpu,AVG(memory_percent) avg_memory,MAX(memory_percent) max_memory FROM task_samples WHERE task_id=?",
        (tid,),
    ).fetchone()
    r = {"task": dict(t), "statistics": dict(s), "alerts": []}
    if s["max_cpu"] and s["max_cpu"] > 80:
        r["alerts"].append("La tâche a atteint plus de 80% CPU.")
    if s["max_memory"] and s["max_memory"] > 80:
        r["alerts"].append("La tâche a atteint plus de 80% de mémoire.")
    c.close()
    return r
