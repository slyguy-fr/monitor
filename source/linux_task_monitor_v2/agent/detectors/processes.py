from . import Finding, detector, fmt_duration


@detector("zombies")
def zombies(ctx):
    th = ctx.thresholds
    rows = ctx.conn.execute(
        """SELECT s.task_id, t.name, t.unit, s.zombie_children, s.pid FROM task_samples s
           JOIN tasks t USING(task_id)
           WHERE s.sample_id = ? AND s.zombie_children > 0 AND t.state = 'active'""",
        (ctx.latest["id"],),
    ).fetchall()
    findings = []
    for r in rows:
        last_clean = ctx.conn.execute(
            "SELECT MAX(timestamp) FROM task_samples WHERE task_id = ? "
            "AND (zombie_children IS NULL OR zombie_children = 0)",
            (r["task_id"],),
        ).fetchone()[0]
        streak_start = ctx.conn.execute(
            "SELECT MIN(timestamp) FROM task_samples WHERE task_id = ? AND timestamp > ?",
            (r["task_id"], last_clean or ""),
        ).fetchone()[0]
        duration = ctx.span_seconds(streak_start, ctx.latest["timestamp"])
        if duration < th.zombie_min_seconds and r["zombie_children"] < th.zombie_count:
            continue
        findings.append(
            Finding(
                detector="zombies",
                severity="warning",
                subject_type="task",
                subject=r["task_id"],
                task_id=r["task_id"],
                title=(
                    f"Processus zombies : {r['zombie_children']} enfant(s) de {r['name']} "
                    f"non récupérés depuis {duration / 60:.0f} min"
                ),
                evidence={
                    "zombie_children": r["zombie_children"],
                    "parent_pid": r["pid"],
                    "duration_seconds": int(duration),
                    "unit": r["unit"],
                },
            )
        )
    return findings


@detector("fd_exhaustion")
def fd_exhaustion(ctx):
    th = ctx.thresholds
    rows = ctx.conn.execute(
        """SELECT s.task_id, t.name, t.unit, s.fd_usage_percent, s.num_fds FROM task_samples s
           JOIN tasks t USING(task_id)
           WHERE s.sample_id = ? AND s.fd_usage_percent >= ? AND t.state = 'active'""",
        (ctx.latest["id"], th.fd_percent),
    ).fetchall()
    return [
        Finding(
            detector="fd_exhaustion",
            severity="critical" if r["fd_usage_percent"] >= th.fd_critical_percent else "warning",
            subject_type="task",
            subject=r["task_id"],
            task_id=r["task_id"],
            title=(
                f"Descripteurs de fichiers : {r['name']} utilise "
                f"{r['fd_usage_percent']:.0f}% de sa limite"
            ),
            evidence={
                "fd_usage_percent": round(r["fd_usage_percent"], 1),
                "num_fds": r["num_fds"],
                "unit": r["unit"],
            },
        )
        for r in rows
    ]


@detector("process_explosion")
def process_explosion(ctx):
    th = ctx.thresholds
    rows = ctx.conn.execute(
        """SELECT s.task_id, t.name, t.unit, s.process_count,
                  (SELECT MIN(process_count) FROM task_samples w
                   WHERE w.task_id = s.task_id AND w.timestamp >= :since) min_count
           FROM task_samples s JOIN tasks t USING(task_id)
           WHERE s.sample_id = :sample AND s.process_count >= :min_processes
             AND t.category = 'process' AND t.state = 'active'""",
        {
            "since": ctx.since(th.explosion_window_seconds),
            "sample": ctx.latest["id"],
            "min_processes": th.explosion_min_processes,
        },
    ).fetchall()
    return [
        Finding(
            detector="process_explosion",
            severity="warning",
            subject_type="task",
            subject=r["task_id"],
            task_id=r["task_id"],
            title=(
                f"Explosion de processus : {r['name']} est passé de {r['min_count']} à "
                f"{r['process_count']} processus en {fmt_duration(th.explosion_window_seconds)}"
            ),
            evidence={
                "process_count": r["process_count"],
                "min_process_count": r["min_count"],
                "window_seconds": th.explosion_window_seconds,
                "unit": r["unit"],
            },
        )
        for r in rows
        if r["min_count"] and r["process_count"] >= th.explosion_factor * r["min_count"]
    ]
