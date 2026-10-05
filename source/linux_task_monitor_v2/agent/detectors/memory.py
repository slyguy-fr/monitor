from . import Finding, detector, finding_key, fmt_duration, linear_fit

MB = 1024 * 1024


@detector("memory_leak")
def memory_leak(ctx):
    th = ctx.thresholds
    rows = ctx.conn.execute(
        """SELECT s.task_id, t.name, t.unit, COUNT(*) n,
                  MIN(s.timestamp) first_ts, MAX(s.timestamp) last_ts,
                  SUM(s.x) sx, SUM(s.y) sy, SUM(s.x * s.x) sxx, SUM(s.x * s.y) sxy,
                  SUM(s.y * s.y) syy, MIN(s.process_count) min_pc, MAX(s.process_count) max_pc
           FROM (SELECT task_id, timestamp, process_count,
                        (julianday(timestamp) - julianday(:now)) * 24.0 x,
                        rss_bytes / 1048576.0 y
                 FROM task_samples WHERE timestamp >= :since AND rss_bytes > 0) s
           JOIN tasks t USING(task_id)
           WHERE t.category = 'process' AND t.state = 'active'
           GROUP BY s.task_id
           HAVING n >= :min_samples AND min_pc = max_pc""",
        {
            "now": ctx.latest["timestamp"],
            "since": ctx.since(th.leak_max_window_seconds),
            "min_samples": th.leak_min_samples,
        },
    ).fetchall()
    available_mb = (ctx.latest["mem_available_bytes"] or 0) / MB
    findings = []
    for r in rows:
        span = ctx.span_seconds(r["first_ts"], r["last_ts"])
        if span < th.leak_min_window_seconds:
            continue
        slope, intercept, r2 = linear_fit(r["n"], r["sx"], r["sy"], r["sxx"], r["sxy"], r["syy"])
        span_hours = span / 3600
        start_mb = intercept - slope * span_hours
        growth_mb = slope * span_hours
        if slope <= 0 or r2 < th.leak_min_r2 or start_mb <= 0:
            continue
        if (
            growth_mb < th.leak_min_growth_mb
            or growth_mb / start_mb * 100 < th.leak_min_growth_percent
        ):
            continue
        hours_to_exhaustion = available_mb / slope if available_mb else None
        critical = hours_to_exhaustion is not None and hours_to_exhaustion < th.leak_critical_hours
        findings.append(
            Finding(
                detector="memory_leak",
                severity="critical" if critical else "warning",
                subject_type="task",
                subject=r["task_id"],
                task_id=r["task_id"],
                title=(
                    f"Fuite mémoire probable : {r['name']} +{slope:.0f} Mo/h "
                    f"depuis {span_hours:.1f} h ({intercept:.0f} Mo)"
                ),
                evidence={
                    "rss_mb": round(intercept, 1),
                    "growth_mb_per_hour": round(slope, 1),
                    "growth_mb": round(growth_mb, 1),
                    "r2": round(r2, 3),
                    "window_hours": round(span_hours, 2),
                    "samples": r["n"],
                    "available_mb": round(available_mb, 1),
                    "hours_to_exhaustion": (
                        round(hours_to_exhaustion, 1) if hours_to_exhaustion is not None else None
                    ),
                    "unit": r["unit"],
                },
            )
        )
    return findings


@detector("memory_pressure")
def memory_pressure(ctx):
    th = ctx.thresholds
    window = th.system_window_seconds
    key = finding_key("memory_pressure", "system")
    w = ctx.conn.execute(
        """SELECT COUNT(*) n, AVG(memory_percent) avg_mem, MIN(timestamp) first_ts,
                  MAX(timestamp) last_ts FROM samples WHERE timestamp >= ?""",
        (ctx.since(window),),
    ).fetchone()
    first_swap = ctx.conn.execute(
        "SELECT swap_percent FROM samples WHERE timestamp >= ? AND swap_percent IS NOT NULL "
        "ORDER BY timestamp LIMIT 1",
        (ctx.since(window),),
    ).fetchone()
    reasons, severity = [], None

    def escalate(level):
        nonlocal severity
        if severity != "critical":
            severity = level

    if w["n"] and ctx.span_seconds(w["first_ts"], w["last_ts"]) >= 0.8 * window:
        if w["avg_mem"] >= ctx.threshold(key, th.memory_percent, th.memory_clear_percent):
            reasons.append(f"mémoire utilisée {w['avg_mem']:.0f}% sur {fmt_duration(window)}")
            escalate("critical" if w["avg_mem"] >= th.memory_critical_percent else "warning")
    swap = ctx.latest["swap_percent"]
    if swap is not None and swap >= th.swap_percent and first_swap and swap > first_swap[0] + 1:
        reasons.append(f"swap {swap:.0f}% et en hausse")
        escalate("warning")
    psi = ctx.latest["psi_memory_some"]
    if psi is not None and psi >= th.psi_memory_percent:
        reasons.append(f"pression mémoire {psi:.0f}% (PSI)")
        escalate("critical" if psi >= th.psi_memory_critical_percent else "warning")
    if not reasons:
        return []
    return [
        Finding(
            detector="memory_pressure",
            severity=severity,
            subject_type="system",
            subject="system",
            title="Pression mémoire : " + ", ".join(reasons),
            evidence={
                "reasons": reasons,
                "avg_memory_percent": round(w["avg_mem"], 1) if w["avg_mem"] is not None else None,
                "swap_percent": swap,
                "psi_memory_some_avg60": psi,
                "available_mb": round((ctx.latest["mem_available_bytes"] or 0) / MB, 1),
                "window_seconds": window,
                "top_tasks": ctx.top_tasks("rss_bytes", window),
            },
        )
    ]


@detector("oom_kill")
def oom_kill(ctx):
    th = ctx.thresholds
    latest = ctx.latest["oom_kill_total"]
    if latest is None:
        return []
    since = ctx.since(th.oom_window_seconds)
    base = (
        ctx.conn.execute(
            "SELECT oom_kill_total FROM samples "
            "WHERE timestamp <= ? AND oom_kill_total IS NOT NULL "
            "ORDER BY timestamp DESC LIMIT 1",
            (since,),
        ).fetchone()
        or ctx.conn.execute(
            "SELECT oom_kill_total FROM samples "
            "WHERE timestamp >= ? AND oom_kill_total IS NOT NULL "
            "ORDER BY timestamp LIMIT 1",
            (since,),
        ).fetchone()
    )
    killed = latest - base[0] if base else 0
    if killed <= 0:
        return []
    return [
        Finding(
            detector="oom_kill",
            severity="critical",
            subject_type="system",
            subject="system",
            title=(
                f"Manque de mémoire : {killed} processus tué(s) par le noyau (OOM) "
                f"sur les dernières {fmt_duration(th.oom_window_seconds)}"
            ),
            evidence={
                "killed": killed,
                "oom_kill_total": latest,
                "window_seconds": th.oom_window_seconds,
                "top_tasks": ctx.top_tasks("rss_bytes", th.oom_window_seconds),
            },
        )
    ]
