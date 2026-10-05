from . import Finding, detector, finding_key, fmt_duration


@detector("sustained_task_cpu")
def sustained_task_cpu(ctx):
    th = ctx.thresholds
    window = th.task_cpu_window_seconds
    rows = ctx.conn.execute(
        """SELECT s.task_id, t.name, t.unit, COUNT(*) n, AVG(s.cpu_percent) avg_cpu,
                  MAX(s.cpu_percent) max_cpu, SUM(s.cpu_percent >= :trigger) above,
                  MIN(s.timestamp) first_ts, MAX(s.timestamp) last_ts
           FROM task_samples s JOIN tasks t USING(task_id)
           WHERE s.timestamp >= :since AND s.cpu_percent IS NOT NULL
             AND t.category = 'process' AND t.state = 'active'
           GROUP BY s.task_id HAVING avg_cpu >= :clear""",
        {
            "since": ctx.since(window),
            "trigger": th.task_cpu_percent,
            "clear": min(th.task_cpu_clear_percent, th.task_cpu_percent),
        },
    ).fetchall()
    capacity = ctx.cpu_count * 100
    findings = []
    for r in rows:
        key = finding_key("sustained_task_cpu", r["task_id"])
        if ctx.span_seconds(r["first_ts"], r["last_ts"]) < 0.8 * window:
            continue
        if ctx.is_open(key):
            triggered = r["avg_cpu"] >= th.task_cpu_clear_percent
        else:
            triggered = (
                r["avg_cpu"] >= th.task_cpu_percent
                and r["above"] / r["n"] >= th.task_cpu_min_fraction
            )
        if not triggered:
            continue
        critical = r["avg_cpu"] >= capacity * th.task_cpu_critical_capacity_percent / 100
        findings.append(
            Finding(
                detector="sustained_task_cpu",
                severity="critical" if critical else "warning",
                subject_type="task",
                subject=r["task_id"],
                task_id=r["task_id"],
                title=(
                    f"CPU soutenue : {r['name']} à {r['avg_cpu']:.0f}% "
                    f"en moyenne sur {fmt_duration(window)}"
                ),
                evidence={
                    "avg_cpu_percent": round(r["avg_cpu"], 1),
                    "max_cpu_percent": round(r["max_cpu"], 1),
                    "machine_share_percent": round(r["avg_cpu"] / capacity * 100, 1),
                    "cpu_count": ctx.cpu_count,
                    "samples": r["n"],
                    "window_seconds": window,
                    "unit": r["unit"],
                },
            )
        )
    return findings


@detector("cpu_saturation")
def cpu_saturation(ctx):
    th = ctx.thresholds
    window = th.system_window_seconds
    key = finding_key("cpu_saturation", "system")
    w = ctx.conn.execute(
        """SELECT COUNT(*) n, AVG(cpu_percent) avg_cpu, MIN(timestamp) first_ts,
                  MAX(timestamp) last_ts FROM samples WHERE timestamp >= ?""",
        (ctx.since(window),),
    ).fetchone()
    reasons, severity = [], None
    if w["n"] and ctx.span_seconds(w["first_ts"], w["last_ts"]) >= 0.8 * window:
        if w["avg_cpu"] >= ctx.threshold(key, th.system_cpu_percent, th.system_cpu_clear_percent):
            reasons.append(f"CPU moyenne {w['avg_cpu']:.0f}% sur {fmt_duration(window)}")
            severity = "critical" if w["avg_cpu"] >= th.system_cpu_critical_percent else "warning"
    load5 = ctx.latest["load5"]
    if load5 is not None and load5 >= th.load_per_core * ctx.cpu_count:
        reasons.append(f"charge 5 min {load5:.1f} pour {ctx.cpu_count} cœurs")
        severity = severity or "warning"
    psi = ctx.latest["psi_cpu_some"]
    if psi is not None and psi >= th.psi_cpu_percent:
        reasons.append(f"pression CPU {psi:.0f}% (PSI)")
        severity = severity or "warning"
    if not reasons:
        return []
    return [
        Finding(
            detector="cpu_saturation",
            severity=severity,
            subject_type="system",
            subject="system",
            title="Saturation CPU : " + ", ".join(reasons),
            evidence={
                "reasons": reasons,
                "avg_cpu_percent": round(w["avg_cpu"], 1) if w["avg_cpu"] is not None else None,
                "load5": load5,
                "cpu_count": ctx.cpu_count,
                "psi_cpu_some_avg60": psi,
                "window_seconds": window,
                "top_tasks": ctx.top_tasks("cpu_percent", window),
            },
        )
    ]
