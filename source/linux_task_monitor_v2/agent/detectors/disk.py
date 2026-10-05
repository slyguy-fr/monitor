from . import Finding, detector, finding_key, fmt_duration, linear_fit

GB = 1024**3


@detector("disk_space")
def disk_space(ctx):
    th = ctx.thresholds
    latest = ctx.conn.execute(
        "SELECT * FROM disk_samples WHERE sample_id = ?", (ctx.latest["id"],)
    ).fetchall()
    findings = []
    for d in latest:
        key = finding_key("disk_space", d["mountpoint"])
        reasons, severity = [], None
        used = d["used_percent"]
        if used is not None and used >= ctx.threshold(key, th.disk_percent, th.disk_clear_percent):
            reasons.append(f"{used:.0f}% utilisé")
            severity = "critical" if used >= th.disk_critical_percent else "warning"
        inodes = d["inodes_percent"]
        if inodes is not None and inodes >= th.inode_percent:
            reasons.append(f"{inodes:.0f}% des inodes utilisés")
            if inodes >= th.inode_critical_percent:
                severity = "critical"
            severity = severity or "warning"
        forecast = _forecast_full(ctx, d)
        if forecast is not None and forecast < th.disk_full_critical_hours:
            reasons.append(f"plein dans environ {forecast:.0f} h au rythme actuel")
            severity = "critical"
        if not reasons:
            continue
        findings.append(
            Finding(
                detector="disk_space",
                severity=severity,
                subject_type="mount",
                subject=d["mountpoint"],
                title=f"Disque {d['mountpoint']} : " + ", ".join(reasons),
                evidence={
                    "reasons": reasons,
                    "mountpoint": d["mountpoint"],
                    "device": d["device"],
                    "used_percent": used,
                    "free_gb": round((d["free_bytes"] or 0) / GB, 2),
                    "total_gb": round((d["total_bytes"] or 0) / GB, 2),
                    "inodes_percent": round(inodes, 1) if inodes is not None else None,
                    "hours_to_full": round(forecast, 1) if forecast is not None else None,
                },
            )
        )
    return findings


def _forecast_full(ctx, disk):
    """Hours until the mount is full according to a linear fit, or None if not growing."""
    th = ctx.thresholds
    r = ctx.conn.execute(
        """SELECT COUNT(*) n, MIN(timestamp) first_ts, MAX(timestamp) last_ts,
                  SUM(x) sx, SUM(y) sy, SUM(x * x) sxx, SUM(x * y) sxy, SUM(y * y) syy
           FROM (SELECT timestamp, (julianday(timestamp) - julianday(:now)) * 24.0 x,
                        used_bytes / 1048576.0 y
                 FROM disk_samples WHERE mountpoint = :mount AND timestamp >= :since)""",
        {
            "now": ctx.latest["timestamp"],
            "mount": disk["mountpoint"],
            "since": ctx.since(th.disk_forecast_window_seconds),
        },
    ).fetchone()
    if r["n"] < th.disk_forecast_min_samples:
        return None
    if ctx.span_seconds(r["first_ts"], r["last_ts"]) < th.disk_forecast_min_window_seconds:
        return None
    slope, _, r2 = linear_fit(r["n"], r["sx"], r["sy"], r["sxx"], r["sxy"], r["syy"])
    if slope <= 0 or r2 < th.disk_forecast_min_r2:
        return None
    return (disk["free_bytes"] or 0) / 1048576.0 / slope


@detector("io_wait")
def io_wait(ctx):
    th = ctx.thresholds
    findings = []
    n = th.dstate_consecutive_samples
    rows = ctx.conn.execute(
        """SELECT s.task_id, t.name, t.unit, s.dstate_count FROM task_samples s
           JOIN tasks t USING(task_id)
           WHERE s.sample_id = ? AND s.dstate_count > 0 AND t.category = 'process'""",
        (ctx.latest["id"],),
    ).fetchall()
    for r in rows:
        recent = ctx.conn.execute(
            "SELECT dstate_count FROM task_samples WHERE task_id = ? "
            "ORDER BY timestamp DESC LIMIT ?",
            (r["task_id"], n),
        ).fetchall()
        if len(recent) < n or any(not x[0] for x in recent):
            continue
        findings.append(
            Finding(
                detector="io_wait",
                severity="warning",
                subject_type="task",
                subject=r["task_id"],
                task_id=r["task_id"],
                title=(
                    f"Attente disque : {r['name']} bloqué en état D sur {n} mesures consécutives"
                ),
                evidence={
                    "dstate_processes": r["dstate_count"],
                    "consecutive_samples": n,
                    "unit": r["unit"],
                },
            )
        )
    window = th.system_window_seconds
    w = ctx.conn.execute(
        """SELECT COUNT(*) n, AVG(iowait_percent) avg_iowait, MIN(timestamp) first_ts,
                  MAX(timestamp) last_ts FROM samples
           WHERE timestamp >= ? AND iowait_percent IS NOT NULL""",
        (ctx.since(window),),
    ).fetchone()
    reasons = []
    if (
        w["n"]
        and ctx.span_seconds(w["first_ts"], w["last_ts"]) >= 0.8 * window
        and w["avg_iowait"] >= th.iowait_percent
    ):
        reasons.append(f"iowait moyen {w['avg_iowait']:.0f}% sur {fmt_duration(window)}")
    psi = ctx.latest["psi_io_some"]
    if psi is not None and psi >= th.psi_io_percent:
        reasons.append(f"pression I/O {psi:.0f}% (PSI)")
    if reasons:
        findings.append(
            Finding(
                detector="io_wait",
                severity="warning",
                subject_type="system",
                subject="system",
                title="Attente disque élevée : " + ", ".join(reasons),
                evidence={
                    "reasons": reasons,
                    "avg_iowait_percent": (
                        round(w["avg_iowait"], 1) if w["avg_iowait"] is not None else None
                    ),
                    "psi_io_some_avg60": psi,
                    "window_seconds": window,
                },
            )
        )
    return findings
