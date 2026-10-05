import json

from . import Finding, detector, fmt_duration


def _active_services(ctx):
    rows = ctx.conn.execute(
        "SELECT task_id, name, metadata FROM tasks WHERE category = 'systemd' AND state = 'active'"
    ).fetchall()
    for r in rows:
        try:
            meta = json.loads(r["metadata"] or "{}")
        except ValueError:
            meta = {}
        yield r, meta


@detector("service_failed")
def service_failed(ctx):
    return [
        Finding(
            detector="service_failed",
            severity="critical",
            subject_type="task",
            subject=r["task_id"],
            task_id=r["task_id"],
            title=f"Service en échec : {r['name']} ({meta.get('result') or 'raison inconnue'})",
            evidence={
                "unit": r["name"],
                "result": meta.get("result"),
                "exec_main_status": meta.get("exec_main_status"),
                "load": meta.get("load"),
                "description": meta.get("description"),
            },
        )
        for r, meta in _active_services(ctx)
        if meta.get("active") == "failed"
    ]


@detector("restart_loop")
def restart_loop(ctx):
    th = ctx.thresholds
    since = ctx.since(th.restart_window_seconds)
    findings = []
    for r, meta in _active_services(ctx):
        current = meta.get("n_restarts")
        if not current:
            continue
        base = (
            ctx.conn.execute(
                "SELECT restarts FROM task_samples WHERE task_id = ? AND timestamp <= ? "
                "AND restarts IS NOT NULL ORDER BY timestamp DESC LIMIT 1",
                (r["task_id"], since),
            ).fetchone()
            or ctx.conn.execute(
                "SELECT MIN(restarts) FROM task_samples WHERE task_id = ? AND timestamp > ?",
                (r["task_id"], since),
            ).fetchone()
        )
        if not base or base[0] is None:
            continue
        restarts = current - base[0]
        if restarts < th.restart_count:
            continue
        findings.append(
            Finding(
                detector="restart_loop",
                severity="critical",
                subject_type="task",
                subject=r["task_id"],
                task_id=r["task_id"],
                title=(
                    f"Redémarrages en boucle : {r['name']} a redémarré {restarts} fois "
                    f"en {fmt_duration(th.restart_window_seconds)}"
                ),
                evidence={
                    "unit": r["name"],
                    "restarts": restarts,
                    "n_restarts_total": current,
                    "window_seconds": th.restart_window_seconds,
                    "result": meta.get("result"),
                    "exec_main_status": meta.get("exec_main_status"),
                },
            )
        )
    return findings
