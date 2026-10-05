import json

from .database import SEVERITY_RANK, apply_task_status, transaction
from .detectors import AnalysisContext, run_detectors


def _dedupe(findings):
    by_key = {}
    for f in findings:
        current = by_key.get(f.key)
        if current is None or SEVERITY_RANK[f.severity] > SEVERITY_RANK[current.severity]:
            by_key[f.key] = f
    return list(by_key.values())


def reconcile(conn, detected, failed_detectors, now, resolve_after):
    """Update the findings table; return (opened findings, resolved rows)."""
    opened, resolved = [], []
    with transaction(conn):
        current = {
            r["key"]: r for r in conn.execute("SELECT * FROM findings WHERE status = 'open'")
        }
        for f in _dedupe(detected):
            row = current.pop(f.key, None)
            if row:
                conn.execute(
                    """UPDATE findings SET severity=?, title=?, evidence=?, last_seen=?, misses=0
                       WHERE id=?""",
                    (f.severity, f.title, json.dumps(f.evidence), now, row["id"]),
                )
            else:
                conn.execute(
                    """INSERT INTO findings(key,detector,severity,subject_type,subject,task_id,
                                            title,evidence,first_seen,last_seen)
                       VALUES(?,?,?,?,?,?,?,?,?,?)""",
                    (
                        f.key,
                        f.detector,
                        f.severity,
                        f.subject_type,
                        f.subject,
                        f.task_id,
                        f.title,
                        json.dumps(f.evidence),
                        now,
                        now,
                    ),
                )
                opened.append(f)
        for row in current.values():
            if row["detector"] in failed_detectors:
                continue
            misses = row["misses"] + 1
            if misses >= resolve_after:
                conn.execute(
                    "UPDATE findings SET status='resolved', resolved_at=?, misses=? WHERE id=?",
                    (now, misses, row["id"]),
                )
                resolved.append(row)
            else:
                conn.execute("UPDATE findings SET misses=? WHERE id=?", (misses, row["id"]))
        # Tasks whose findings were resolved fall back to their collected status next cycle.
        apply_task_status(conn)
    return opened, resolved


def run_analysis(conn, thresholds):
    latest = conn.execute("SELECT * FROM samples ORDER BY id DESC LIMIT 1").fetchone()
    if not latest:
        return [], []
    open_keys = {r[0] for r in conn.execute("SELECT key FROM findings WHERE status = 'open'")}
    ctx = AnalysisContext(conn, latest, thresholds, open_keys)
    detected, failed = run_detectors(ctx)
    return reconcile(conn, detected, failed, latest["timestamp"], thresholds.resolve_after_runs)


SEVERITY_ORDER = "CASE f.severity WHEN 'critical' THEN 0 WHEN 'warning' THEN 1 ELSE 2 END"
FINDING_SELECT = """SELECT f.*, t.name task_name, t.unit task_unit, t.category task_category,
    (SELECT s.pid FROM task_samples s WHERE s.task_id = f.task_id ORDER BY s.id DESC LIMIT 1) pid
    FROM findings f LEFT JOIN tasks t ON t.task_id = f.task_id"""
NOT_ACKED = "(f.acked_until IS NULL OR f.acked_until <= ?)"


def decode(row):
    finding = dict(row)
    finding["evidence"] = json.loads(finding.get("evidence") or "{}")
    if "context" in finding:
        finding["context"] = json.loads(finding["context"]) if finding["context"] else None
    return finding
