"""Detectors turn windows of stored samples into findings.

Each detector is a function ``(ctx) -> list[Finding]`` registered with ``@detector(name)``.
Detectors must be read-only and use ``ctx.now`` (time of the latest sample) as "now".
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from ..database import TIMESTAMP_FORMAT

log = logging.getLogger(__name__)

DETECTORS = {}
TASK_METRICS = {"cpu_percent", "rss_bytes", "memory_percent"}


def detector(name):
    def register(func):
        DETECTORS[name] = func
        func.detector_name = name
        return func

    return register


def fmt_duration(seconds):
    seconds = int(seconds)
    if seconds < 60:
        return f"{seconds} s"
    if seconds < 3600:
        return f"{seconds // 60} min"
    return f"{seconds / 3600:g} h"


def finding_key(detector_name, subject):
    return f"{detector_name}:{subject}"


def parse_timestamp(value):
    return datetime.strptime(value, TIMESTAMP_FORMAT).replace(tzinfo=timezone.utc)


@dataclass
class Finding:
    detector: str
    severity: str
    subject_type: str
    subject: str
    title: str
    evidence: dict = field(default_factory=dict)
    task_id: str | None = None

    @property
    def key(self):
        return finding_key(self.detector, self.subject)


class AnalysisContext:
    def __init__(self, conn, latest_sample, thresholds, open_keys=()):
        self.conn = conn
        self.latest = latest_sample
        self.thresholds = thresholds
        self.open_keys = frozenset(open_keys)
        self.now = parse_timestamp(latest_sample["timestamp"])

    @property
    def cpu_count(self):
        return self.latest["cpu_count"] or 1

    def since(self, seconds):
        return (self.now - timedelta(seconds=seconds)).strftime(TIMESTAMP_FORMAT)

    def is_open(self, key):
        return key in self.open_keys

    def threshold(self, key, trigger, clear):
        """Hysteresis: an open finding stays open until the value drops below `clear`."""
        return clear if self.is_open(key) else trigger

    @staticmethod
    def span_seconds(first_ts, last_ts):
        if not first_ts or not last_ts:
            return 0.0
        return (parse_timestamp(last_ts) - parse_timestamp(first_ts)).total_seconds()

    def top_tasks(self, metric, window_seconds, limit=5):
        if metric not in TASK_METRICS:
            raise ValueError(metric)
        rows = self.conn.execute(
            f"""SELECT s.task_id, t.name, t.unit, AVG(s.{metric}) value
                FROM task_samples s JOIN tasks t USING(task_id)
                WHERE s.timestamp >= ? AND t.category = 'process' AND s.{metric} IS NOT NULL
                GROUP BY s.task_id ORDER BY value DESC LIMIT ?""",
            (self.since(window_seconds), limit),
        ).fetchall()
        return [
            {"task_id": r["task_id"], "name": r["name"], "unit": r["unit"], metric: r["value"]}
            for r in rows
        ]


def linear_fit(n, sx, sy, sxx, sxy, syy):
    """Least squares y = a + b*x from aggregated sums. Returns (slope, intercept, r2)."""
    denominator_x = n * sxx - sx * sx
    if n < 2 or denominator_x <= 0:
        return 0.0, (sy / n if n else 0.0), 0.0
    slope = (n * sxy - sx * sy) / denominator_x
    intercept = (sy - slope * sx) / n
    denominator_y = n * syy - sy * sy
    r2 = (n * sxy - sx * sy) ** 2 / (denominator_x * denominator_y) if denominator_y > 0 else 0.0
    return slope, intercept, r2


def run_detectors(ctx):
    """Run every detector; return (findings, names of detectors that crashed)."""
    findings, failed = [], set()
    for name, func in DETECTORS.items():
        try:
            findings.extend(func(ctx))
        except Exception:
            log.exception("Détecteur %s en erreur", name)
            failed.add(name)
    return findings, failed


from . import cpu, disk, memory, processes, services  # noqa: E402,F401
