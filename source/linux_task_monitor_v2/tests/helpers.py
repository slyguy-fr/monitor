from datetime import datetime, timedelta, timezone

from agent.database import TIMESTAMP_FORMAT, connect, init_db, store_cycle

BASE = datetime(2026, 1, 1, tzinfo=timezone.utc)


def ts(seconds):
    return (BASE + timedelta(seconds=seconds)).strftime(TIMESTAMP_FORMAT)


def system(seconds, **kw):
    s = {
        "timestamp": ts(seconds),
        "hostname": "h",
        "cpu_percent": 10.0,
        "memory_percent": 30.0,
        "load1": 0.1,
        "load5": 0.1,
        "load15": 0.1,
        "disk_used_percent": 40.0,
        "cpu_count": 4,
        "mem_total_bytes": 8 * 1024**3,
        "mem_available_bytes": 4 * 1024**3,
        "swap_percent": 0.0,
        "iowait_percent": 0.0,
        "psi_cpu_some": 0.0,
        "psi_memory_some": 0.0,
        "psi_io_some": 0.0,
        "oom_kill_total": 0,
    }
    s.update(kw)
    return s


def proc(task_id, **kw):
    t = {
        "task_id": task_id,
        "category": "process",
        "name": task_id,
        "command": task_id,
        "unit": None,
        "pid": 100,
        "raw_status": "sleeping",
        "status": "ok",
        "process_count": 1,
        "cpu_percent": 1.0,
        "memory_percent": 1.0,
        "rss_bytes": 100 * 1024**2,
        "num_threads": 1,
        "num_fds": 3,
        "zombie_children": 0,
        "dstate_count": 0,
        "fd_usage_percent": 1.0,
        "restarts": None,
        "metadata": "{}",
    }
    t.update(kw)
    return t


def service(unit, active="active", sub="running", restarts=0, **kw):
    import json

    t = proc(
        f"svc-{unit}",
        category="systemd",
        name=unit,
        unit=unit,
        raw_status=f"{active}/{sub}",
        status="critical" if active == "failed" else "ok",
        restarts=restarts,
        metadata=json.dumps(
            {"active": active, "sub": sub, "n_restarts": restarts, "result": kw.pop("result", None)}
        ),
    )
    t.update(kw)
    return t


def disk(mount="/", used_percent=40.0, free_gb=60.0, total_gb=100.0, **kw):
    d = {
        "mountpoint": mount,
        "device": "/dev/sda1",
        "fstype": "ext4",
        "total_bytes": int(total_gb * 1024**3),
        "used_bytes": int((total_gb - free_gb) * 1024**3),
        "free_bytes": int(free_gb * 1024**3),
        "used_percent": used_percent,
        "inodes_percent": 10.0,
    }
    d.update(kw)
    return d


class Timeline:
    """Feeds synthetic cycles into a fresh database every `step` seconds."""

    def __init__(self, step=15):
        init_db()
        self.conn = connect()
        self.step = step
        self.t = 0

    def cycle(self, tasks=(), disks=(), **system_kw):
        store_cycle(self.conn, system(self.t, **system_kw), list(tasks), list(disks))
        self.t += self.step

    def run(self, seconds, tasks_fn=lambda t: [], disks_fn=lambda t: [], system_fn=lambda t: {}):
        end = self.t + seconds
        while self.t <= end:
            self.cycle(tasks_fn(self.t), disks_fn(self.t), **system_fn(self.t))
