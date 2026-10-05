import hashlib
import json
import os
import socket
import subprocess
import time

import psutil


def task_id(category, identity):
    return hashlib.sha256(f"{category}:{identity}".encode()).hexdigest()[:16]


def collect_system():
    v = psutil.virtual_memory()
    d = psutil.disk_usage("/")
    return {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "hostname": socket.gethostname(),
        "cpu_percent": psutil.cpu_percent(interval=1),
        "memory_percent": v.percent,
        "load1": os.getloadavg()[0] if hasattr(os, "getloadavg") else None,
        "disk_used_percent": d.percent,
    }


def collect_processes():
    out = []
    for p in psutil.process_iter(
        ["pid", "name", "username", "status", "memory_percent", "memory_info", "exe", "cmdline"]
    ):
        try:
            i = p.info
            n = i["name"] or "unknown"
            exe = i.get("exe") or ""
            cmd = " ".join(i.get("cmdline") or [])
            ident = exe or cmd or n
            out.append(
                {
                    "task_id": task_id("process", ident),
                    "category": "process",
                    "name": n,
                    "command": cmd or exe or n,
                    "pid": i["pid"],
                    "status": i["status"],
                    "cpu_percent": p.cpu_percent(None),
                    "memory_percent": i["memory_percent"] or 0,
                    "rss_bytes": i["memory_info"].rss if i["memory_info"] else 0,
                    "metadata": json.dumps({"username": i.get("username"), "exe": exe}),
                }
            )
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    return out


def collect_systemd():
    out = []
    try:
        r = subprocess.run(
            ["systemctl", "list-units", "--type=service", "--all", "--no-legend", "--no-pager"],
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return out
    for line in r.stdout.splitlines():
        p = line.split(None, 4)
        if len(p) < 4:
            continue
        unit, load, active, sub = p[:4]
        desc = p[4] if len(p) > 4 else ""
        status = "ok" if active == "active" and sub == "running" else "warning"
        out.append(
            {
                "task_id": task_id("systemd", unit),
                "category": "systemd",
                "name": unit,
                "command": "",
                "pid": None,
                "status": status,
                "cpu_percent": 0,
                "memory_percent": 0,
                "rss_bytes": 0,
                "metadata": json.dumps(
                    {"load": load, "active": active, "sub": sub, "description": desc}
                ),
            }
        )
    return out


def collect_all():
    return collect_system(), collect_processes() + collect_systemd()
