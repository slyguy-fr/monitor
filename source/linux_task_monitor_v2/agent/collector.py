import hashlib
import json
import os
import re
import socket
import subprocess
import time

import psutil

INTERPRETER_RE = re.compile(
    r"^(python|pypy|node|nodejs|java|ruby|perl|php|bash|sh|dash|zsh)[\d.]*$"
)
OPTIONS_WITH_VALUE = {"-cp", "-classpath", "--class-path", "-r", "--require", "-W", "-X"}
OPTIONS_IDENTIFYING_NEXT = {"-m", "-jar"}
INLINE_CODE_OPTIONS = {"-c", "-e"}
SERVICE_CGROUP_RE = re.compile(r"/([^/]+\.service)(?=/|$)")
STATUS_PRIORITY = ["zombie", "disk-sleep", "stopped", "tracing-stop", "dead", "running"]
MAX_PIDS_IN_METADATA = 50
SYSTEMD_SHOW_PROPERTIES = (
    "Id,LoadState,ActiveState,SubState,Result,NRestarts,MainPID,"
    "MemoryCurrent,CPUUsageNSec,ExecMainStatus"
)
SYSTEMD_UNITS_PER_CALL = 100


def utc_timestamp() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def task_id(category, identity):
    return hashlib.sha256(f"{category}:{identity}".encode()).hexdigest()[:16]


IGNORED_FSTYPES = {
    "squashfs",
    "tmpfs",
    "devtmpfs",
    "overlay",
    "iso9660",
    "ramfs",
    "nsfs",
    "autofs",
    "proc",
    "sysfs",
}
REMOTE_FSTYPE_PREFIXES = ("nfs", "cifs", "smb", "fuse.sshfs", "9p")


def parse_psi_avg60(text):
    for line in (text or "").splitlines():
        if line.startswith("some "):
            for part in line.split()[1:]:
                key, _, value = part.partition("=")
                if key == "avg60":
                    return float(value)
    return None


def read_psi(resource):
    try:
        with open(f"/proc/pressure/{resource}", encoding="utf-8") as f:
            return parse_psi_avg60(f.read())
    except OSError:
        return None


def parse_vmstat_counter(text, name):
    for line in (text or "").splitlines():
        key, _, value = line.partition(" ")
        if key == name:
            return int(value)
    return None


def read_oom_kills():
    try:
        with open("/proc/vmstat", encoding="utf-8") as f:
            return parse_vmstat_counter(f.read(), "oom_kill")
    except (OSError, ValueError):
        return None


def collect_system():
    times = psutil.cpu_times_percent(interval=1)
    iowait = getattr(times, "iowait", None)
    v = psutil.virtual_memory()
    d = psutil.disk_usage("/")
    load = os.getloadavg() if hasattr(os, "getloadavg") else (None, None, None)
    return {
        "timestamp": utc_timestamp(),
        "hostname": socket.gethostname(),
        # Same definition as psutil.cpu_percent(): busy = total - idle - iowait.
        "cpu_percent": round(max(0.0, 100.0 - times.idle - (iowait or 0.0)), 1),
        "memory_percent": v.percent,
        "load1": load[0],
        "load5": load[1],
        "load15": load[2],
        "disk_used_percent": d.percent,
        "cpu_count": psutil.cpu_count() or 1,
        "mem_total_bytes": v.total,
        "mem_available_bytes": v.available,
        "swap_percent": psutil.swap_memory().percent,
        "iowait_percent": iowait,
        "psi_cpu_some": read_psi("cpu"),
        "psi_memory_some": read_psi("memory"),
        "psi_io_some": read_psi("io"),
        "oom_kill_total": read_oom_kills(),
    }


def collect_disks():
    disks = []
    seen_devices = set()
    for part in psutil.disk_partitions(all=False):
        if part.fstype in IGNORED_FSTYPES or part.fstype.startswith(REMOTE_FSTYPE_PREFIXES):
            continue
        if part.device in seen_devices:
            continue
        try:
            usage = psutil.disk_usage(part.mountpoint)
            st = os.statvfs(part.mountpoint)
        except OSError:
            continue
        seen_devices.add(part.device)
        inodes_percent = (st.f_files - st.f_ffree) / st.f_files * 100 if st.f_files else None
        disks.append(
            {
                "mountpoint": part.mountpoint,
                "device": part.device,
                "fstype": part.fstype,
                "total_bytes": usage.total,
                "used_bytes": usage.used,
                "free_bytes": usage.free,
                "used_percent": usage.percent,
                "inodes_percent": inodes_percent,
            }
        )
    return disks


def script_argument(args):
    """Return the argument that identifies what an interpreter runs (script, module, jar)."""
    skip_next = False
    for i, arg in enumerate(args):
        if skip_next:
            skip_next = False
            continue
        if arg in OPTIONS_IDENTIFYING_NEXT:
            return f"{arg} {args[i + 1]}" if i + 1 < len(args) else arg
        if arg in INLINE_CODE_OPTIONS:
            return arg
        if arg in OPTIONS_WITH_VALUE:
            skip_next = True
            continue
        if arg.startswith("-"):
            continue
        return arg
    return None


def process_identity(info):
    """Stable identity shared by all processes running the same program in the same unit."""
    exe = info.get("exe") or ""
    cmdline = info.get("cmdline") or []
    name = info.get("name") or "unknown"
    program = exe or (cmdline[0] if cmdline else "") or name
    base = os.path.basename(cmdline[0] if cmdline else program)
    if INTERPRETER_RE.match(base) or INTERPRETER_RE.match(os.path.basename(program)):
        script = script_argument(cmdline[1:])
        if script:
            program = f"{program} {script}"
    unit = info.get("unit")
    return f"{unit}|{program}" if unit else program


def is_kernel_thread(info):
    return not info.get("exe") and not info.get("cmdline") and info.get("ppid") in (0, 2)


def service_unit_from_cgroup(cgroup_text):
    matches = SERVICE_CGROUP_RE.findall(cgroup_text or "")
    return matches[-1] if matches else None


def parse_fd_limit(limits_text):
    for line in (limits_text or "").splitlines():
        if line.startswith("Max open files"):
            soft = line.split()[3]
            return None if soft == "unlimited" else int(soft)
    return None


def read_fd_limit(pid):
    try:
        with open(f"/proc/{pid}/limits", encoding="utf-8") as f:
            return parse_fd_limit(f.read())
    except (OSError, ValueError, IndexError):
        return None


def read_service_unit(pid):
    try:
        with open(f"/proc/{pid}/cgroup", encoding="utf-8") as f:
            return service_unit_from_cgroup(f.read())
    except OSError:
        return None


def _group_status(status_counts):
    for status in STATUS_PRIORITY:
        if status in status_counts:
            return status
    return max(status_counts, key=status_counts.get) if status_counts else None


def _sum_or_none(values):
    known = [v for v in values if v is not None]
    return sum(known) if known else None


def build_process_tasks(infos):
    """Group raw process infos into one aggregated task per program."""
    groups = {}
    identities = {}
    for info in infos:
        identity = process_identity(info)
        identities[info["pid"]] = identity
        groups.setdefault(identity, []).append(info)
    zombie_children = {}
    for info in infos:
        if info.get("status") == psutil.STATUS_ZOMBIE:
            parent = identities.get(info.get("ppid"))
            if parent:
                zombie_children[parent] = zombie_children.get(parent, 0) + 1
    tasks = []
    for identity, members in groups.items():
        members.sort(key=lambda m: m["pid"])
        leader = members[0]
        cmdline = " ".join(leader.get("cmdline") or [])
        exe = leader.get("exe") or ""
        status_counts = {}
        for m in members:
            status_counts[m.get("status")] = status_counts.get(m.get("status"), 0) + 1
        fd_usage = [
            m["num_fds"] / m["fd_limit"] * 100
            for m in members
            if m.get("num_fds") is not None and m.get("fd_limit")
        ]
        tasks.append(
            {
                "task_id": task_id("process", identity),
                "category": "process",
                "name": leader.get("name") or "unknown",
                "command": cmdline or exe or leader.get("name") or "unknown",
                "unit": leader.get("unit"),
                "pid": leader["pid"],
                "raw_status": _group_status(status_counts),
                "status": "ok",
                "process_count": len(members),
                "cpu_percent": _sum_or_none(m.get("cpu_percent") for m in members),
                "memory_percent": sum(m.get("memory_percent") or 0 for m in members),
                "rss_bytes": sum(m.get("rss_bytes") or 0 for m in members),
                "num_threads": _sum_or_none(m.get("num_threads") for m in members),
                "num_fds": _sum_or_none(m.get("num_fds") for m in members),
                "zombie_children": zombie_children.get(identity, 0),
                "dstate_count": status_counts.get(psutil.STATUS_DISK_SLEEP, 0),
                "fd_usage_percent": max(fd_usage) if fd_usage else None,
                "restarts": None,
                "metadata": json.dumps(
                    {
                        "username": leader.get("username"),
                        "exe": exe,
                        "unit": leader.get("unit"),
                        "pids": [m["pid"] for m in members][:MAX_PIDS_IN_METADATA],
                        "status_counts": status_counts,
                    }
                ),
            }
        )
    return tasks


class ProcessCollector:
    ATTRS = [
        "pid",
        "ppid",
        "name",
        "username",
        "status",
        "memory_percent",
        "memory_info",
        "exe",
        "cmdline",
        "create_time",
        "num_threads",
        "num_fds",
    ]

    def __init__(self, include_kernel_threads=False):
        self.include_kernel_threads = include_kernel_threads
        self._seen = set()

    def read(self):
        infos = []
        seen = set()
        for p in psutil.process_iter(self.ATTRS, ad_value=None):
            try:
                i = dict(p.info)
                if not self.include_kernel_threads and is_kernel_thread(i):
                    continue
                key = (i["pid"], i.get("create_time"))
                seen.add(key)
                cpu = p.cpu_percent(None)
                # psutil needs a previous measurement: the first value is always 0.0.
                i["cpu_percent"] = cpu if key in self._seen else None
                mem = i.pop("memory_info")
                i["rss_bytes"] = mem.rss if mem else 0
                i["unit"] = read_service_unit(i["pid"])
                i["fd_limit"] = read_fd_limit(i["pid"]) if i.get("num_fds") is not None else None
                infos.append(i)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        self._seen = seen
        return infos

    def collect(self):
        return build_process_tasks(self.read())


def parse_list_units(output):
    units = []
    for line in output.splitlines():
        parts = line.lstrip("●* ").split(None, 4)
        if len(parts) < 4 or not parts[0].endswith(".service"):
            continue
        unit, load, active, sub = parts[:4]
        units.append(
            {
                "unit": unit,
                "load": load,
                "active": active,
                "sub": sub,
                "description": parts[4] if len(parts) > 4 else "",
            }
        )
    return units


def parse_systemctl_show(output):
    blocks = {}
    current = {}
    for line in output.splitlines() + [""]:
        if not line.strip():
            if current.get("Id"):
                blocks[current["Id"]] = current
            current = {}
            continue
        key, _, value = line.partition("=")
        current[key] = value
    return blocks


def _int_property(value):
    try:
        number = int(value)
    except (TypeError, ValueError):
        return None
    # systemd reports "unset" counters as UINT64_MAX.
    return None if number >= 2**63 else number


def systemd_status(active, sub):
    if active == "failed":
        return "critical"
    if sub == "auto-restart":
        return "warning"
    return "ok"


def _run_systemctl(args):
    try:
        result = subprocess.run(
            ["systemctl", *args, "--no-pager"],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None
    return result.stdout


class SystemdCollector:
    def __init__(self):
        self._previous_cpu = {}
        self._last_signature = {}

    def collect(self):
        listing = _run_systemctl(
            ["list-units", "--type=service", "--all", "--plain", "--no-legend"]
        )
        if listing is None:
            return []
        units = parse_list_units(listing)
        details = {}
        names = [u["unit"] for u in units]
        for start in range(0, len(names), SYSTEMD_UNITS_PER_CALL):
            chunk = names[start : start + SYSTEMD_UNITS_PER_CALL]
            output = _run_systemctl(["show", f"--property={SYSTEMD_SHOW_PROPERTIES}", "--", *chunk])
            details.update(parse_systemctl_show(output or ""))
        return self.build_tasks(units, details, time.monotonic(), psutil.virtual_memory().total)

    def build_tasks(self, units, details, now, total_memory):
        tasks = []
        current_cpu = {}
        for u in units:
            show = details.get(u["unit"], {})
            memory = _int_property(show.get("MemoryCurrent"))
            cpu_nsec = _int_property(show.get("CPUUsageNSec"))
            cpu_percent = None
            if cpu_nsec is not None:
                current_cpu[u["unit"]] = (cpu_nsec, now)
                previous = self._previous_cpu.get(u["unit"])
                if previous and now > previous[1] and cpu_nsec >= previous[0]:
                    cpu_percent = (cpu_nsec - previous[0]) / ((now - previous[1]) * 1e9) * 100
            main_pid = _int_property(show.get("MainPID"))
            restarts = _int_property(show.get("NRestarts"))
            raw_status = f"{u['active']}/{u['sub']}"
            # Idle units only get a history row when their state or restart count changes.
            signature = (raw_status, restarts)
            running = u["active"] == "active" and u["sub"] == "running"
            store_sample = running or self._last_signature.get(u["unit"]) != signature
            self._last_signature[u["unit"]] = signature
            tasks.append(
                {
                    "task_id": task_id("systemd", u["unit"]),
                    "category": "systemd",
                    "name": u["unit"],
                    "command": "",
                    "unit": u["unit"],
                    "pid": main_pid or None,
                    "raw_status": raw_status,
                    "status": systemd_status(u["active"], u["sub"]),
                    "process_count": None,
                    "cpu_percent": cpu_percent,
                    "memory_percent": (memory / total_memory * 100) if memory else 0,
                    "rss_bytes": memory or 0,
                    "num_threads": None,
                    "num_fds": None,
                    "zombie_children": None,
                    "dstate_count": None,
                    "fd_usage_percent": None,
                    "restarts": restarts,
                    "store_sample": store_sample,
                    "metadata": json.dumps(
                        {
                            "load": u["load"],
                            "active": u["active"],
                            "sub": u["sub"],
                            "description": u["description"],
                            "result": show.get("Result"),
                            "n_restarts": restarts,
                            "exec_main_status": _int_property(show.get("ExecMainStatus")),
                        }
                    ),
                }
            )
        self._previous_cpu = current_cpu
        return tasks


class Collector:
    def __init__(self, include_kernel_threads=False):
        self.processes = ProcessCollector(include_kernel_threads)
        self.systemd = SystemdCollector()

    def collect_all(self):
        sample = collect_system()
        tasks = self.processes.collect() + self.systemd.collect()
        return sample, tasks, collect_disks()
