"""Read-only diagnostics gathered once when a finding opens (journal tail, du, ps…)."""

import json
import logging
import os
import re
import shlex
import shutil
import subprocess
from collections import Counter
from pathlib import Path

from .collector import redact, utc_timestamp
from .database import transaction
from .findings import FINDING_SELECT, decode

log = logging.getLogger(__name__)

MAX_OUTPUT_CHARS = 4000
DEFAULT_TIMEOUT = 15
DU_TIMEOUT = 60
DELETED_FILES_TITLE = "Fichiers supprimés encore ouverts"
DOCKER_TITLE = "Espace utilisé par Docker"
# Deleted-but-open files smaller than this are normal (temp files) and not worth a restart.
DELETED_SIGNIFICANT_BYTES = 50 * 1024 * 1024
DOCKER_RECLAIMABLE_RE = re.compile(r"([\d.]+)\s*[kKMGT]?B(?:\s*\(\d+%\))?\s*$")
GATHERERS = {}


def gatherer(*detectors):
    def register(func):
        for name in detectors:
            GATHERERS.setdefault(name, []).append(func)
        return func

    return register


def _low_priority(cmd):
    prefix = []
    if shutil.which("nice"):
        prefix += ["nice", "-n", "19"]
    if shutil.which("ionice"):
        prefix += ["ionice", "-c", "3"]
    return prefix + cmd


def run_command(cmd, timeout=DEFAULT_TIMEOUT):
    try:
        p = subprocess.run(
            _low_priority(cmd),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            env={**os.environ, "LC_ALL": "C"},
        )
    except FileNotFoundError:
        return f"{cmd[0]} : commande introuvable"
    except subprocess.TimeoutExpired:
        return f"délai dépassé ({timeout} s)"
    out = p.stdout or ""
    if p.returncode and p.stderr:
        out += ("\n" if out else "") + p.stderr
    return out


def _clip(text):
    text = redact(text.strip())
    if len(text) > MAX_OUTPUT_CHARS:
        return text[:MAX_OUTPUT_CHARS] + "\n… (tronqué)"
    return text or "(aucune sortie)"


def _diag(title, output, command):
    return {"title": title, "command": command, "output": _clip(output)}


def _run(env, title, cmd, transform=None, timeout=DEFAULT_TIMEOUT, display=None):
    out = env.run(cmd, timeout)
    if transform:
        out = transform(out)
    return _diag(title, out, display or shlex.join(cmd))


def _head(n):
    return lambda out: "\n".join(out.splitlines()[:n])


def _tail(n):
    return lambda out: "\n".join(out.splitlines()[-n:])


def _matching(*needles, limit=20):
    def keep(out):
        lines = [line for line in out.splitlines() if any(n in line.lower() for n in needles)]
        return "\n".join(lines[-limit:]) or "aucune ligne correspondante"

    return keep


class Env:
    def __init__(self, run=run_command, proc_root="/proc"):
        self.run = run
        self.proc = Path(proc_root)


def _unit(f):
    unit = (f.get("evidence") or {}).get("unit") or f.get("task_unit")
    return unit if unit and unit.endswith(".service") else None


def _pid(f):
    return f.get("pid") or (f.get("evidence") or {}).get("parent_pid")


@gatherer("service_failed", "restart_loop")
def service_context(f, env):
    unit = _unit(f)
    if not unit:
        return []
    return [
        _run(
            env,
            "Derniers journaux du service",
            ["journalctl", "-u", unit, "-n", "30", "--no-pager", "-o", "short-iso"],
        ),
        _run(
            env,
            "Configuration de démarrage",
            [
                "systemctl",
                "show",
                unit,
                "-p",
                "ExecStart,Restart,RestartUSec,StartLimitBurst,StartLimitIntervalUSec,"
                "FragmentPath,DropInPaths",
            ],
        ),
    ]


@gatherer(
    "sustained_task_cpu", "memory_leak", "fd_exhaustion", "process_explosion", "zombies", "io_wait"
)
def process_context(f, env):
    pid = _pid(f)
    if f["subject_type"] != "task" or not pid:
        return []
    return [
        _run(
            env,
            "Processus",
            [
                "ps",
                "-o",
                "pid,ppid,user,etime,pcpu,pmem,rss,nlwp,stat,wchan:20,args",
                "-p",
                str(pid),
            ],
        )
    ]


@gatherer("sustained_task_cpu")
def threads_context(f, env):
    pid = _pid(f)
    if not pid:
        return []
    cmd = ["ps", "-L", "-o", "tid,pcpu,stat,comm", "--sort=-pcpu", "-p", str(pid)]
    return [_run(env, "Threads les plus actifs", cmd, _head(16))]


@gatherer("memory_leak")
def unit_memory_context(f, env):
    unit = _unit(f)
    if not unit:
        return []
    props = "MemoryCurrent,MemoryHigh,MemoryMax,ActiveEnterTimestamp,NRestarts"
    return [_run(env, "Mémoire et uptime du service", ["systemctl", "show", unit, "-p", props])]


@gatherer("zombies", "process_explosion")
def children_context(f, env):
    pid = _pid(f)
    if not pid:
        return []
    cmd = ["ps", "--ppid", str(pid), "-o", "pid,etime,stat,args"]
    return [_run(env, "Processus enfants", cmd, _head(21))]


def fd_types(pid, proc_root="/proc"):
    counts = Counter()
    for fd in (Path(proc_root) / str(pid) / "fd").iterdir():
        try:
            target = os.readlink(fd)
        except OSError:
            continue
        kind = target.split(":", 1)[0] if ":" in target and not target.startswith("/") else "file"
        counts[kind] += 1
    return counts


@gatherer("fd_exhaustion")
def fd_context(f, env):
    pid = _pid(f)
    if not pid:
        return []
    try:
        counts = fd_types(pid, env.proc)
        out = "\n".join(f"{kind:12} {n}" for kind, n in counts.most_common())
    except OSError as e:
        out = f"lecture impossible : {e}"
    return [_diag("Types de descripteurs ouverts", out, f"ls -l /proc/{pid}/fd")]


@gatherer("io_wait")
def io_context(f, env):
    items = []
    if f["subject_type"] == "system":
        items.append(
            _run(
                env,
                "Processus en attente disque (état D)",
                ["ps", "-eo", "pid,stat,wchan:32,args"],
                lambda out: "\n".join(
                    line for i, line in enumerate(out.splitlines()) if i == 0 or " D" in line[:12]
                ),
            )
        )
    items.append(_run(env, "Pression I/O", ["cat", "/proc/pressure/io"]))
    items.append(_run(env, "Montages réseau", ["findmnt", "-t", "nfs,nfs4,cifs,smb3"]))
    return items


@gatherer("cpu_saturation")
def cpu_context(f, env):
    return [
        _run(
            env,
            "Processus les plus consommateurs de CPU",
            ["ps", "-eo", "pid,user,pcpu,pmem,etime,args", "--sort=-pcpu"],
            _head(11),
        ),
        _run(env, "Pression CPU", ["cat", "/proc/pressure/cpu"]),
    ]


@gatherer("memory_pressure", "oom_kill")
def memory_context(f, env):
    return [
        _run(
            env,
            "Processus les plus consommateurs de mémoire",
            ["ps", "-eo", "pid,user,rss,pmem,etime,args", "--sort=-rss"],
            _head(11),
        ),
        _run(env, "Mémoire", ["free", "-m"]),
    ]


@gatherer("oom_kill")
def oom_context(f, env):
    cmd = ["journalctl", "-k", "--since", "-1h", "--no-pager", "-o", "short-iso"]
    return [
        _run(
            env,
            "Messages OOM du noyau",
            cmd,
            _matching("out of memory", "killed process", "oom-kill"),
            display=shlex.join(cmd) + " | grep -iE 'out of memory|killed process'",
        )
    ]


def sort_du(out, limit=15):
    rows = []
    for line in out.splitlines():
        size, _, path = line.partition("\t")
        if size.isdigit():
            rows.append((int(size), path))
    rows.sort(reverse=True)
    return "\n".join(f"{size:>8} Mo  {path}" for size, path in rows[:limit]) or out


def docker_reclaimable(out):
    for line in out.splitlines()[1:]:
        m = DOCKER_RECLAIMABLE_RE.search(line)
        if m and float(m.group(1)) > 0:
            return True
    return False


def deleted_open_files(mount, proc_root="/proc", limit=10):
    found = {}
    prefix = mount.rstrip("/") + "/"
    for proc in Path(proc_root).iterdir():
        if not proc.name.isdigit():
            continue
        try:
            fds = list((proc / "fd").iterdir())
            comm = (proc / "comm").read_text().strip()
        except OSError:
            continue
        for fd in fds:
            try:
                target = os.readlink(fd)
            except OSError:
                continue
            if not target.endswith(" (deleted)") or not target.startswith(prefix):
                continue
            try:
                size = os.stat(fd).st_size
            except OSError:
                size = 0
            key = (int(proc.name), target[: -len(" (deleted)")])
            found[key] = (comm, max(size, found.get(key, ("", 0))[1]))
    rows = sorted(found.items(), key=lambda item: item[1][1], reverse=True)[:limit]
    return [
        {"pid": pid, "comm": comm, "path": path, "size_bytes": size}
        for (pid, path), (comm, size) in rows
    ]


@gatherer("disk_space")
def disk_context(f, env):
    mount = f["subject"]
    items = [
        _run(env, "Espace du volume", ["df", "-h", mount]),
        _run(env, "Inodes du volume", ["df", "-i", mount]),
        _run(
            env,
            "Plus gros répertoires",
            ["du", "-x", "--max-depth=2", "-BM", mount],
            lambda out: sort_du(out.replace("M\t", "\t")),
            timeout=DU_TIMEOUT,
            display=f"du -xh --max-depth=2 {shlex.quote(mount)} | sort -rh | head -15",
        ),
    ]
    if mount in ("/", "/var", "/var/log"):
        items.append(_run(env, "Taille du journal systemd", ["journalctl", "--disk-usage"]))
    if shutil.which("docker") and mount in ("/", "/var", "/var/lib", "/var/lib/docker"):
        docker = _run(env, DOCKER_TITLE, ["docker", "system", "df"])
        items.append(docker | {"reclaimable": docker_reclaimable(docker["output"])})
    try:
        files = deleted_open_files(mount, env.proc)
        out = "\n".join(
            f"PID {d['pid']} ({d['comm']}) {d['size_bytes'] // 1048576} Mo  {d['path']}"
            for d in files
        )
    except OSError as e:
        files, out = [], f"lecture impossible : {e}"
    items.append(
        _diag(DELETED_FILES_TITLE, out or "aucun", f"find /proc/*/fd -lname '{mount}*(deleted)'")
        | {
            "count": len(files),
            "significant_bytes": sum(
                d["size_bytes"] for d in files if d["size_bytes"] >= DELETED_SIGNIFICANT_BYTES
            ),
        }
    )
    return items


def gather_context(finding, run=run_command, proc_root="/proc"):
    env = Env(run, proc_root)
    items = []
    for func in GATHERERS.get(finding["detector"], []):
        try:
            items.extend(func(finding, env))
        except Exception as e:
            log.exception("Diagnostic %s en erreur", func.__name__)
            items.append({"title": func.__name__, "command": None, "output": f"erreur : {e}"})
    return items


def attach_contexts(conn, run=run_command, proc_root="/proc", limit=10):
    """Gather diagnostics for open findings that do not have any yet."""
    rows = conn.execute(
        FINDING_SELECT + " WHERE f.status = 'open' AND f.context IS NULL ORDER BY f.id LIMIT ?",
        (limit,),
    ).fetchall()
    for row in rows:
        context = {
            "gathered_at": utc_timestamp(),
            "diagnostics": gather_context(decode(row), run, proc_root),
        }
        with transaction(conn):
            conn.execute(
                "UPDATE findings SET context = ? WHERE id = ?", (json.dumps(context), row["id"])
            )
    return len(rows)
