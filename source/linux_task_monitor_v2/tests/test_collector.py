import json

from agent.collector import (
    SystemdCollector,
    build_process_tasks,
    is_kernel_thread,
    parse_list_units,
    parse_systemctl_show,
    process_identity,
    service_unit_from_cgroup,
    systemd_status,
)

LIST_UNITS = """\
cron.service      loaded    active   running Regular background program processing daemon
● vncserver.service loaded  failed   failed  TigerVNC Server service
zfs-mount.service not-found inactive dead    zfs-mount.service
foo.service       loaded    activating auto-restart Foo
"""

SHOW = """\
Id=cron.service
ActiveState=active
SubState=running
MainPID=569
MemoryCurrent=454656
CPUUsageNSec=2000000000
NRestarts=0

Id=vncserver.service
ActiveState=failed
SubState=failed
MainPID=0
MemoryCurrent=[not set]
CPUUsageNSec=18446744073709551615
NRestarts=3
"""


def proc(pid, exe, cmdline, **kw):
    info = {
        "pid": pid,
        "ppid": 1,
        "name": kw.pop("name", exe.rsplit("/", 1)[-1]),
        "exe": exe,
        "cmdline": cmdline,
        "status": "sleeping",
        "cpu_percent": 1.0,
        "memory_percent": 1.0,
        "rss_bytes": 100,
        "num_threads": 2,
        "num_fds": 5,
        "username": "root",
        "unit": None,
    }
    info.update(kw)
    return info


def test_parse_list_units_keeps_failed_units_separate():
    units = parse_list_units(LIST_UNITS)
    assert [u["unit"] for u in units] == [
        "cron.service",
        "vncserver.service",
        "zfs-mount.service",
        "foo.service",
    ]
    assert units[1]["active"] == "failed"
    assert units[2]["load"] == "not-found"


def test_systemd_status_vocabulary():
    assert systemd_status("failed", "failed") == "critical"
    assert systemd_status("activating", "auto-restart") == "warning"
    assert systemd_status("inactive", "dead") == "ok"
    assert systemd_status("active", "exited") == "ok"


def test_parse_systemctl_show_blocks():
    blocks = parse_systemctl_show(SHOW)
    assert set(blocks) == {"cron.service", "vncserver.service"}
    assert blocks["vncserver.service"]["NRestarts"] == "3"


def test_systemd_tasks_compute_cpu_from_usage_delta():
    collector = SystemdCollector()
    units = parse_list_units(LIST_UNITS)[:2]
    first = collector.build_tasks(units, parse_systemctl_show(SHOW), 100.0, 1_000_000)
    assert first[0]["cpu_percent"] is None
    assert first[0]["rss_bytes"] == 454656
    assert first[1]["status"] == "critical"
    assert first[1]["pid"] is None
    assert json.loads(first[1]["metadata"])["n_restarts"] == 3

    later = parse_systemctl_show(SHOW.replace("CPUUsageNSec=2000000000", "CPUUsageNSec=7000000000"))
    second = collector.build_tasks(units, later, 110.0, 1_000_000)
    assert second[0]["cpu_percent"] == 50.0
    assert second[1]["cpu_percent"] is None


def test_workers_of_same_program_are_grouped():
    tasks = build_process_tasks(
        [
            proc(10, "/usr/bin/chrome", ["/usr/bin/chrome"]),
            proc(11, "/usr/bin/chrome", ["/usr/bin/chrome", "--type=renderer"], cpu_percent=None),
            proc(12, "/usr/bin/chrome", ["/usr/bin/chrome", "--type=gpu"], status="zombie"),
        ]
    )
    assert len(tasks) == 1
    t = tasks[0]
    assert t["process_count"] == 3
    assert t["cpu_percent"] == 2.0
    assert t["rss_bytes"] == 300
    assert t["num_fds"] == 15
    assert t["pid"] == 10
    assert t["raw_status"] == "zombie"
    assert json.loads(t["metadata"])["pids"] == [10, 11, 12]


def test_first_cpu_sample_is_unknown_when_no_measurement():
    tasks = build_process_tasks([proc(10, "/usr/bin/foo", ["foo"], cpu_percent=None)])
    assert tasks[0]["cpu_percent"] is None


def test_interpreter_scripts_are_separate_tasks():
    a = process_identity(proc(1, "/usr/bin/python3.10", ["python3", "-u", "/srv/a.py"]))
    b = process_identity(proc(2, "/usr/bin/python3.10", ["python3", "/srv/b.py", "--x"]))
    m = process_identity(proc(3, "/usr/bin/python3.10", ["python3", "-m", "http.server"]))
    j = process_identity(proc(4, "/usr/bin/java", ["java", "-cp", "lib/*", "-jar", "app.jar"]))
    assert a == "/usr/bin/python3.10 /srv/a.py"
    assert b == "/usr/bin/python3.10 /srv/b.py"
    assert m == "/usr/bin/python3.10 -m http.server"
    assert j == "/usr/bin/java -jar app.jar"
    assert process_identity(proc(5, "/usr/sbin/nginx", ["nginx", "-g", "x"])) == "/usr/sbin/nginx"


def test_same_program_in_different_units_is_not_merged():
    a = process_identity(proc(1, "/usr/bin/postgres", ["postgres"], unit="pg-a.service"))
    b = process_identity(proc(2, "/usr/bin/postgres", ["postgres"], unit="pg-b.service"))
    assert a != b


def test_service_unit_from_cgroup():
    assert service_unit_from_cgroup("0::/system.slice/nginx.service\n") == "nginx.service"
    assert (
        service_unit_from_cgroup(
            "0::/user.slice/user-1000.slice/user@1000.service/app.slice/x.service"
        )
        == "x.service"
    )
    assert service_unit_from_cgroup("0::/user.slice/user-1000.slice/session-3.scope") is None


def test_kernel_thread_detection():
    assert is_kernel_thread({"exe": None, "cmdline": [], "ppid": 2})
    assert not is_kernel_thread({"exe": "/usr/bin/x", "cmdline": ["x"], "ppid": 2})
