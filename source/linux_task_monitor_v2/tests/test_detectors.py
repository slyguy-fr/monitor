from agent.config import Thresholds
from agent.findings import run_analysis
from tests.helpers import Timeline, disk, proc, service

TH = Thresholds()


def analyze(tl, thresholds=TH):
    return run_analysis(tl.conn, thresholds)


def open_findings(tl):
    return {
        (r["detector"], r["subject"]): r
        for r in tl.conn.execute("SELECT * FROM findings WHERE status='open'")
    }


def test_quiet_system_has_no_findings(db_path):
    tl = Timeline()
    tl.run(600, lambda t: [proc("a"), service("cron.service")], lambda t: [disk()])
    opened, resolved = analyze(tl)
    assert opened == [] and resolved == []


def test_sustained_task_cpu_opens_resolves_with_hysteresis(db_path):
    tl = Timeline()
    tl.run(360, lambda t: [proc("busy", cpu_percent=95.0)])
    opened, _ = analyze(tl)
    assert [(f.detector, f.subject, f.severity) for f in opened] == [
        ("sustained_task_cpu", "busy", "warning")
    ]
    assert tl.conn.execute("SELECT status FROM tasks WHERE task_id='busy'").fetchone()[0] == (
        "warning"
    )
    # 75% is below the trigger (80) but above the clear threshold (70): stays open.
    tl.run(360, lambda t: [proc("busy", cpu_percent=75.0)])
    assert analyze(tl) == ([], [])
    tl.run(360, lambda t: [proc("busy", cpu_percent=5.0)])
    assert analyze(tl) == ([], [])  # first miss
    _, resolved = analyze(tl)
    assert [r["subject"] for r in resolved] == ["busy"]


def test_short_cpu_spike_is_ignored(db_path):
    tl = Timeline()
    tl.run(300, lambda t: [proc("spiky", cpu_percent=99.0 if t > 240 else 2.0)])
    assert analyze(tl) == ([], [])


def test_task_cpu_critical_when_most_of_the_machine(db_path):
    tl = Timeline()
    tl.run(360, lambda t: [proc("hog", cpu_percent=350.0)])
    opened, _ = analyze(tl)
    assert opened[0].severity == "critical"


def test_cpu_saturation_lists_top_tasks(db_path):
    tl = Timeline()
    tl.run(
        360,
        lambda t: [proc("hog", cpu_percent=300.0), proc("idle")],
        system_fn=lambda t: {"cpu_percent": 96.0, "load5": 7.0},
    )
    findings = open_findings(tl) if analyze(tl) else {}
    f = findings[("cpu_saturation", "system")]
    assert f["severity"] == "warning"
    assert '"name": "hog"' in f["evidence"]


def test_memory_leak_detected_on_steady_growth(db_path):
    tl = Timeline(step=60)
    mb = 1024**2
    tl.run(
        2 * 3600,
        lambda t: [
            proc("leaky", rss_bytes=int((200 + t / 3600 * 150) * mb)),
            proc("stable", rss_bytes=300 * mb + (t % 120) * mb),
        ],
    )
    opened, _ = analyze(tl)
    assert [(f.detector, f.subject) for f in opened] == [("memory_leak", "leaky")]
    assert 140 <= opened[0].evidence["growth_mb_per_hour"] <= 160


def test_memory_leak_ignores_worker_scaling(db_path):
    tl = Timeline(step=60)
    mb = 1024**2
    tl.run(
        2 * 3600,
        lambda t: [proc("pool", process_count=1 + t // 1800, rss_bytes=(1 + t // 1800) * 300 * mb)],
    )
    assert analyze(tl) == ([], [])


def test_memory_pressure_and_oom(db_path):
    tl = Timeline()
    tl.run(
        360,
        lambda t: [proc("big", rss_bytes=6 * 1024**3)],
        system_fn=lambda t: {"memory_percent": 96.0, "oom_kill_total": 2 if t > 300 else 0},
    )
    analyze(tl)
    found = open_findings(tl)
    assert found[("memory_pressure", "system")]["severity"] == "critical"
    assert found[("oom_kill", "system")]["severity"] == "critical"
    assert "2 processus" in found[("oom_kill", "system")]["title"]


def test_disk_space_threshold_and_forecast(db_path):
    tl = Timeline(step=300)
    # /data loses 1 GB every 5 min with 20 GB free: full in < 24 h, while only 80% used.
    tl.run(
        3 * 3600,
        disks_fn=lambda t: [
            disk("/", used_percent=90.0, free_gb=10.0),
            disk("/data", used_percent=60.0 + t / 3600, free_gb=56.0 - t / 300, device="/dev/sdb"),
        ],
    )
    analyze(tl)
    found = open_findings(tl)
    assert found[("disk_space", "/")]["severity"] == "warning"
    data = found[("disk_space", "/data")]
    assert data["severity"] == "critical" and "plein dans" in data["title"]


def test_failed_service_and_restart_loop(db_path):
    tl = Timeline()
    tl.cycle([service("vnc.service", "failed", "failed", result="exit-code")])
    tl.run(
        900,
        lambda t: [
            service("vnc.service", "failed", "failed", result="exit-code"),
            service("flappy.service", "activating", "auto-restart", restarts=t // 120),
        ],
    )
    analyze(tl)
    found = open_findings(tl)
    assert "exit-code" in found[("service_failed", "svc-vnc.service")]["title"]
    assert found[("restart_loop", "svc-flappy.service")]["severity"] == "critical"


def test_zombies_fd_and_process_explosion(db_path):
    tl = Timeline()
    tl.run(
        600,
        lambda t: [
            proc("parent", zombie_children=1 if t >= 300 else 0),
            proc("fds", fd_usage_percent=97.0),
            proc("forky", process_count=2 if t < 500 else 60),
        ],
    )
    analyze(tl)
    found = open_findings(tl)
    assert ("zombies", "parent") in found
    assert found[("fd_exhaustion", "fds")]["severity"] == "critical"
    assert ("process_explosion", "forky") in found


def test_task_in_d_state_and_system_iowait(db_path):
    tl = Timeline()
    tl.run(
        360,
        lambda t: [proc("stuck", dstate_count=1 if t >= 300 else 0)],
        system_fn=lambda t: {"iowait_percent": 35.0},
    )
    analyze(tl)
    found = open_findings(tl)
    assert ("io_wait", "stuck") in found and ("io_wait", "system") in found


def test_crashing_detector_does_not_resolve_its_findings(db_path, monkeypatch):
    from agent import detectors

    tl = Timeline()
    tl.run(360, lambda t: [proc("busy", cpu_percent=95.0)])
    analyze(tl)

    def boom(ctx):
        raise RuntimeError("boom")

    monkeypatch.setitem(detectors.DETECTORS, "sustained_task_cpu", boom)
    tl.run(360, lambda t: [proc("busy", cpu_percent=1.0)])
    for _ in range(3):
        assert analyze(tl) == ([], [])
    assert ("sustained_task_cpu", "busy") in open_findings(tl)
