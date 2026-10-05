import pytest

from agent.detectors import DETECTORS
from agent.recommendations import DISRUPTIVE, LOW, SAFE, TEMPLATES, memory_limit, recommend


def finding(detector, subject="t1", subject_type="task", **kw):
    f = {
        "detector": detector,
        "subject": subject,
        "subject_type": subject_type,
        "severity": "warning",
        "title": f"{detector} title",
        "evidence": {},
        "task_name": "app",
        "task_unit": None,
        "pid": 1234,
        "context": None,
    }
    f.update(kw)
    return f


def commands(rec):
    return [a["command"] for a in rec["actions"] if a["command"]]


def test_every_detector_has_a_template():
    assert set(TEMPLATES) == set(DETECTORS)


@pytest.mark.parametrize("detector", sorted(DETECTORS))
def test_recommendation_shape(detector):
    rec = recommend(finding(detector, evidence={"unit": "app.service"}))
    assert rec["summary"] == f"{detector} title"
    assert rec["probable_causes"] and rec["actions"]
    assert {a["risk"] for a in rec["actions"]} <= {SAFE, LOW, DISRUPTIVE}


def test_memory_leak_is_service_aware():
    service = recommend(finding("memory_leak", evidence={"unit": "app.service", "rss_mb": 1200}))
    assert "systemctl set-property app.service MemoryMax=2G" in commands(service)
    assert "systemctl restart app.service" in commands(service)
    plain = recommend(finding("memory_leak", evidence={"rss_mb": 300}))
    assert not any("systemctl" in c for c in commands(plain))
    assert "kill 1234" in commands(plain)


def test_task_cpu_uses_renice_without_unit():
    rec = recommend(finding("sustained_task_cpu"))
    assert "renice -n 10 -p 1234" in commands(rec)
    assert "top -H -p 1234" in commands(rec)


def test_missing_pid_uses_placeholder():
    rec = recommend(finding("zombies", pid=None))
    assert "kill -s SIGCHLD <PID>" in commands(rec)


def test_service_failed_explains_exit_code_and_tests_config():
    rec = recommend(
        finding(
            "service_failed",
            task_name="nginx.service",
            evidence={"unit": "nginx.service", "result": "exit-code", "exec_main_status": 1},
        )
    )
    assert "(code 1)" in rec["probable_causes"][0]
    assert "nginx -t" in commands(rec)
    assert "journalctl -u nginx.service -n 100 --no-pager" in commands(rec)


def test_cpu_saturation_targets_top_consumer():
    top = [{"task_id": "x", "name": "worker", "unit": "jobs.service", "cpu_percent": 300}]
    rec = recommend(finding("cpu_saturation", subject="system", evidence={"top_tasks": top}))
    assert "worker" in rec["probable_causes"][0]
    assert "systemctl set-property jobs.service CPUQuota=100%" in commands(rec)


def test_disk_actions_depend_on_mount_and_diagnostics():
    data = recommend(finding("disk_space", subject="/data", subject_type="mount"))
    assert not any("journalctl" in c for c in commands(data))
    context = {
        "diagnostics": [
            {
                "title": "Fichiers supprimés encore ouverts",
                "output": "PID 1",
                "count": 1,
                "significant_bytes": 300 * 1048576,
            },
            {"title": "Espace utilisé par Docker", "output": "Images 3", "reclaimable": True},
        ]
    }
    root = recommend(
        finding(
            "disk_space",
            subject="/",
            subject_type="mount",
            evidence={"inodes_percent": 95, "hours_to_full": 5},
            context=context,
        )
    )
    cmds = commands(root)
    assert "journalctl --vacuum-size=500M" in cmds and "docker system prune" in cmds
    assert any("300 Mo non libérés" in c for c in root["probable_causes"])
    assert any("plein dans environ 5 h" in c for c in root["probable_causes"])
    assert root["diagnostics"] == context["diagnostics"]


def test_memory_limit_rounding():
    assert memory_limit(100) == "256M"
    assert memory_limit(600) == "1024M"
    assert memory_limit(1200) == "2G"


def test_disk_ignores_small_deleted_files_and_empty_docker():
    context = {
        "diagnostics": [
            {"title": "Fichiers supprimés encore ouverts", "count": 3, "significant_bytes": 0},
            {"title": "Espace utilisé par Docker", "reclaimable": False},
        ]
    }
    rec = recommend(finding("disk_space", subject="/", subject_type="mount", context=context))
    assert "docker system prune" not in commands(rec)
    assert not any(a["risk"] == DISRUPTIVE for a in rec["actions"])
