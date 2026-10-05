import json
import os

from agent.config import Thresholds
from agent.context import (
    DELETED_FILES_TITLE,
    attach_contexts,
    deleted_open_files,
    docker_reclaimable,
    fd_types,
    gather_context,
    sort_du,
)
from agent.findings import run_analysis
from tests.helpers import Timeline, service


class FakeRun:
    def __init__(self, outputs=None):
        self.calls = []
        self.outputs = outputs or {}

    def __call__(self, cmd, timeout):
        self.calls.append(cmd)
        return self.outputs.get(cmd[0], f"output of {cmd[0]}")


def make_proc(tmp_path, pid, comm, links):
    fd_dir = tmp_path / str(pid) / "fd"
    fd_dir.mkdir(parents=True)
    (tmp_path / str(pid) / "comm").write_text(comm + "\n")
    for i, target in enumerate(links):
        os.symlink(target, fd_dir / str(i))


def test_service_context_reads_journal_and_redacts(tmp_path):
    run = FakeRun({"journalctl": "start failed: --password=hunter2"})
    f = {"detector": "service_failed", "subject_type": "task", "evidence": {"unit": "a.service"}}
    items = gather_context(f, run, tmp_path)
    assert run.calls[0][:3] == ["journalctl", "-u", "a.service"]
    assert items[0]["output"] == "start failed: --password=***"
    assert items[0]["command"].startswith("journalctl -u a.service")


def test_disk_context_sorts_du_and_finds_deleted_files(tmp_path):
    make_proc(tmp_path, 42, "nginx", ["/data/log/access.log (deleted)", "/data/ok.log", "/etc/x"])
    make_proc(tmp_path, 43, "other", ["/var/log/x (deleted)"])
    run = FakeRun({"du": "5M\t/data/a\n900M\t/data/big\n20M\t/data\n"})
    f = {"detector": "disk_space", "subject": "/data", "subject_type": "mount", "evidence": {}}
    items = {i["title"]: i for i in gather_context(f, run, tmp_path)}
    du = items["Plus gros répertoires"]["output"].splitlines()
    assert du[0].endswith("/data/big") and du[-1].endswith("/data/a")
    deleted = items[DELETED_FILES_TITLE]
    assert deleted["count"] == 1 and "PID 42 (nginx)" in deleted["output"]
    assert not any(c[0] == "journalctl" for c in run.calls)


def test_deleted_open_files_on_root_mount(tmp_path):
    make_proc(tmp_path, 7, "app", ["/var/log/x (deleted)", "socket:[123]"])
    assert [d["path"] for d in deleted_open_files("/", tmp_path)] == ["/var/log/x"]


def test_fd_types(tmp_path):
    make_proc(tmp_path, 9, "app", ["socket:[1]", "socket:[2]", "pipe:[3]", "/tmp/f"])
    assert fd_types(9, tmp_path) == {"socket": 2, "pipe": 1, "file": 1}


def test_sort_du_keeps_unparseable_output():
    assert sort_du("du: cannot read") == "du: cannot read"


def test_crashing_gatherer_is_reported(tmp_path):
    def boom(cmd, timeout):
        raise RuntimeError("nope")

    items = gather_context({"detector": "cpu_saturation", "subject_type": "system"}, boom, tmp_path)
    assert items[0]["output"] == "erreur : nope"


def test_attach_contexts_runs_once_per_finding(db_path, tmp_path):
    tl = Timeline()
    tl.cycle([service("vnc.service", "failed", "failed", result="exit-code")])
    run_analysis(tl.conn, Thresholds())
    run = FakeRun()
    assert attach_contexts(tl.conn, run, tmp_path) == 1
    assert attach_contexts(tl.conn, run, tmp_path) == 0
    context = json.loads(tl.conn.execute("SELECT context FROM findings").fetchone()[0])
    assert context["diagnostics"][0]["title"] == "Derniers journaux du service"


def test_docker_reclaimable():
    empty = "TYPE TOTAL ACTIVE SIZE RECLAIMABLE\nImages 0 0 0B 0B\nBuild Cache 0 0 0B 0B"
    assert not docker_reclaimable(empty)
    assert docker_reclaimable("TYPE TOTAL ACTIVE SIZE RECLAIMABLE\nImages 5 1 2.1GB 1.5GB (71%)")
