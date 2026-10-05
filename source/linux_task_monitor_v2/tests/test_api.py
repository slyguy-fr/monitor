import pytest
from fastapi.testclient import TestClient

from agent.database import connect, init_db, store_cycle
from api.main import app
from tests.test_database import sample, task


@pytest.fixture
def client(db_path):
    init_db()
    conn = connect()
    store_cycle(conn, sample("2026-01-01T00:00:00Z"), [task("a"), task("b", category="systemd")])
    store_cycle(conn, sample("2026-01-01T00:00:15Z"), [task("a")])
    conn.close()
    with TestClient(app) as c:
        yield c


def test_unknown_task_returns_404(client):
    for path in ("/tasks/nope", "/tasks/nope/history", "/tasks/nope/analysis"):
        assert client.get(path).status_code == 404


def test_task_filters(client):
    assert [t["task_id"] for t in client.get("/tasks?state=active").json()] == ["a"]
    assert [t["task_id"] for t in client.get("/tasks?status=gone").json()] == ["b"]
    assert [t["task_id"] for t in client.get("/tasks?category=systemd").json()] == ["b"]


def test_task_history_and_analysis(client):
    assert len(client.get("/tasks/a/history").json()) == 2
    assert client.get("/tasks/a/analysis").json()["statistics"]["samples"] == 2


def test_findings_endpoints(client):
    from agent.config import Thresholds
    from agent.findings import run_analysis
    from tests.helpers import Timeline, service

    tl = Timeline()
    tl.cycle([service("vnc.service", "failed", "failed", result="exit-code")])
    run_analysis(tl.conn, Thresholds())
    found = client.get("/findings").json()
    assert [f["detector"] for f in found] == ["service_failed"]
    assert found[0]["evidence"]["result"] == "exit-code"
    assert client.get(f"/findings/{found[0]['id']}").json()["key"] == found[0]["key"]
    assert client.get("/findings/999").status_code == 404
    assert client.get("/findings?status=resolved").json() == []
    assert client.get("/analysis").json()["findings"][0]["id"] == found[0]["id"]
    task = client.get("/tasks/svc-vnc.service/analysis").json()
    assert [f["detector"] for f in task["findings"]] == ["service_failed"]
