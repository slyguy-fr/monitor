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


@pytest.fixture
def failed_service(client):
    from agent.config import Thresholds
    from agent.findings import run_analysis
    from tests.helpers import Timeline, service

    tl = Timeline()
    tl.cycle([service("vnc.service", "failed", "failed", result="exit-code")])
    run_analysis(tl.conn, Thresholds())
    return client


def test_recommendations_and_ack(failed_service):
    client = failed_service
    recs = client.get("/recommendations").json()
    assert len(recs) == 1
    rec = recs[0]["recommendation"]
    assert any(a["command"] == "systemctl reset-failed vnc.service" for a in rec["actions"])
    finding_id = recs[0]["id"]
    assert client.get(f"/findings/{finding_id}").json()["recommendation"]["summary"]
    assert client.get("/tasks/svc-vnc.service").json()["open_findings"][0]["id"] == finding_id

    acked = client.post(f"/findings/{finding_id}/ack?hours=2").json()
    assert acked["acked_until"]
    assert client.get("/recommendations").json() == []
    assert client.get("/analysis").json()["findings"] == []
    assert len(client.get("/recommendations?include_acked=true").json()) == 1
    assert client.post(f"/findings/{finding_id}/ack?hours=0").json()["acked_until"] is None
    assert len(client.get("/recommendations").json()) == 1
    assert client.post("/findings/999/ack").status_code == 404


def test_api_token(client, monkeypatch):
    monkeypatch.setenv("LTM_API_TOKEN", "s3cret")
    assert client.get("/health").status_code == 200
    assert client.get("/tasks").status_code == 401
    assert client.get("/tasks", headers={"Authorization": "Bearer wrong"}).status_code == 401
    assert client.get("/tasks", headers={"Authorization": "Bearer s3cret"}).status_code == 200
