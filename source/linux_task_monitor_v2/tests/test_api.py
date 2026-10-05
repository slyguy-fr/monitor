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


def test_dashboard_is_served(client):
    assert client.get("/").json()["status"] == "ok"
    browser = client.get("/", headers={"Accept": "text/html"}, follow_redirects=False)
    assert browser.status_code == 307 and browser.headers["location"] == "/ui/"
    page = client.get("/ui/")
    assert page.status_code == 200 and "Linux Task Monitor" in page.text
    assert client.get("/ui/app.js").status_code == 200


def test_dashboard_page_is_public_but_data_needs_token(client, monkeypatch):
    monkeypatch.setenv("LTM_API_TOKEN", "s3cret")
    assert client.get("/ui/").status_code == 200
    for path in ("/system/history", "/disks/latest", "/tasks/top"):
        assert client.get(path).status_code == 401


def test_system_history_buckets(client):
    assert len(client.get("/system/history?hours=1").json()) == 2
    rows = client.get("/system/history?hours=1&points=10").json()
    assert len(rows) == 1
    assert rows[0]["timestamp"] == "2026-01-01T00:00:00Z" and rows[0]["cpu_percent"] == 10.0


def test_system_history_empty(db_path):
    with TestClient(app) as c:
        assert c.get("/system/history").json() == []


def test_top_tasks_uses_latest_cycle(client):
    assert [t["task_id"] for t in client.get("/tasks/top").json()] == ["a"]
    assert client.get("/tasks/top?by=memory").json()[0]["rss_bytes"] == 10
    assert client.get("/tasks/top?by=bogus").status_code == 422


def test_disks_latest(client):
    disk = {
        "mountpoint": "/",
        "device": "/dev/vda1",
        "fstype": "ext4",
        "total_bytes": 100,
        "used_bytes": 40,
        "free_bytes": 60,
        "used_percent": 40.0,
        "inodes_percent": 3.0,
    }
    conn = connect()
    store_cycle(conn, sample("2026-01-01T00:00:30Z"), [task("a")], [disk])
    store_cycle(conn, sample("2026-01-01T00:00:45Z"), [task("a")], [disk | {"used_percent": 41.0}])
    conn.close()
    assert [d["used_percent"] for d in client.get("/disks/latest").json()] == [41.0]
