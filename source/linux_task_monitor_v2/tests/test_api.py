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
