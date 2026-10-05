import io
import json
import urllib.error
from datetime import datetime, timedelta, timezone

from agent.config import LLMSettings, Thresholds
from agent.findings import run_analysis
from agent.summary import build_payload, fallback_summary, latest_summary, update_summary
from tests.helpers import Timeline, service

NOW = datetime(2026, 1, 1, 1, tzinfo=timezone.utc)
LLM = LLMSettings(model="test-model", api_key="sk-test", base_url="http://llm.local/v1/")


class FakeOpener:
    def __init__(self, answer="Résumé de l'IA", error=None):
        self.requests = []
        self.answer = answer
        self.error = error

    def __call__(self, request, timeout):
        self.requests.append(request)
        if self.error:
            raise self.error
        return io.BytesIO(json.dumps({"choices": [{"message": {"content": self.answer}}]}).encode())


def failed_service_timeline():
    tl = Timeline()
    tl.cycle([service("vnc.service", "failed", "failed", result="exit-code")])
    run_analysis(tl.conn, Thresholds())
    return tl


def rec(**kw):
    return {"probable_causes": [], "actions": [], "diagnostics": [], **kw}


def test_fallback_summary():
    assert "Aucun problème" in fallback_summary([])
    text = fallback_summary(
        [
            {
                "severity": "critical",
                "title": "Service en échec : a.service",
                "recommendation": rec(
                    probable_causes=["config invalide"],
                    actions=[{"title": "Lire le journal", "command": "journalctl -u a"}],
                ),
            }
        ]
    )
    assert "1 problème(s) ouvert(s), dont 1 critique(s)" in text
    assert "config invalide" in text and "(`journalctl -u a`)" in text


def test_payload_is_redacted_and_clipped():
    f = {
        "severity": "warning",
        "title": "t",
        "first_seen": "x",
        "evidence": {"command": "app --password=hunter2"},
        "recommendation": rec(diagnostics=[{"title": "log", "output": "a" * 5000}]),
    }
    payload = build_payload([f], {"hostname": "h", "cpu_percent": 5.0, "other": 1})
    assert payload["serveur"] == {"hostname": "h", "cpu_percent": 5.0}
    problem = payload["problemes"][0]
    assert problem["preuves"]["command"] == "app --password=***"
    assert len(problem["diagnostics"][0]["sortie"]) == 800


def test_without_llm_stores_auto_summary_once(db_path):
    tl = failed_service_timeline()
    assert update_summary(tl.conn, LLMSettings(), now=NOW)
    assert update_summary(tl.conn, LLMSettings(), now=NOW) is None
    summary = latest_summary(tl.conn)
    assert summary["source"] == "auto" and summary["finding_count"] == 1
    assert "vnc.service" in summary["text"]


def test_llm_request_and_regeneration_on_change(db_path):
    tl = failed_service_timeline()
    opener = FakeOpener()
    assert update_summary(tl.conn, LLM, opener, now=NOW)
    request = opener.requests[0]
    assert request.full_url == "http://llm.local/v1/chat/completions"
    assert request.get_header("Authorization") == "Bearer sk-test"
    body = json.loads(request.data)
    assert body["model"] == "test-model"
    assert "vnc.service" in body["messages"][1]["content"]
    summary = latest_summary(tl.conn)
    assert (summary["source"], summary["model"], summary["text"]) == (
        "ai",
        "test-model",
        "Résumé de l'IA",
    )

    later = NOW + timedelta(hours=1)
    assert update_summary(tl.conn, LLM, opener, now=later) is None
    assert len(opener.requests) == 1

    tl.conn.execute("UPDATE findings SET acked_until='2999-01-01T00:00:00Z'")
    assert update_summary(tl.conn, LLM, opener, now=later)
    assert len(opener.requests) == 1, "no LLM call when nothing is open"
    assert "Aucun problème" in latest_summary(tl.conn)["text"]


def test_llm_error_falls_back_and_retries_after_interval(db_path):
    tl = failed_service_timeline()
    body = io.BytesIO(b'{"error": {"message": "Incorrect API key"}}')
    error = urllib.error.HTTPError("u", 401, "Unauthorized", {}, body)
    opener = FakeOpener(error=error)
    assert update_summary(tl.conn, LLM, opener, now=NOW)
    summary = latest_summary(tl.conn)
    assert summary["source"] == "auto" and summary["error"] == "HTTP 401 : Incorrect API key"
    assert "sk-test" not in json.dumps(summary)

    assert update_summary(tl.conn, LLM, opener, now=NOW + timedelta(minutes=5)) is None
    opener.error = None
    assert update_summary(tl.conn, LLM, opener, now=NOW + timedelta(minutes=11))
    assert latest_summary(tl.conn)["source"] == "ai"
    assert len(opener.requests) == 2


def test_summary_endpoint(db_path):
    from fastapi.testclient import TestClient

    from api.main import app

    tl = failed_service_timeline()
    with TestClient(app) as client:
        live = client.get("/summary").json()
        assert live["created_at"] is None and live["finding_count"] == 1
        update_summary(tl.conn, LLMSettings(), now=NOW)
        assert client.get("/summary").json()["created_at"] == "2026-01-01T01:00:00Z"
