import pytest


@pytest.fixture
def db_path(tmp_path, monkeypatch):
    path = tmp_path / "monitor.db"
    monkeypatch.setenv("LTM_DB_PATH", str(path))
    return path
