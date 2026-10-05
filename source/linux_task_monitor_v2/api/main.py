from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Query

from agent.analyzer import SEVERITY_ORDER, analyze_latest, analyze_task
from agent.database import get_connection, init_db
from agent.findings import decode

VERSION = "0.4.0"
TASK_NOT_FOUND = "Task not found"


@asynccontextmanager
async def lifespan(_app):
    init_db()
    yield


app = FastAPI(title="Linux Task Monitor", version=VERSION, lifespan=lifespan)


def _fetch_one(sql, params=()):
    c = get_connection()
    try:
        return c.execute(sql, params).fetchone()
    finally:
        c.close()


def _fetch_all(sql, params=()):
    c = get_connection()
    try:
        return [dict(r) for r in c.execute(sql, params).fetchall()]
    finally:
        c.close()


def _require_task(task_id):
    row = _fetch_one("SELECT * FROM tasks WHERE task_id=?", (task_id,))
    if not row:
        raise HTTPException(status_code=404, detail=TASK_NOT_FOUND)
    return dict(row)


@app.get("/")
def root():
    return {"application": "Linux Task Monitor", "version": VERSION, "status": "ok"}


@app.get("/health")
def health():
    return {"status": "healthy"}


@app.get("/system/latest")
def system_latest():
    r = _fetch_one("SELECT * FROM samples ORDER BY id DESC LIMIT 1")
    return dict(r) if r else {"message": "Aucune donnée"}


@app.get("/tasks")
def tasks(
    category: str | None = None,
    status: str | None = None,
    state: str | None = None,
    name: str | None = None,
    limit: int = Query(100, ge=1, le=1000),
):
    sql = "SELECT * FROM tasks WHERE 1=1"
    p = []
    if category:
        sql += " AND category=?"
        p.append(category)
    if status:
        sql += " AND status=?"
        p.append(status)
    if state:
        sql += " AND state=?"
        p.append(state)
    if name:
        sql += " AND name LIKE ?"
        p.append("%" + name + "%")
    sql += " ORDER BY category,name LIMIT ?"
    p.append(limit)
    return _fetch_all(sql, p)


@app.get("/tasks/{task_id}")
def task(task_id: str):
    return _require_task(task_id)


@app.get("/tasks/{task_id}/history")
def history(task_id: str, limit: int = Query(100, ge=1, le=1000)):
    _require_task(task_id)
    return _fetch_all(
        "SELECT * FROM task_samples WHERE task_id=? ORDER BY timestamp DESC LIMIT ?",
        (task_id, limit),
    )


@app.get("/tasks/{task_id}/analysis")
def task_analysis(task_id: str):
    result = analyze_task(task_id)
    if result is None:
        raise HTTPException(status_code=404, detail=TASK_NOT_FOUND)
    return result


@app.get("/analysis")
def analysis():
    return {"findings": analyze_latest()}


@app.get("/findings")
def findings(
    status: str | None = "open",
    severity: str | None = None,
    detector: str | None = None,
    task_id: str | None = None,
    limit: int = Query(100, ge=1, le=1000),
):
    sql = "SELECT * FROM findings WHERE 1=1"
    p = []
    for column, value in (
        ("status", status),
        ("severity", severity),
        ("detector", detector),
        ("task_id", task_id),
    ):
        if value:
            sql += f" AND {column}=?"
            p.append(value)
    sql += f" ORDER BY {SEVERITY_ORDER}, last_seen DESC LIMIT ?"
    p.append(limit)
    return [decode(r) for r in _fetch_all(sql, p)]


@app.get("/findings/{finding_id}")
def finding(finding_id: int):
    row = _fetch_one("SELECT * FROM findings WHERE id=?", (finding_id,))
    if not row:
        raise HTTPException(status_code=404, detail="Finding not found")
    return decode(row)
