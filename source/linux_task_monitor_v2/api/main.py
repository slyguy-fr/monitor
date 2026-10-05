import os
import secrets
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, FastAPI, Header, HTTPException, Query

from agent.analyzer import analyze_task, open_findings
from agent.database import TIMESTAMP_FORMAT, get_connection, init_db, transaction
from agent.findings import FINDING_SELECT, SEVERITY_ORDER, decode
from agent.recommendations import recommend

VERSION = "0.5.0"
TASK_NOT_FOUND = "Task not found"
FINDING_NOT_FOUND = "Finding not found"


@asynccontextmanager
async def lifespan(_app):
    init_db()
    yield


def require_token(authorization: str | None = Header(None)):
    """Bearer token check, enabled when LTM_API_TOKEN is set."""
    expected = os.environ.get("LTM_API_TOKEN")
    if not expected:
        return
    scheme, _, token = (authorization or "").partition(" ")
    if scheme.lower() != "bearer" or not secrets.compare_digest(token, expected):
        raise HTTPException(
            status_code=401,
            detail="Invalid or missing token",
            headers={"WWW-Authenticate": "Bearer"},
        )


app = FastAPI(title="Linux Task Monitor", version=VERSION, lifespan=lifespan)
router = APIRouter(dependencies=[Depends(require_token)])


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


def _require_finding(finding_id):
    row = _fetch_one(FINDING_SELECT + " WHERE f.id=?", (finding_id,))
    if not row:
        raise HTTPException(status_code=404, detail=FINDING_NOT_FOUND)
    return decode(row)


@app.get("/")
def root():
    return {"application": "Linux Task Monitor", "version": VERSION, "status": "ok"}


@app.get("/health")
def health():
    return {"status": "healthy"}


@router.get("/system/latest")
def system_latest():
    r = _fetch_one("SELECT * FROM samples ORDER BY id DESC LIMIT 1")
    return dict(r) if r else {"message": "Aucune donnée"}


@router.get("/tasks")
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


@router.get("/tasks/{task_id}")
def task(task_id: str):
    result = _require_task(task_id)
    c = get_connection()
    try:
        result["open_findings"] = open_findings(c, task_id, include_acked=True)
    finally:
        c.close()
    return result


@router.get("/tasks/{task_id}/history")
def history(task_id: str, limit: int = Query(100, ge=1, le=1000)):
    _require_task(task_id)
    return _fetch_all(
        "SELECT * FROM task_samples WHERE task_id=? ORDER BY timestamp DESC LIMIT ?",
        (task_id, limit),
    )


@router.get("/tasks/{task_id}/analysis")
def task_analysis(task_id: str):
    result = analyze_task(task_id)
    if result is None:
        raise HTTPException(status_code=404, detail=TASK_NOT_FOUND)
    return result


@router.get("/recommendations")
def recommendations(severity: str | None = None, include_acked: bool = False):
    """Open findings, most severe first, each with probable causes and proposed actions."""
    c = get_connection()
    try:
        return open_findings(
            c, severity=severity, include_acked=include_acked, with_recommendation=True
        )
    finally:
        c.close()


@router.get("/analysis")
def analysis():
    return {"findings": recommendations()}


@router.get("/findings")
def findings(
    status: str | None = "open",
    severity: str | None = None,
    detector: str | None = None,
    task_id: str | None = None,
    limit: int = Query(100, ge=1, le=1000),
):
    sql = FINDING_SELECT + " WHERE 1=1"
    p = []
    for column, value in (
        ("status", status),
        ("severity", severity),
        ("detector", detector),
        ("task_id", task_id),
    ):
        if value:
            sql += f" AND f.{column}=?"
            p.append(value)
    sql += f" ORDER BY {SEVERITY_ORDER}, f.last_seen DESC LIMIT ?"
    p.append(limit)
    return [decode(r) for r in _fetch_all(sql, p)]


@router.get("/findings/{finding_id}")
def finding(finding_id: int):
    result = _require_finding(finding_id)
    result["recommendation"] = recommend(result)
    return result


@router.post("/findings/{finding_id}/ack")
def acknowledge(finding_id: int, hours: float = Query(24, ge=0, le=24 * 30)):
    """Hide a finding from /recommendations for `hours` (0 removes the acknowledgement)."""
    _require_finding(finding_id)
    until = None
    if hours:
        until = (datetime.now(timezone.utc) + timedelta(hours=hours)).strftime(TIMESTAMP_FORMAT)
    c = get_connection()
    try:
        with transaction(c):
            c.execute("UPDATE findings SET acked_until=? WHERE id=?", (until, finding_id))
    finally:
        c.close()
    return _require_finding(finding_id)


app.include_router(router)
