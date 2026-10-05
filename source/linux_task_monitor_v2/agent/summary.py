"""Plain-language summary of the open findings, written by an LLM when one is configured."""

import hashlib
import json
import logging
import urllib.error
import urllib.request
from datetime import datetime, timezone

from .analyzer import open_findings
from .collector import redact
from .database import TIMESTAMP_FORMAT, transaction

log = logging.getLogger(__name__)

SYSTEM_PROMPT = (
    "Tu es un administrateur Linux expérimenté. On te donne l'état d'un serveur et les problèmes "
    "détectés par un outil de supervision : preuves, causes probables, actions proposées et "
    "extraits de diagnostics. Rédige en français un résumé de 200 mots au plus pour "
    "l'administrateur : 1) l'état général en une phrase ; 2) les problèmes par ordre de priorité, "
    "avec la cause la plus probable d'après les diagnostics ; 3) les trois premières actions à "
    "mener, avec la commande exacte. N'invente aucun chiffre ni aucune commande absents des "
    "données. Rappelle qu'aucune action n'a été exécutée. Texte simple, listes avec « - »."
)
SYSTEM_KEYS = (
    "hostname",
    "timestamp",
    "cpu_percent",
    "memory_percent",
    "swap_percent",
    "load1",
    "cpu_count",
    "iowait_percent",
    "psi_memory_some",
    "psi_io_some",
)
DIAGNOSTIC_CHARS = 800
MAX_FINDINGS = 15


def fingerprint(findings):
    """Changes when a finding opens, resolves, is (un)acknowledged or changes severity."""
    keys = sorted(f"{f['id']}:{f['severity']}" for f in findings)
    return hashlib.sha256("|".join(keys).encode()).hexdigest()[:16]


def _redact_tree(value):
    if isinstance(value, str):
        return redact(value)
    if isinstance(value, dict):
        return {k: _redact_tree(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact_tree(v) for v in value]
    return value


def build_payload(findings, system):
    problems = []
    for f in findings[:MAX_FINDINGS]:
        rec = f["recommendation"]
        problems.append(
            {
                "gravite": f["severity"],
                "titre": f["title"],
                "depuis": f["first_seen"],
                "preuves": f["evidence"],
                "causes_probables": rec["probable_causes"],
                "actions_proposees": [
                    {"titre": a["title"], "commande": a["command"], "risque": a["risk"]}
                    for a in rec["actions"]
                ],
                "diagnostics": [
                    {"titre": d.get("title"), "sortie": (d.get("output") or "")[:DIAGNOSTIC_CHARS]}
                    for d in rec["diagnostics"]
                ],
            }
        )
    server = {k: system[k] for k in SYSTEM_KEYS if system and k in system.keys()}
    return _redact_tree({"serveur": server, "problemes": problems})


def fallback_summary(findings):
    if not findings:
        return "Aucun problème ouvert : le serveur fonctionne normalement."
    critical = sum(f["severity"] == "critical" for f in findings)
    lines = [f"{len(findings)} problème(s) ouvert(s), dont {critical} critique(s) :"]
    for f in findings[:5]:
        rec = f["recommendation"]
        line = f"- {f['title']}"
        if rec["probable_causes"]:
            line += f". Cause probable : {rec['probable_causes'][0]}"
        first = next((a for a in rec["actions"] if a["command"]), None)
        if first:
            line += f". À faire : {first['title']} (`{first['command']}`)"
        lines.append(line)
    if len(findings) > 5:
        lines.append(f"- … et {len(findings) - 5} autre(s).")
    lines.append("Aucune action n'a été exécutée.")
    return "\n".join(lines)


def ask_llm(payload, llm, opener=urllib.request.urlopen):
    """Call an OpenAI-compatible /chat/completions endpoint and return the answer text."""
    body = {
        "model": llm.model,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": json.dumps(payload, ensure_ascii=False)},
        ],
    }
    headers = {"Content-Type": "application/json"}
    if llm.api_key:
        headers["Authorization"] = f"Bearer {llm.api_key}"
    request = urllib.request.Request(
        llm.base_url.rstrip("/") + "/chat/completions",
        data=json.dumps(body).encode(),
        headers=headers,
        method="POST",
    )
    with opener(request, timeout=llm.timeout_seconds) as response:
        data = json.loads(response.read())
    return data["choices"][0]["message"]["content"].strip()


def _error_message(exc):
    if isinstance(exc, urllib.error.HTTPError):
        detail = exc.read().decode(errors="replace")
        try:
            detail = json.loads(detail)["error"]["message"]
        except (ValueError, KeyError, TypeError):
            pass
        return f"HTTP {exc.code} : {detail[:300]}"
    return str(exc)[:300]


def _seconds_since(timestamp, now):
    if not timestamp:
        return float("inf")
    then = datetime.strptime(timestamp, TIMESTAMP_FORMAT).replace(tzinfo=timezone.utc)
    return (now - then).total_seconds()


def update_summary(conn, llm, opener=urllib.request.urlopen, now=None):
    """Store a new summary when the open findings changed. Returns the new row id or None."""
    now = now or datetime.now(timezone.utc)
    findings = open_findings(conn, with_recommendation=True)
    fp = fingerprint(findings)
    last = conn.execute("SELECT * FROM summaries ORDER BY id DESC LIMIT 1").fetchone()
    last_attempt = conn.execute(
        "SELECT MAX(created_at) FROM summaries WHERE model IS NOT NULL"
    ).fetchone()[0]
    ai_due = (
        llm.enabled
        and bool(findings)
        and _seconds_since(last_attempt, now) >= llm.min_interval_seconds
    )
    changed = last is None or last["fingerprint"] != fp
    if not changed and not (ai_due and last["source"] != "ai"):
        return None

    row = {
        "source": "auto",
        "model": None,
        "text": fallback_summary(findings),
        "error": None,
    }
    if ai_due:
        row["model"] = llm.model
        try:
            system = conn.execute("SELECT * FROM samples ORDER BY id DESC LIMIT 1").fetchone()
            row["text"] = ask_llm(build_payload(findings, system), llm, opener)
            row["source"] = "ai"
        except Exception as exc:  # noqa: BLE001 - any provider failure falls back to the auto text
            row["error"] = _error_message(exc)
            log.warning("Résumé IA indisponible : %s", row["error"])
    with transaction(conn):
        return conn.execute(
            """INSERT INTO summaries(created_at, fingerprint, source, model, finding_count,
                text, error) VALUES(?, ?, ?, ?, ?, ?, ?)""",
            (
                now.strftime(TIMESTAMP_FORMAT),
                fp,
                row["source"],
                row["model"],
                len(findings),
                row["text"],
                row["error"],
            ),
        ).lastrowid


def latest_summary(conn):
    row = conn.execute("SELECT * FROM summaries ORDER BY id DESC LIMIT 1").fetchone()
    if row:
        return dict(row)
    findings = open_findings(conn, with_recommendation=True)
    return {
        "created_at": None,
        "source": "auto",
        "model": None,
        "finding_count": len(findings),
        "text": fallback_summary(findings),
        "error": None,
    }
