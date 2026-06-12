"""EFEX Payments API -- intentionally vulnerable seed.

DO NOT DEPLOY. This service exists to exercise the DevSecOps pipeline.
Every vulnerability below is tagged ``VULN-###`` and is documented in
``docs/threat-model.md`` and matched by a scanner in
``.github/workflows/secure-pipeline.yml``.
"""
from __future__ import annotations

import sqlite3
import subprocess

from fastapi import FastAPI, HTTPException

# VULN-001 -- hardcoded production-shaped secrets (gitleaks)
JWT_SECRET = "super-secret-jwt-key-do-not-share-12345"
SPEI_API_KEY = "sk_live_efex_a1b2c3d4e5f6g7h8i9j0"  # noqa: S105

DB_PATH = "payments.db"

app = FastAPI(title="EFEX Payments API", version="0.0.1-vuln")


def _db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


@app.on_event("startup")
def _seed() -> None:
    with _db() as conn:
        conn.execute(
            "CREATE TABLE IF NOT EXISTS clients ("
            "id INTEGER PRIMARY KEY, name TEXT, clabe TEXT)"
        )
        conn.execute(
            "INSERT OR IGNORE INTO clients (id, name, clabe) VALUES "
            "(1, 'Acme SA de CV', '012180001234567890'),"
            "(2, 'Bullground MX', '014180009876543210')"
        )


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "efex-payments"}


@app.get("/clients/search")
def search_clients(name: str) -> list[dict]:
    """VULN-002 -- SQL injection (custom Semgrep rule efex-py-001-fstring-sql-execute).

    ``name`` is concatenated directly into the SQL string. A request like
    ``?name=' OR 1=1 --`` returns every client row.
    """
    with _db() as conn:
        query = f"SELECT id, name, clabe FROM clients WHERE name LIKE '%{name}%'"
        rows = conn.execute(query).fetchall()
    return [dict(r) for r in rows]


@app.get("/diag/ping")
def diag_ping(host: str) -> dict[str, str]:
    """VULN-003 -- OS command injection (Semgrep python.lang.security.audit.subprocess-shell-true).

    ``host`` is passed unquoted to a shell. ``?host=8.8.8.8;cat /etc/passwd``
    executes both commands.
    """
    try:
        out = subprocess.check_output(
            f"ping -c 1 {host}",
            shell=True,  # noqa: S602
            text=True,
            timeout=5,
        )
    except subprocess.CalledProcessError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {"output": out}
