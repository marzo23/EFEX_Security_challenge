"""EFEX Payments API -- remediated (Green) version.

Every VULN-### from the Red baseline has a remediation noted at the call
site. Pair-review checklist:
  - VULN-001  ->  secrets from env, fail-fast at startup
  - VULN-002  ->  parameterised SQL, length-capped input
  - VULN-003  ->  shell=False + arg list + hostname regex
"""
from __future__ import annotations

import os
import re
import sqlite3
import subprocess

from fastapi import FastAPI, HTTPException

# VULN-001 remediated -- secrets loaded from env (Secrets Manager at deploy
# time). Failing fast at startup avoids silent fallback to a dev key.
JWT_SECRET = os.environ["JWT_SECRET"]
SPEI_API_KEY = os.environ["SPEI_API_KEY"]

DB_PATH = os.environ.get("PAYMENTS_DB", "payments.db")

# Hostnames per RFC 1123 (labels <= 63 chars, alphanumeric + hyphen).
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)([A-Za-z0-9-]{1,63})(\.[A-Za-z0-9-]{1,63})*$"
)

app = FastAPI(title="EFEX Payments API", version="0.1.0")


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
    # VULN-002 remediated -- parameterised query; input length-capped.
    if len(name) > 64:
        raise HTTPException(status_code=400, detail="name too long")
    with _db() as conn:
        rows = conn.execute(
            "SELECT id, name, clabe FROM clients WHERE name LIKE ?",
            (f"%{name}%",),
        ).fetchall()
    return [dict(r) for r in rows]


@app.get("/diag/ping")
def diag_ping(host: str) -> dict[str, str]:
    # VULN-003 remediated -- hostname validated, shell disabled, arg list used.
    if not _HOSTNAME_RE.match(host):
        raise HTTPException(status_code=400, detail="invalid hostname")
    try:
        out = subprocess.run(
            ["ping", "-c", "1", host],
            capture_output=True,
            text=True,
            timeout=5,
            check=True,
        ).stdout
    except subprocess.CalledProcessError as exc:
        raise HTTPException(status_code=400, detail=exc.stderr or str(exc))
    return {"output": out}
