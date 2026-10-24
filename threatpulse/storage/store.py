"""Durable storage for alerts and incidents (SQLite in WAL mode).

Writes are buffered and flushed in batches from a worker thread, so the detection loop
never blocks on disk.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any

SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    id TEXT PRIMARY KEY,
    ts REAL NOT NULL,
    type TEXT NOT NULL,
    severity TEXT NOT NULL,
    attacker TEXT,
    incident_id TEXT,
    body TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts);
CREATE INDEX IF NOT EXISTS idx_alerts_incident ON alerts(incident_id);
CREATE TABLE IF NOT EXISTS incidents (
    id TEXT PRIMARY KEY,
    last_seen REAL NOT NULL,
    severity TEXT NOT NULL,
    status TEXT NOT NULL,
    body TEXT NOT NULL
);
"""


class Store:
    def __init__(self, path: str):
        self.path = path
        if path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.executescript(SCHEMA)
        self._lock = threading.Lock()
        self._alerts: list[dict[str, Any]] = []
        self._incidents: dict[str, dict[str, Any]] = {}

    def add_alert(self, alert: dict[str, Any]) -> None:
        with self._lock:
            self._alerts.append(alert)

    def upsert_incident(self, incident: dict[str, Any]) -> None:
        with self._lock:
            self._incidents[incident["id"]] = incident

    def flush(self) -> int:
        with self._lock:
            alerts, self._alerts = self._alerts, []
            incidents, self._incidents = list(self._incidents.values()), {}
        if not alerts and not incidents:
            return 0
        with self._conn:
            self._conn.executemany(
                "INSERT OR REPLACE INTO alerts VALUES (?,?,?,?,?,?,?)",
                [(a["id"], a["ts"], a["type"], a["severity"], a.get("attacker"), a.get("incident_id"),
                  json.dumps(a, default=str)) for a in alerts],
            )
            self._conn.executemany(
                "INSERT OR REPLACE INTO incidents VALUES (?,?,?,?,?)",
                [(i["id"], i["last_seen"], i["severity"], i["status"], json.dumps(i, default=str))
                 for i in incidents],
            )
        return len(alerts) + len(incidents)

    def recent_alerts(self, limit: int = 100, incident_id: str | None = None) -> list[dict[str, Any]]:
        q = "SELECT body FROM alerts"
        args: tuple = ()
        if incident_id:
            q += " WHERE incident_id = ?"
            args = (incident_id,)
        q += " ORDER BY ts DESC LIMIT ?"
        with self._lock:
            rows = self._conn.execute(q, (*args, limit)).fetchall()
        return [json.loads(r[0]) for r in rows]

    def incidents(self, limit: int = 100) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute("SELECT body FROM incidents ORDER BY last_seen DESC LIMIT ?", (limit,)).fetchall()
        return [json.loads(r[0]) for r in rows]

    def counts(self) -> dict[str, int]:
        with self._lock:
            a = self._conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
            i = self._conn.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
        return {"alerts": a, "incidents": i}

    def close(self) -> None:
        self.flush()
        self._conn.close()
