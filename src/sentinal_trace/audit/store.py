from __future__ import annotations

import sqlite3
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1

_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS incidents (
    id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    adapter TEXT NOT NULL,
    source TEXT,
    category TEXT,
    severity TEXT,
    confidence TEXT,
    action TEXT NOT NULL,
    rule_version TEXT,
    fingerprint TEXT,
    remediation_status TEXT NOT NULL DEFAULT 'open'
);
CREATE TABLE IF NOT EXISTS events (
    id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    kind TEXT NOT NULL,
    detail TEXT NOT NULL,
    FOREIGN KEY(incident_id) REFERENCES incidents(id)
);
CREATE TABLE IF NOT EXISTS notification_outbox (
    id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    provider TEXT NOT NULL,
    payload TEXT NOT NULL,
    status TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    last_error TEXT,
    dedupe_key TEXT NOT NULL,
    UNIQUE(dedupe_key)
);
"""


class AuditStore:
    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        self._conn = sqlite3.connect(path)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)
        self._conn.execute(
            "INSERT OR IGNORE INTO meta(key, value) VALUES ('schema_version', ?)",
            (str(SCHEMA_VERSION),),
        )
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    def record_incident(
        self,
        *,
        adapter: str,
        source: str | None,
        category: str | None,
        severity: str | None,
        confidence: str | None,
        action: str,
        rule_version: str | None,
        fingerprint: str | None,
    ) -> str:
        incident_id = str(uuid.uuid4())
        now = datetime.now(UTC).isoformat()
        if fingerprint:
            existing = self._conn.execute(
                "SELECT id FROM incidents WHERE fingerprint = ? ORDER BY created_at DESC LIMIT 1",
                (fingerprint,),
            ).fetchone()
            if existing:
                incident_id = str(existing["id"])
                self._conn.execute(
                    "INSERT INTO events(id, incident_id, created_at, kind, detail) VALUES (?, ?, ?, ?, ?)",
                    (str(uuid.uuid4()), incident_id, now, "correlated", "same fingerprint"),
                )
                self._conn.commit()
                return incident_id
        self._conn.execute(
            """
            INSERT INTO incidents(
                id, created_at, adapter, source, category, severity, confidence,
                action, rule_version, fingerprint
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                incident_id,
                now,
                adapter,
                source,
                category,
                severity,
                confidence,
                action,
                rule_version,
                fingerprint,
            ),
        )
        self._conn.execute(
            "INSERT INTO events(id, incident_id, created_at, kind, detail) VALUES (?, ?, ?, ?, ?)",
            (str(uuid.uuid4()), incident_id, now, "created", action),
        )
        self._conn.commit()
        return incident_id

    def recent(self, limit: int = 20) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT id, created_at, adapter, category, severity, confidence, action, remediation_status "
            "FROM incidents ORDER BY created_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [dict(row) for row in rows]

    def enqueue_notification(self, *, incident_id: str, provider: str, payload: str, dedupe_key: str) -> str:
        notice_id = str(uuid.uuid4())
        now = datetime.now(UTC).isoformat()
        try:
            self._conn.execute(
                """
                INSERT INTO notification_outbox(
                    id, incident_id, created_at, provider, payload, status, dedupe_key
                ) VALUES (?, ?, ?, ?, ?, 'pending', ?)
                """,
                (notice_id, incident_id, now, provider, payload, dedupe_key),
            )
            self._conn.commit()
        except sqlite3.IntegrityError:
            row = self._conn.execute(
                "SELECT id FROM notification_outbox WHERE dedupe_key = ?",
                (dedupe_key,),
            ).fetchone()
            return str(row["id"]) if row else notice_id
        return notice_id

    def pending_notifications(self, limit: int = 20) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT * FROM notification_outbox WHERE status = 'pending' ORDER BY created_at LIMIT ?",
            (limit,),
        ).fetchall()
        return [dict(row) for row in rows]

    def mark_notification(self, notice_id: str, status: str, error: str | None = None) -> None:
        self._conn.execute(
            "UPDATE notification_outbox SET status = ?, last_error = ?, attempts = attempts + 1 WHERE id = ?",
            (status, error, notice_id),
        )
        self._conn.commit()

    def purge(self, retention_days: int) -> int:
        cutoff = (datetime.now(UTC) - timedelta(days=retention_days)).isoformat()
        cur = self._conn.execute("DELETE FROM incidents WHERE created_at < ?", (cutoff,))
        self._conn.commit()
        return cur.rowcount

    def dump_text(self) -> str:
        rows = self._conn.execute("SELECT * FROM incidents").fetchall()
        events = self._conn.execute("SELECT * FROM events").fetchall()
        outbox = self._conn.execute("SELECT * FROM notification_outbox").fetchall()
        parts = [str(dict(r)) for r in rows] + [str(dict(r)) for r in events] + [str(dict(r)) for r in outbox]
        return "\n".join(parts)
