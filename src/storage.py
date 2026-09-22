"""Durable audit storage.

The previous in-memory list lost every record on restart and, because the
container runs multiple workers, each worker kept a different list - so the
metrics endpoint answered differently depending on who picked up the request.
SQLite in WAL mode gives every worker one shared, crash-surviving view.
Swapping to Postgres later means changing this module only.
"""
import json
import logging
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from config import settings

logger = logging.getLogger(__name__)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_logs (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp         TEXT    NOT NULL,
    prompt            TEXT    NOT NULL,
    verdict           TEXT    NOT NULL,
    malicious         INTEGER NOT NULL,
    category          TEXT,
    risk_score        INTEGER NOT NULL DEFAULT 0,
    risk_level        TEXT,
    priority_level    TEXT,
    confidence        REAL,
    latency_ms        REAL,
    client_id         TEXT,
    request_id        TEXT,
    payload           TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_ts       ON audit_logs(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_verdict  ON audit_logs(verdict);
CREATE INDEX IF NOT EXISTS idx_audit_priority ON audit_logs(priority_level);
"""


class AuditStore:
    def __init__(self, db_path: Path):
        self.db_path = db_path
        self._lock = threading.Lock()
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        # WAL lets readers and writers work concurrently across worker processes.
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.executescript(_SCHEMA)
        self._conn.commit()
        logger.info("Audit store ready at %s", db_path)

    def record(self, result: dict, client_id: str = "anonymous",
               request_id: Optional[str] = None) -> None:
        priority = (result.get("priority") or {}).get("level")
        with self._lock:
            self._conn.execute(
                """INSERT INTO audit_logs (timestamp, prompt, verdict, malicious,
                       category, risk_score, risk_level, priority_level, confidence,
                       latency_ms, client_id, request_id, payload)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    result.get("timestamp") or datetime.now(timezone.utc).isoformat(),
                    result.get("prompt", "")[:10_000],
                    result.get("verdict", "UNKNOWN"),
                    1 if result.get("malicious") else 0,
                    result.get("category"),
                    result.get("risk_score", 0),
                    result.get("risk_level"),
                    priority,
                    result.get("confidence"),
                    result.get("latency_ms"),
                    client_id,
                    request_id,
                    json.dumps(result, ensure_ascii=False),
                ),
            )
            self._conn.commit()

    def query(self, limit: int = 50, verdict: Optional[str] = None,
              priority: Optional[str] = None, search: Optional[str] = None) -> list[dict]:
        sql = "SELECT id, payload FROM audit_logs WHERE 1=1"
        params: list = []
        if verdict:
            sql += " AND verdict = ?"
            params.append(verdict.upper())
        if priority:
            sql += " AND priority_level = ?"
            params.append(priority.upper())
        if search:
            sql += " AND (prompt LIKE ? OR category LIKE ?)"
            params += [f"%{search}%", f"%{search}%"]
        sql += " ORDER BY id DESC LIMIT ?"
        params.append(limit)

        with self._lock:
            rows = self._conn.execute(sql, params).fetchall()

        records = []
        for row in rows:
            record = json.loads(row["payload"])
            record["id"] = f"LOG-{row['id']}"  # stable key for the UI table
            records.append(record)
        return records

    def aggregate(self) -> dict:
        """Compute telemetry in SQL rather than loading every row into memory."""
        with self._lock:
            totals = self._conn.execute(
                """SELECT COUNT(*) AS total,
                          COALESCE(SUM(malicious), 0) AS blocked,
                          COALESCE(AVG(latency_ms), 0) AS avg_latency,
                          COALESCE(AVG(risk_score), 0) AS avg_risk
                   FROM audit_logs"""
            ).fetchone()
            by_category = self._conn.execute(
                "SELECT category, COUNT(*) AS n FROM audit_logs GROUP BY category"
            ).fetchall()
            by_priority = self._conn.execute(
                "SELECT priority_level, COUNT(*) AS n FROM audit_logs GROUP BY priority_level"
            ).fetchall()

        total = totals["total"] or 0
        blocked = totals["blocked"] or 0
        return {
            "total_scanned": total,
            "total_blocked": blocked,
            "total_allowed": total - blocked,
            "block_rate_percent": round(blocked / total * 100, 1) if total else 0.0,
            "avg_latency_ms": round(totals["avg_latency"], 2),
            "avg_risk_score": round(totals["avg_risk"], 1),
            "category_distribution": {r["category"] or "Uncategorized": r["n"] for r in by_category},
            "priority_distribution": {r["priority_level"] or "P4": r["n"] for r in by_priority},
        }

    def clear(self) -> int:
        with self._lock:
            n = self._conn.execute("SELECT COUNT(*) FROM audit_logs").fetchone()[0]
            self._conn.execute("DELETE FROM audit_logs")
            self._conn.commit()
        return n

    def prune(self, retention_days: int) -> int:
        cutoff = (datetime.now(timezone.utc) - timedelta(days=retention_days)).isoformat()
        with self._lock:
            cur = self._conn.execute("DELETE FROM audit_logs WHERE timestamp < ?", (cutoff,))
            self._conn.commit()
        return cur.rowcount

    def healthy(self) -> bool:
        try:
            with self._lock:
                self._conn.execute("SELECT 1").fetchone()
            return True
        except sqlite3.Error:
            return False

    def close(self) -> None:
        with self._lock:
            self._conn.close()


store = AuditStore(settings.database_path)
