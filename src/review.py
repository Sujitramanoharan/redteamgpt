"""Human review queue and feedback loop.

A guardrail that only ever blocks is a dead end: its mistakes stay mistakes.
Borderline decisions are queued here, a person says whether the firewall was
right, and those judgements become labelled training data. The model's own
operation is what improves it.

Shares the audit database. SQLite in WAL mode handles the second connection.
"""
import json
import logging
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from config import settings

logger = logging.getLogger(__name__)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS review_queue (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at      TEXT    NOT NULL,
    prompt          TEXT    NOT NULL,
    verdict         TEXT    NOT NULL,
    predicted_label INTEGER NOT NULL,
    risk_score      INTEGER NOT NULL,
    category        TEXT,
    priority_level  TEXT,
    queued_reason   TEXT    NOT NULL,
    status          TEXT    NOT NULL DEFAULT 'pending',
    true_label      INTEGER,
    reviewer_note   TEXT,
    reviewed_at     TEXT,
    exported        INTEGER NOT NULL DEFAULT 0,
    payload         TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_review_status ON review_queue(status, id DESC);
-- One row per prompt: the same borderline prompt arriving repeatedly should
-- not bury the queue in duplicates of a decision already made.
CREATE UNIQUE INDEX IF NOT EXISTS idx_review_prompt ON review_queue(prompt);
"""

REASONS = {
    "uncertain": "Model confidence fell in the band where it is least reliable",
    "reported": "A user disputed this decision",
    "flagged": "Priority P3: suspicious but not conclusive",
    "disagreement": "The rule layer and the classifier disagreed on this one",
}


class ReviewStore:
    def __init__(self, db_path: Path):
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(str(db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        # The audit store writes to this same file from its own connection.
        # Without a busy timeout, whichever writer arrives second fails
        # immediately with "database is locked" rather than waiting.
        self._conn.execute("PRAGMA busy_timeout=5000")
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    def enqueue(self, result: dict, reason: str) -> bool:
        """Add a decision for review. Returns False if already queued."""
        prompt = (result.get("prompt") or "").strip()
        if not prompt:
            return False

        with self._lock:
            try:
                self._conn.execute(
                    """INSERT INTO review_queue (created_at, prompt, verdict,
                           predicted_label, risk_score, category, priority_level,
                           queued_reason, payload)
                       VALUES (?,?,?,?,?,?,?,?,?)""",
                    (
                        datetime.now(timezone.utc).isoformat(),
                        prompt[:10_000],
                        result.get("verdict", "UNKNOWN"),
                        1 if result.get("malicious") else 0,
                        result.get("risk_score", 0),
                        result.get("category"),
                        (result.get("priority") or {}).get("level"),
                        reason,
                        json.dumps(result, ensure_ascii=False),
                    ),
                )
                self._conn.commit()
                return True
            except sqlite3.IntegrityError:
                return False  # already queued

    def pending(self, limit: int = 50) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                """SELECT * FROM review_queue WHERE status = 'pending'
                   ORDER BY id DESC LIMIT ?""", (limit,)
            ).fetchall()
        return [self._row(r) for r in rows]

    def reviewed(self, limit: int = 50) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                """SELECT * FROM review_queue WHERE status = 'reviewed'
                   ORDER BY reviewed_at DESC LIMIT ?""", (limit,)
            ).fetchall()
        return [self._row(r) for r in rows]

    def submit(self, item_id: int, true_label: int, note: str = "") -> Optional[dict]:
        with self._lock:
            cur = self._conn.execute(
                """UPDATE review_queue
                   SET status='reviewed', true_label=?, reviewer_note=?, reviewed_at=?
                   WHERE id=? AND status='pending'""",
                (int(true_label), note[:1000],
                 datetime.now(timezone.utc).isoformat(), item_id),
            )
            self._conn.commit()
            if cur.rowcount == 0:
                return None
            row = self._conn.execute(
                "SELECT * FROM review_queue WHERE id=?", (item_id,)).fetchone()
        return self._row(row)

    def stats(self) -> dict:
        with self._lock:
            row = self._conn.execute(
                """SELECT
                     COUNT(*) AS total,
                     SUM(status='pending') AS pending,
                     SUM(status='reviewed') AS reviewed,
                     SUM(status='reviewed' AND true_label = predicted_label) AS agreed,
                     SUM(status='reviewed' AND true_label=0 AND predicted_label=1)
                       AS false_positives,
                     SUM(status='reviewed' AND true_label=1 AND predicted_label=0)
                       AS false_negatives,
                     SUM(status='reviewed' AND exported=0) AS ready_to_export
                   FROM review_queue"""
            ).fetchone()

        reviewed = row["reviewed"] or 0
        agreed = row["agreed"] or 0
        return {
            "total": row["total"] or 0,
            "pending": row["pending"] or 0,
            "reviewed": reviewed,
            "agreed": agreed,
            "agreement_rate": round(agreed / reviewed, 3) if reviewed else None,
            "false_positives": row["false_positives"] or 0,
            "false_negatives": row["false_negatives"] or 0,
            "ready_to_export": row["ready_to_export"] or 0,
        }

    def export_training_rows(self, mark: bool = True) -> list[dict]:
        """Reviewed decisions as labelled rows, ready to append to the corpus."""
        with self._lock:
            rows = self._conn.execute(
                """SELECT id, prompt, true_label FROM review_queue
                   WHERE status='reviewed' AND exported=0"""
            ).fetchall()
            if mark and rows:
                self._conn.executemany(
                    "UPDATE review_queue SET exported=1 WHERE id=?",
                    [(r["id"],) for r in rows],
                )
                self._conn.commit()

        return [{"text": r["prompt"], "label": int(r["true_label"]),
                 "source": "human-review"} for r in rows]

    @staticmethod
    def _row(row: sqlite3.Row) -> dict:
        item = dict(row)
        item["payload"] = json.loads(item["payload"])
        item["reason_text"] = REASONS.get(item["queued_reason"], item["queued_reason"])
        return item

    def close(self) -> None:
        with self._lock:
            self._conn.close()


store = ReviewStore(settings.database_path)
