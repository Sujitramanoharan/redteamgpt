"""Durable, per-organisation audit storage.

Every method takes the caller's org_id and filters on it; nothing in here can
read across tenants. Postgres in production, SQLite locally (see db.py).
"""
import hashlib
import logging
from datetime import timedelta
from typing import Optional

from sqlalchemy import Integer, case, delete, func, or_, select

from db import healthy as db_healthy
from db import session_scope
from models_db import AuditLog, Organization, utcnow

logger = logging.getLogger(__name__)

NOT_STORED = "[prompt not stored - disabled in organisation settings]"


def prompt_hash(prompt: str) -> str:
    return hashlib.sha256((prompt or "").encode("utf-8")).hexdigest()


class AuditStore:
    def record(self, result: dict, org_id: str, *, channel: str = "api",
               api_key_id: Optional[str] = None, request_id: Optional[str] = None,
               store_prompt: bool = True) -> None:
        prompt = result.get("prompt", "") or ""
        payload = dict(result)
        if not store_prompt:
            # The verdict, category and evidence snippets are kept so the
            # dashboard still works; the full text is not.
            payload["prompt"] = NOT_STORED
        with session_scope() as s:
            s.add(AuditLog(
                org_id=org_id,
                prompt=prompt[:10_000] if store_prompt else None,
                prompt_sha256=prompt_hash(prompt),
                verdict=result.get("verdict", "UNKNOWN"),
                malicious=bool(result.get("malicious")),
                category=(result.get("category") or "")[:80] or None,
                risk_score=int(result.get("risk_score", 0)),
                risk_level=result.get("risk_level"),
                priority_level=(result.get("priority") or {}).get("level"),
                confidence=result.get("confidence"),
                latency_ms=result.get("latency_ms"),
                channel=channel,
                api_key_id=api_key_id,
                request_id=(request_id or "")[:64] or None,
                payload=payload,
            ))

    def query(self, org_id: str, limit: int = 50, verdict: Optional[str] = None,
              priority: Optional[str] = None, search: Optional[str] = None) -> list[dict]:
        stmt = select(AuditLog.id, AuditLog.payload).where(AuditLog.org_id == org_id)
        if verdict:
            stmt = stmt.where(AuditLog.verdict == verdict.upper())
        if priority:
            stmt = stmt.where(AuditLog.priority_level == priority.upper())
        if search:
            like = f"%{search.lower()}%"
            stmt = stmt.where(or_(func.lower(AuditLog.prompt).like(like),
                                  func.lower(AuditLog.category).like(like)))
        stmt = stmt.order_by(AuditLog.id.desc()).limit(limit)

        with session_scope() as s:
            rows = s.execute(stmt).all()
        records = []
        for row_id, payload in rows:
            record = dict(payload)
            record["id"] = f"LOG-{row_id}"  # stable key for the UI table
            records.append(record)
        return records

    def aggregate(self, org_id: str) -> dict:
        """Telemetry computed in SQL rather than by loading every row."""
        scope = AuditLog.org_id == org_id
        blocked_expr = func.sum(case((AuditLog.malicious.is_(True), 1), else_=0), type_=Integer)
        with session_scope() as s:
            total, blocked, avg_latency, avg_risk = s.execute(
                select(func.count(AuditLog.id),
                       func.coalesce(blocked_expr, 0),
                       func.coalesce(func.avg(AuditLog.latency_ms), 0),
                       func.coalesce(func.avg(AuditLog.risk_score), 0)).where(scope)
            ).one()
            by_category = s.execute(
                select(AuditLog.category, func.count()).where(scope).group_by(AuditLog.category)
            ).all()
            by_priority = s.execute(
                select(AuditLog.priority_level, func.count()).where(scope)
                .group_by(AuditLog.priority_level)
            ).all()

        total, blocked = int(total or 0), int(blocked or 0)
        return {
            "total_scanned": total,
            "total_blocked": blocked,
            "total_allowed": total - blocked,
            "block_rate_percent": round(blocked / total * 100, 1) if total else 0.0,
            "avg_latency_ms": round(float(avg_latency), 2),
            "avg_risk_score": round(float(avg_risk), 1),
            "category_distribution": {c or "Uncategorized": n for c, n in by_category},
            "priority_distribution": {p or "P4": n for p, n in by_priority},
        }

    def clear(self, org_id: str) -> int:
        with session_scope() as s:
            return s.execute(delete(AuditLog).where(AuditLog.org_id == org_id)).rowcount

    def prune_expired(self) -> int:
        """Apply each organisation's own retention period."""
        removed = 0
        with session_scope() as s:
            orgs = s.execute(select(Organization.id, Organization.retention_days)).all()
            now = utcnow()
            for org_id, days in orgs:
                removed += s.execute(delete(AuditLog).where(
                    AuditLog.org_id == org_id,
                    AuditLog.timestamp < now - timedelta(days=max(1, days)),
                )).rowcount
        return removed

    def healthy(self) -> bool:
        return db_healthy()


store = AuditStore()
