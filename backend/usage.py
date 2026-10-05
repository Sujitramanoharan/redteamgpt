"""Daily per-organisation usage counters (scans, assistant messages)."""
from datetime import date, datetime, timedelta, timezone

from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError

from db import session_scope
from models_db import UsageDaily


def today() -> date:
    return datetime.now(timezone.utc).date()


def increment(org_id: str, field: str, amount: int = 1) -> None:
    column = getattr(UsageDaily, field)
    day = today()
    for _ in range(2):
        with session_scope() as s:
            # An atomic UPDATE first: two concurrent requests both add, rather
            # than both reading 5 and writing 6.
            hit = s.execute(update(UsageDaily)
                            .where(UsageDaily.org_id == org_id, UsageDaily.day == day)
                            .values({field: column + amount})).rowcount
            if hit:
                return
        try:
            with session_scope() as s:
                s.add(UsageDaily(org_id=org_id, day=day, **{field: amount}))
            return
        except IntegrityError:
            continue  # another request created today's row first; update it


def get_today(org_id: str) -> dict:
    with session_scope() as s:
        row = s.get(UsageDaily, (org_id, today()))
        return {"scans": row.scans if row else 0,
                "chat_messages": row.chat_messages if row else 0}


def history(org_id: str, days: int = 30) -> list[dict]:
    since = today() - timedelta(days=days - 1)
    with session_scope() as s:
        rows = s.scalars(select(UsageDaily).where(
            UsageDaily.org_id == org_id, UsageDaily.day >= since
        ).order_by(UsageDaily.day)).all()
        return [{"day": r.day.isoformat(), "scans": r.scans,
                 "chat_messages": r.chat_messages} for r in rows]
