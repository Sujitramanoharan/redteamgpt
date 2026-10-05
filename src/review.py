"""Human review queue and feedback loop, per organisation.

A guardrail that only ever blocks is a dead end: its mistakes stay mistakes.
Borderline decisions are queued, a person in the customer's organisation says
whether the firewall was right, and - only for organisations that opted in -
those judgements become labelled training data.
"""
import logging
from typing import Optional

from sqlalchemy import Integer, and_, case, func, select, update
from sqlalchemy.exc import IntegrityError

from db import session_scope
from models_db import Organization, ReviewItem, utcnow
from storage import prompt_hash

logger = logging.getLogger(__name__)

REASONS = {
    "uncertain": "Model confidence fell in the band where it is least reliable",
    "reported": "A user disputed this decision",
    "flagged": "Priority P3: suspicious but not conclusive",
    "disagreement": "The rule layer and the classifier disagreed on this one",
}


def _count(condition):
    return func.coalesce(func.sum(case((condition, 1), else_=0), type_=Integer), 0)


class ReviewStore:
    def enqueue(self, result: dict, reason: str, org_id: str) -> bool:
        """Add a decision for review. Returns False if already queued."""
        prompt = (result.get("prompt") or "").strip()
        if not prompt:
            return False
        try:
            with session_scope() as s:
                s.add(ReviewItem(
                    org_id=org_id,
                    prompt=prompt[:10_000],
                    prompt_sha256=prompt_hash(prompt),
                    verdict=result.get("verdict", "UNKNOWN"),
                    predicted_label=1 if result.get("malicious") else 0,
                    risk_score=int(result.get("risk_score", 0)),
                    category=(result.get("category") or "")[:80] or None,
                    priority_level=(result.get("priority") or {}).get("level"),
                    queued_reason=reason,
                    payload=result,
                ))
            return True
        except IntegrityError:
            return False  # already queued for this organisation

    def pending(self, org_id: str, limit: int = 50) -> list[dict]:
        return self._list(org_id, "pending", ReviewItem.id.desc(), limit)

    def reviewed(self, org_id: str, limit: int = 50) -> list[dict]:
        return self._list(org_id, "reviewed", ReviewItem.reviewed_at.desc(), limit)

    def _list(self, org_id: str, status: str, order, limit: int) -> list[dict]:
        with session_scope() as s:
            items = s.scalars(select(ReviewItem).where(
                ReviewItem.org_id == org_id, ReviewItem.status == status
            ).order_by(order).limit(limit)).all()
            return [self._row(i) for i in items]

    def submit(self, org_id: str, item_id: int, true_label: int, note: str = "",
               reviewer_id: Optional[str] = None) -> Optional[dict]:
        with session_scope() as s:
            item = s.scalar(select(ReviewItem).where(
                ReviewItem.id == item_id, ReviewItem.org_id == org_id,
                ReviewItem.status == "pending"))
            if item is None:
                return None
            item.status = "reviewed"
            item.true_label = int(true_label)
            item.reviewer_note = note[:1000]
            item.reviewed_by = reviewer_id
            item.reviewed_at = utcnow()
            s.flush()
            return self._row(item)

    def stats(self, org_id: str) -> dict:
        reviewed = ReviewItem.status == "reviewed"
        with session_scope() as s:
            row = s.execute(select(
                func.count(ReviewItem.id),
                _count(ReviewItem.status == "pending"),
                _count(reviewed),
                _count(and_(reviewed, ReviewItem.true_label == ReviewItem.predicted_label)),
                _count(and_(reviewed, ReviewItem.true_label == 0, ReviewItem.predicted_label == 1)),
                _count(and_(reviewed, ReviewItem.true_label == 1, ReviewItem.predicted_label == 0)),
            ).where(ReviewItem.org_id == org_id)).one()

        total, pending, n_reviewed, agreed, fps, fns = (int(x or 0) for x in row)
        return {
            "total": total,
            "pending": pending,
            "reviewed": n_reviewed,
            "agreed": agreed,
            "agreement_rate": round(agreed / n_reviewed, 3) if n_reviewed else None,
            "false_positives": fps,
            "false_negatives": fns,
        }

    def export_training_rows(self, mark: bool = True) -> list[dict]:
        """Reviewed decisions from organisations that opted in to contributing
        training data. Platform-operator only; customers' prompts are theirs."""
        with session_scope() as s:
            items = s.execute(
                select(ReviewItem.id, ReviewItem.prompt, ReviewItem.true_label)
                .join(Organization, Organization.id == ReviewItem.org_id)
                .where(ReviewItem.status == "reviewed", ReviewItem.exported.is_(False),
                       Organization.contribute_training.is_(True))
            ).all()
            if mark and items:
                s.execute(update(ReviewItem)
                          .where(ReviewItem.id.in_([i.id for i in items]))
                          .values(exported=True))
        return [{"text": i.prompt, "label": int(i.true_label), "source": "human-review"}
                for i in items]

    @staticmethod
    def _row(item: ReviewItem) -> dict:
        return {
            "id": item.id,
            "created_at": item.created_at.isoformat() if item.created_at else None,
            "prompt": item.prompt,
            "verdict": item.verdict,
            "predicted_label": item.predicted_label,
            "risk_score": item.risk_score,
            "category": item.category,
            "priority_level": item.priority_level,
            "queued_reason": item.queued_reason,
            "reason_text": REASONS.get(item.queued_reason, item.queued_reason),
            "status": item.status,
            "true_label": item.true_label,
            "reviewer_note": item.reviewer_note,
            "reviewed_at": item.reviewed_at.isoformat() if item.reviewed_at else None,
            "payload": item.payload,
        }


store = ReviewStore()
