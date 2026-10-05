"""Database tables.

Every row that belongs to a customer carries org_id, and every query that
reads customer data filters on it. That single column is the tenant boundary;
tests/test_tenancy.py checks it holds.
"""
import uuid
from datetime import date, datetime, timezone
from typing import Optional

from sqlalchemy import (JSON, Boolean, Date, DateTime, Float, ForeignKey,
                        Index, Integer, String, Text, UniqueConstraint)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from db import Base

ROLES = ("owner", "admin", "member")
SENSITIVITIES = {
    # Probability at or above which a prompt is blocked.
    "strict": 0.35,
    "balanced": 0.5,
    "permissive": 0.7,
}


def _uuid() -> str:
    return str(uuid.uuid4())


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Organization(Base):
    __tablename__ = "organizations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(120))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    # Data handling, chosen by the customer.
    retention_days: Mapped[int] = mapped_column(Integer, default=30)
    store_prompts: Mapped[bool] = mapped_column(Boolean, default=True)
    contribute_training: Mapped[bool] = mapped_column(Boolean, default=False)
    sensitivity: Mapped[str] = mapped_column(String(16), default="balanced")
    chat_daily_cap: Mapped[int] = mapped_column(Integer, default=50)

    # The customer's own LLM, used by the /v1 proxy. The key is encrypted.
    upstream_base_url: Mapped[Optional[str]] = mapped_column(String(300))
    upstream_model: Mapped[Optional[str]] = mapped_column(String(120))
    upstream_key_encrypted: Mapped[Optional[str]] = mapped_column(Text)

    users: Mapped[list["User"]] = relationship(back_populates="org", passive_deletes=True)


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    email: Mapped[str] = mapped_column(String(254), unique=True)
    name: Mapped[Optional[str]] = mapped_column(String(120))
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(16), default="member")
    is_platform_admin: Mapped[bool] = mapped_column(Boolean, default=False)
    email_verified_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    failed_logins: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_login_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))

    org: Mapped[Organization] = relationship(back_populates="users")


class AuthSession(Base):
    __tablename__ = "sessions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    # Only a hash is stored, so a database leak does not hand out live sessions.
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    csrf_token: Mapped[str] = mapped_column(String(64))
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    ip: Mapped[Optional[str]] = mapped_column(String(64))
    user_agent: Mapped[Optional[str]] = mapped_column(String(300))

    user: Mapped[User] = relationship()


class ApiKey(Base):
    __tablename__ = "api_keys"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(80))
    # Enough of the key to recognise it in a list; the rest is never stored.
    prefix: Mapped[str] = mapped_column(String(20))
    key_hash: Mapped[str] = mapped_column(String(64), unique=True)
    created_by: Mapped[Optional[str]] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_used_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))


class EmailToken(Base):
    """Single-use, expiring links: verify email, reset password, accept invite."""
    __tablename__ = "email_tokens"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    purpose: Mapped[str] = mapped_column(String(16))  # verify | reset | invite
    email: Mapped[str] = mapped_column(String(254))
    user_id: Mapped[Optional[str]] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    org_id: Mapped[Optional[str]] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"))
    role: Mapped[Optional[str]] = mapped_column(String(16))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    used_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))


class AuditLog(Base):
    __tablename__ = "audit_logs"
    __table_args__ = (
        Index("ix_audit_org_id_desc", "org_id", "id"),
        Index("ix_audit_org_verdict", "org_id", "verdict"),
        Index("ix_audit_org_ts", "org_id", "timestamp"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    org_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"))
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    # Null when the organisation has turned prompt storage off.
    prompt: Mapped[Optional[str]] = mapped_column(Text)
    prompt_sha256: Mapped[str] = mapped_column(String(64))
    verdict: Mapped[str] = mapped_column(String(16))
    malicious: Mapped[bool] = mapped_column(Boolean)
    category: Mapped[Optional[str]] = mapped_column(String(80))
    risk_score: Mapped[int] = mapped_column(Integer, default=0)
    risk_level: Mapped[Optional[str]] = mapped_column(String(16))
    priority_level: Mapped[Optional[str]] = mapped_column(String(4))
    confidence: Mapped[Optional[float]] = mapped_column(Float)
    latency_ms: Mapped[Optional[float]] = mapped_column(Float)
    channel: Mapped[str] = mapped_column(String(16), default="api")
    api_key_id: Mapped[Optional[str]] = mapped_column(ForeignKey("api_keys.id", ondelete="SET NULL"))
    request_id: Mapped[Optional[str]] = mapped_column(String(64))
    payload: Mapped[dict] = mapped_column(JSON)


class ReviewItem(Base):
    __tablename__ = "review_queue"
    __table_args__ = (
        # The same borderline prompt arriving repeatedly should not bury the
        # queue in duplicates of a decision already made.
        UniqueConstraint("org_id", "prompt_sha256", name="uq_review_org_prompt"),
        Index("ix_review_org_status", "org_id", "status", "id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    org_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    prompt: Mapped[str] = mapped_column(Text)
    prompt_sha256: Mapped[str] = mapped_column(String(64))
    verdict: Mapped[str] = mapped_column(String(16))
    predicted_label: Mapped[int] = mapped_column(Integer)
    risk_score: Mapped[int] = mapped_column(Integer)
    category: Mapped[Optional[str]] = mapped_column(String(80))
    priority_level: Mapped[Optional[str]] = mapped_column(String(4))
    queued_reason: Mapped[str] = mapped_column(String(32))
    status: Mapped[str] = mapped_column(String(16), default="pending")
    true_label: Mapped[Optional[int]] = mapped_column(Integer)
    reviewer_note: Mapped[Optional[str]] = mapped_column(Text)
    reviewed_by: Mapped[Optional[str]] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    reviewed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    exported: Mapped[bool] = mapped_column(Boolean, default=False)
    payload: Mapped[dict] = mapped_column(JSON)


class UsageDaily(Base):
    __tablename__ = "usage_daily"

    org_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), primary_key=True)
    day: Mapped[date] = mapped_column(Date, primary_key=True)
    scans: Mapped[int] = mapped_column(Integer, default=0)
    chat_messages: Mapped[int] = mapped_column(Integer, default=0)
