"""Organisation settings, members, invitations, API keys, usage, and the
platform operator's admin endpoints.

Permissions: any member can view; admins manage keys, invites and settings;
only the owner changes roles or deletes the organisation.
"""
import csv
import io
import logging
from typing import Literal, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Response
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

import crypto_box
import emailer
import llm_client
import usage
from auth import clear_session_cookies, issue_email_token, normalise_email
from config import settings
from db import get_db
from models_db import (SENSITIVITIES, ApiKey, AuditLog, EmailToken, Organization, User,
                       utcnow)
from review import store as review_store
from security import (API_KEY_PREFIX, ROLE_RANK, Principal, get_org, hash_token,
                      new_token, require_platform_admin, require_role, require_session)

logger = logging.getLogger("redteamgpt.account")
router = APIRouter(tags=["account"])


# --- Organisation ------------------------------------------------------------
class OrgUpdate(BaseModel):
    name: Optional[str] = Field(default=None, min_length=2, max_length=120)
    retention_days: Optional[int] = Field(default=None, ge=1)
    store_prompts: Optional[bool] = None
    contribute_training: Optional[bool] = None
    sensitivity: Optional[Literal["strict", "balanced", "permissive"]] = None


class UpstreamConfig(BaseModel):
    base_url: str = Field(..., max_length=300,
                          json_schema_extra={"example": "https://api.openai.com/v1"})
    model: str = Field(..., min_length=1, max_length=120)
    api_key: str = Field(..., min_length=8, max_length=500)


class OrgDelete(BaseModel):
    confirm_name: str


def org_view(org: Organization) -> dict:
    return {
        "id": org.id,
        "name": org.name,
        "created_at": org.created_at.isoformat(),
        "retention_days": org.retention_days,
        "max_retention_days": settings.max_retention_days,
        "store_prompts": org.store_prompts,
        "contribute_training": org.contribute_training,
        "sensitivity": org.sensitivity,
        "sensitivities": list(SENSITIVITIES),
        "chat_daily_cap": org.chat_daily_cap,
        "upstream": {
            "configured": bool(org.upstream_key_encrypted),
            "base_url": org.upstream_base_url,
            "model": org.upstream_model,
        },
    }


@router.get("/api/org")
def get_org_settings(principal: Principal = Depends(require_session),
                     db: Session = Depends(get_db)):
    return org_view(get_org(principal, db))


@router.patch("/api/org")
def update_org(req: OrgUpdate, principal: Principal = Depends(require_role("admin")),
               db: Session = Depends(get_db)):
    org = get_org(principal, db)
    changes = req.model_dump(exclude_none=True)
    if "retention_days" in changes and changes["retention_days"] > settings.max_retention_days:
        raise HTTPException(status_code=422,
                            detail=f"Retention is limited to {settings.max_retention_days} days.")
    for field, value in changes.items():
        setattr(org, field, value.strip() if isinstance(value, str) else value)
    logger.info("Organisation settings changed: %s", sorted(changes))
    return org_view(org)


@router.put("/api/org/upstream")
def set_upstream(req: UpstreamConfig, principal: Principal = Depends(require_role("admin")),
                 db: Session = Depends(get_db)):
    try:
        llm_client.assert_public_https_url(req.base_url)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    org = get_org(principal, db)
    org.upstream_base_url = req.base_url.rstrip("/")
    org.upstream_model = req.model.strip()
    org.upstream_key_encrypted = crypto_box.encrypt(req.api_key.strip())
    return org_view(org)


@router.delete("/api/org/upstream")
def clear_upstream(principal: Principal = Depends(require_role("admin")),
                   db: Session = Depends(get_db)):
    org = get_org(principal, db)
    org.upstream_base_url = org.upstream_model = org.upstream_key_encrypted = None
    return org_view(org)


@router.delete("/api/org")
def delete_org(req: OrgDelete, response: Response,
               principal: Principal = Depends(require_role("owner")),
               db: Session = Depends(get_db)):
    org = get_org(principal, db)
    if req.confirm_name.strip() != org.name:
        raise HTTPException(status_code=422,
                            detail="Type the organisation name exactly to confirm deletion.")
    # Foreign keys cascade: users, sessions, keys, logs, reviews and usage go too.
    db.delete(org)
    clear_session_cookies(response)
    logger.warning("Organisation deleted by its owner")
    return {"status": "deleted"}


# --- Members and invitations -----------------------------------------------
class InviteRequest(BaseModel):
    email: str = Field(..., max_length=254)
    role: Literal["admin", "member"] = "member"


class RoleChange(BaseModel):
    role: Literal["owner", "admin", "member"]


@router.get("/api/org/members")
def list_members(principal: Principal = Depends(require_session),
                 db: Session = Depends(get_db)):
    users = db.scalars(select(User).where(User.org_id == principal.org_id)
                       .order_by(User.created_at)).all()
    invites = db.scalars(select(EmailToken).where(
        EmailToken.org_id == principal.org_id, EmailToken.purpose == "invite",
        EmailToken.used_at.is_(None), EmailToken.expires_at > utcnow())).all()
    return {
        "members": [{"id": u.id, "email": u.email, "name": u.name, "role": u.role,
                     "last_login_at": u.last_login_at.isoformat() if u.last_login_at else None,
                     "is_you": u.id == principal.user_id} for u in users],
        "invites": [{"id": i.id, "email": i.email, "role": i.role,
                     "expires_at": i.expires_at.isoformat()} for i in invites],
    }


@router.post("/api/org/invites")
def invite_member(req: InviteRequest, background: BackgroundTasks,
                  principal: Principal = Depends(require_role("admin")),
                  db: Session = Depends(get_db)):
    email = normalise_email(req.email)
    if db.scalar(select(User.id).where(User.email == email)):
        raise HTTPException(status_code=409,
                            detail="That email already has an account. "
                                   "Accounts can belong to one organisation.")
    org = get_org(principal, db)
    token = issue_email_token(db, "invite", email, org_id=org.id, role=req.role)
    background.add_task(emailer.invitation, email, token, org.name, principal.email or "A teammate")
    return {"status": "invited", "email": email, "role": req.role}


@router.delete("/api/org/invites/{invite_id}")
def revoke_invite(invite_id: str, principal: Principal = Depends(require_role("admin")),
                  db: Session = Depends(get_db)):
    removed = db.execute(delete(EmailToken).where(
        EmailToken.id == invite_id, EmailToken.org_id == principal.org_id,
        EmailToken.purpose == "invite")).rowcount
    if not removed:
        raise HTTPException(status_code=404, detail="Invitation not found.")
    return {"status": "revoked"}


def _member(db: Session, principal: Principal, user_id: str) -> User:
    user = db.get(User, user_id)
    if user is None or user.org_id != principal.org_id:
        raise HTTPException(status_code=404, detail="Member not found.")
    return user


@router.patch("/api/org/members/{user_id}")
def change_role(user_id: str, req: RoleChange,
                principal: Principal = Depends(require_role("owner")),
                db: Session = Depends(get_db)):
    user = _member(db, principal, user_id)
    if user.id == principal.user_id and req.role != "owner":
        owners = db.scalar(select(func.count(User.id)).where(
            User.org_id == principal.org_id, User.role == "owner"))
        if owners <= 1:
            raise HTTPException(status_code=422,
                                detail="Make someone else an owner before stepping down.")
    user.role = req.role
    return {"id": user.id, "role": user.role}


@router.delete("/api/org/members/{user_id}")
def remove_member(user_id: str, principal: Principal = Depends(require_role("admin")),
                  db: Session = Depends(get_db)):
    user = _member(db, principal, user_id)
    if user.id == principal.user_id:
        raise HTTPException(status_code=422, detail="You cannot remove yourself.")
    if ROLE_RANK[user.role] >= ROLE_RANK[principal.role]:
        raise HTTPException(status_code=403,
                            detail="You can only remove members with a lower role than yours.")
    db.delete(user)  # sessions cascade, so they are signed out immediately
    return {"status": "removed"}


# --- API keys --------------------------------------------------------------
class KeyCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=80)


def key_view(k: ApiKey) -> dict:
    return {"id": k.id, "name": k.name, "prefix": k.prefix,
            "created_at": k.created_at.isoformat(),
            "last_used_at": k.last_used_at.isoformat() if k.last_used_at else None,
            "revoked": k.revoked_at is not None}


@router.get("/api/keys")
def list_keys(principal: Principal = Depends(require_session),
              db: Session = Depends(get_db)):
    keys = db.scalars(select(ApiKey).where(ApiKey.org_id == principal.org_id)
                      .order_by(ApiKey.created_at.desc())).all()
    return {"keys": [key_view(k) for k in keys]}


@router.post("/api/keys")
def create_key(req: KeyCreate, principal: Principal = Depends(require_role("admin")),
               db: Session = Depends(get_db)):
    active = db.scalar(select(func.count(ApiKey.id)).where(
        ApiKey.org_id == principal.org_id, ApiKey.revoked_at.is_(None)))
    if active >= 25:
        raise HTTPException(status_code=422, detail="Revoke unused keys first (limit 25).")
    raw = API_KEY_PREFIX + new_token(32)
    key = ApiKey(org_id=principal.org_id, name=req.name.strip(), prefix=raw[:16],
                 key_hash=hash_token(raw), created_by=principal.user_id)
    db.add(key)
    db.flush()
    # The only time the full key is ever shown.
    return key_view(key) | {"key": raw}


@router.delete("/api/keys/{key_id}")
def revoke_key(key_id: str, principal: Principal = Depends(require_role("admin")),
               db: Session = Depends(get_db)):
    key = db.get(ApiKey, key_id)
    if key is None or key.org_id != principal.org_id:
        raise HTTPException(status_code=404, detail="Key not found.")
    if key.revoked_at is None:
        key.revoked_at = utcnow()
    return key_view(key)


# --- Usage -----------------------------------------------------------------
@router.get("/api/usage")
def get_usage(principal: Principal = Depends(require_session),
              db: Session = Depends(get_db)):
    org = get_org(principal, db)
    return {"today": usage.get_today(org.id), "history": usage.history(org.id),
            "limits": {"chat_daily_cap": org.chat_daily_cap,
                       "rate_limit_per_minute": settings.rate_limit_per_minute}}


# --- Platform operator -----------------------------------------------------
# 404 for everyone else, so the endpoints' existence is not advertised.
@router.get("/api/admin/stats", include_in_schema=False)
def admin_stats(_: Principal = Depends(require_platform_admin),
                db: Session = Depends(get_db)):
    today_start = utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    return {
        "organizations": db.scalar(select(func.count(Organization.id))),
        "users": db.scalar(select(func.count(User.id))),
        "verified_users": db.scalar(select(func.count(User.id))
                                    .where(User.email_verified_at.is_not(None))),
        "active_api_keys": db.scalar(select(func.count(ApiKey.id))
                                     .where(ApiKey.revoked_at.is_(None))),
        "scans_today": db.scalar(select(func.count(AuditLog.id))
                                 .where(AuditLog.timestamp >= today_start)),
        "orgs_contributing_training": db.scalar(
            select(func.count(Organization.id)).where(Organization.contribute_training.is_(True))),
    }


@router.post("/api/admin/training-export", include_in_schema=False)
def admin_training_export(_: Principal = Depends(require_platform_admin)):
    """Reviewed decisions from opted-in organisations, as CSV for training.
    Downloaded rather than written to disk: the container's disk is ephemeral."""
    rows = review_store.export_training_rows(mark=True)
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=["text", "label", "source"])
    writer.writeheader()
    writer.writerows(rows)
    return StreamingResponse(
        iter([buf.getvalue()]), media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=review_feedback.csv",
                 "X-Exported-Rows": str(len(rows))},
    )
