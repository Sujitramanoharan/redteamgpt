"""Sign-up, sign-in and account recovery.

Design choices worth knowing:
- Responses never reveal whether an email is registered (sign-up, resend and
  forgot-password all answer the same way), so the API cannot be used to
  enumerate customers.
- Sessions are only ever issued to verified users, so nothing downstream has
  to re-check verification.
- Passwords use Argon2id; session, reset and invite tokens are random and
  stored only as SHA-256 hashes.
"""
import logging
from datetime import timedelta
from typing import Optional

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from email_validator import EmailNotValidError, validate_email
from fastapi import (APIRouter, BackgroundTasks, Depends, HTTPException, Request,
                     Response, status)
from pydantic import BaseModel, Field
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

import emailer
import usage
from config import settings
from db import get_db
from models_db import AuthSession, EmailToken, Organization, User, utcnow
from security import (CSRF_COOKIE, SESSION_COOKIE, _aware, client_ip, hash_token,
                      load_session, new_token)

logger = logging.getLogger("redteamgpt.auth")
router = APIRouter(prefix="/api/auth", tags=["auth"])
hasher = PasswordHasher()

# Computed once so a login for an unknown email costs the same as a real one:
# timing must not reveal which emails have accounts.
_DUMMY_HASH = hasher.hash("timing-equaliser-not-a-real-password")

TOKEN_TTL = {"verify": timedelta(hours=24), "reset": timedelta(hours=1),
             "invite": timedelta(days=7)}
GENERIC_EMAIL_SENT = {"status": "ok",
                      "message": "If that address can receive email, a message is on its way."}
MIN_PASSWORD = 10
_COMMON = {"password12", "password123", "1234567890", "qwertyuiop", "letmein123",
           "welcome123", "iloveyou12", "admin12345", "passw0rd12", "0987654321"}


# --- Schemas ---------------------------------------------------------------
class SignupRequest(BaseModel):
    email: str = Field(..., max_length=254)
    password: str = Field(..., max_length=200)
    org_name: str = Field(..., min_length=2, max_length=120)
    name: Optional[str] = Field(default=None, max_length=120)


class LoginRequest(BaseModel):
    email: str = Field(..., max_length=254)
    password: str = Field(..., max_length=200)


class EmailRequest(BaseModel):
    email: str = Field(..., max_length=254)


class TokenRequest(BaseModel):
    token: str = Field(..., max_length=200)


class ResetRequest(BaseModel):
    token: str = Field(..., max_length=200)
    password: str = Field(..., max_length=200)


class InviteAcceptRequest(BaseModel):
    token: str = Field(..., max_length=200)
    password: str = Field(..., max_length=200)
    name: Optional[str] = Field(default=None, max_length=120)


class ChangePasswordRequest(BaseModel):
    current_password: str = Field(..., max_length=200)
    new_password: str = Field(..., max_length=200)


# --- Helpers ---------------------------------------------------------------
def normalise_email(raw: str) -> str:
    try:
        # Deliverability (DNS) checks are skipped: they are slow, flaky behind
        # corporate DNS, and the verification email proves the address anyway.
        return validate_email(raw.strip(), check_deliverability=False).normalized.lower()
    except EmailNotValidError as exc:
        raise HTTPException(status_code=422, detail=f"Invalid email address: {exc}")


def check_password(password: str, email: str = "") -> None:
    problems = []
    if len(password) < MIN_PASSWORD:
        problems.append(f"at least {MIN_PASSWORD} characters")
    if password.lower() in _COMMON or len(set(password)) < 4:
        problems.append("not a common or repetitive password")
    if email and email.split("@")[0].lower() in password.lower() and len(email.split("@")[0]) > 3:
        problems.append("not contain your email name")
    if problems:
        raise HTTPException(status_code=422, detail="Password must be " + ", ".join(problems) + ".")


def issue_email_token(db: Session, purpose: str, email: str, *, user_id=None,
                      org_id=None, role=None) -> str:
    # One live token per purpose and address: requesting a new link kills the old.
    db.execute(delete(EmailToken).where(EmailToken.email == email,
                                        EmailToken.purpose == purpose,
                                        EmailToken.used_at.is_(None)))
    token = new_token()
    db.add(EmailToken(token_hash=hash_token(token), purpose=purpose, email=email,
                      user_id=user_id, org_id=org_id, role=role,
                      expires_at=utcnow() + TOKEN_TTL[purpose]))
    return token


def consume_email_token(db: Session, token: str, purpose: str) -> EmailToken:
    record = db.scalar(select(EmailToken).where(EmailToken.token_hash == hash_token(token),
                                                EmailToken.purpose == purpose))
    if record is None or record.used_at is not None or _aware(record.expires_at) <= utcnow():
        raise HTTPException(status_code=400,
                            detail="This link is invalid or has expired. Request a new one.")
    record.used_at = utcnow()
    return record


def start_session(db: Session, user: User, request: Request, response: Response) -> dict:
    token, csrf = new_token(), new_token(24)
    now = utcnow()
    db.add(AuthSession(token_hash=hash_token(token), csrf_token=csrf, user_id=user.id,
                       expires_at=now + timedelta(hours=settings.session_ttl_hours),
                       ip=client_ip(request),
                       user_agent=(request.headers.get("user-agent") or "")[:300]))
    user.last_login_at = now
    max_age = settings.session_ttl_hours * 3600
    secure = settings.app_base_url.startswith("https://")
    response.set_cookie(SESSION_COOKIE, token, max_age=max_age, httponly=True,
                        secure=secure, samesite="lax", path="/")
    # Readable by the page's own script, which echoes it in X-CSRF-Token.
    response.set_cookie(CSRF_COOKIE, csrf, max_age=max_age, httponly=False,
                        secure=secure, samesite="lax", path="/")
    return me_payload(db, user, csrf)


def clear_session_cookies(response: Response) -> None:
    response.delete_cookie(SESSION_COOKIE, path="/")
    response.delete_cookie(CSRF_COOKIE, path="/")


def me_payload(db: Session, user: User, csrf: str) -> dict:
    org = db.get(Organization, user.org_id)
    return {
        "user": {"id": user.id, "email": user.email, "name": user.name, "role": user.role,
                 "is_platform_admin": user.is_platform_admin},
        "org": {"id": org.id, "name": org.name},
        "usage_today": usage.get_today(org.id),
        "limits": {"chat_daily_cap": org.chat_daily_cap},
        "csrf_token": csrf,
    }


def _verified_now(user: User) -> None:
    if user.email_verified_at is None:
        user.email_verified_at = utcnow()


# --- Routes ----------------------------------------------------------------
@router.get("/config")
def auth_config():
    """What the sign-in pages need to know before anyone is signed in."""
    return {"signup_enabled": settings.signup_enabled,
            "email_verification_required": settings.email_verification_required,
            "min_password_length": MIN_PASSWORD}


@router.post("/signup")
def signup(req: SignupRequest, request: Request, response: Response,
           background: BackgroundTasks, db: Session = Depends(get_db)):
    if not settings.signup_enabled:
        raise HTTPException(status_code=403, detail="Sign-up is currently closed.")
    email = normalise_email(req.email)
    check_password(req.password, email)

    if db.scalar(select(User.id).where(User.email == email)):
        # Same answer as a fresh sign-up, so the endpoint cannot be used to
        # discover who is a customer.
        logger.info("Sign-up attempted for an existing account")
        return GENERIC_EMAIL_SENT | {"verification_required": True}

    org = Organization(name=req.org_name.strip(), retention_days=settings.audit_retention_days,
                       chat_daily_cap=settings.default_chat_daily_cap)
    db.add(org)
    db.flush()
    user = User(org_id=org.id, email=email, name=(req.name or "").strip() or None,
                password_hash=hasher.hash(req.password), role="owner")
    db.add(user)
    db.flush()
    logger.info("New organisation created")

    if not settings.email_verification_required:
        _verified_now(user)
        return start_session(db, user, request, response) | {"verification_required": False}

    token = issue_email_token(db, "verify", email, user_id=user.id)
    background.add_task(emailer.verification, email, token)
    return GENERIC_EMAIL_SENT | {"verification_required": True}


@router.post("/verify-email")
def verify_email(req: TokenRequest, request: Request, response: Response,
                 db: Session = Depends(get_db)):
    record = consume_email_token(db, req.token, "verify")
    user = db.get(User, record.user_id)
    if user is None:
        raise HTTPException(status_code=400, detail="This account no longer exists.")
    _verified_now(user)
    return start_session(db, user, request, response)


@router.post("/resend-verification")
def resend_verification(req: EmailRequest, background: BackgroundTasks,
                        db: Session = Depends(get_db)):
    email = normalise_email(req.email)
    user = db.scalar(select(User).where(User.email == email))
    if user is not None and user.email_verified_at is None:
        token = issue_email_token(db, "verify", email, user_id=user.id)
        background.add_task(emailer.verification, email, token)
    return GENERIC_EMAIL_SENT


@router.post("/login")
def login(req: LoginRequest, request: Request, response: Response,
          db: Session = Depends(get_db)):
    invalid = HTTPException(status_code=401, detail="Incorrect email or password.")
    try:
        email = normalise_email(req.email)
    except HTTPException:
        raise invalid
    user = db.scalar(select(User).where(User.email == email))

    if user is None:
        try:
            hasher.verify(_DUMMY_HASH, req.password)
        except VerifyMismatchError:
            pass
        raise invalid

    now = utcnow()
    if user.locked_until and _aware(user.locked_until) > now:
        raise HTTPException(status_code=429,
                            detail="Too many failed attempts. Try again later or reset your password.")

    try:
        hasher.verify(user.password_hash, req.password)
    except (VerifyMismatchError, InvalidHashError):
        user.failed_logins += 1
        if user.failed_logins >= settings.login_max_failures:
            user.locked_until = now + timedelta(minutes=settings.login_lockout_minutes)
            user.failed_logins = 0
            logger.warning("Account locked after repeated failed sign-ins")
        # get_db commits on success only; commit the counter before raising.
        db.commit()
        raise invalid

    if user.email_verified_at is None and settings.email_verification_required:
        raise HTTPException(status_code=403, detail="verify_email")

    user.failed_logins, user.locked_until = 0, None
    if hasher.check_needs_rehash(user.password_hash):
        user.password_hash = hasher.hash(req.password)
    return start_session(db, user, request, response)


@router.post("/logout")
def logout(request: Request, response: Response, db: Session = Depends(get_db)):
    sess = load_session(request, db)
    if sess is not None:
        db.delete(sess)
    clear_session_cookies(response)
    return {"status": "signed_out"}


@router.get("/me")
def me(request: Request, db: Session = Depends(get_db)):
    sess = load_session(request, db)
    if sess is None:
        raise HTTPException(status_code=401, detail="Not signed in.")
    return me_payload(db, sess.user, sess.csrf_token)


@router.post("/forgot-password")
def forgot_password(req: EmailRequest, background: BackgroundTasks,
                    db: Session = Depends(get_db)):
    email = normalise_email(req.email)
    user = db.scalar(select(User).where(User.email == email))
    if user is not None:
        token = issue_email_token(db, "reset", email, user_id=user.id)
        background.add_task(emailer.password_reset, email, token)
    return GENERIC_EMAIL_SENT


@router.post("/reset-password")
def reset_password(req: ResetRequest, request: Request, response: Response,
                   db: Session = Depends(get_db)):
    record = consume_email_token(db, req.token, "reset")
    user = db.get(User, record.user_id)
    if user is None:
        raise HTTPException(status_code=400, detail="This account no longer exists.")
    check_password(req.password, user.email)
    user.password_hash = hasher.hash(req.password)
    user.failed_logins, user.locked_until = 0, None
    _verified_now(user)  # they just proved they own the address
    # Whoever knew the old password must lose access.
    db.execute(delete(AuthSession).where(AuthSession.user_id == user.id))
    return start_session(db, user, request, response)


@router.post("/accept-invite")
def accept_invite(req: InviteAcceptRequest, request: Request, response: Response,
                  db: Session = Depends(get_db)):
    record = consume_email_token(db, req.token, "invite")
    if db.scalar(select(User.id).where(User.email == record.email)):
        raise HTTPException(status_code=409,
                            detail="An account with this email already exists. "
                                   "Accounts can belong to one organisation.")
    if db.get(Organization, record.org_id) is None:
        raise HTTPException(status_code=400, detail="This organisation no longer exists.")
    check_password(req.password, record.email)
    user = User(org_id=record.org_id, email=record.email,
                name=(req.name or "").strip() or None,
                password_hash=hasher.hash(req.password), role=record.role or "member",
                email_verified_at=utcnow())
    db.add(user)
    db.flush()
    return start_session(db, user, request, response)


@router.post("/change-password")
def change_password(req: ChangePasswordRequest, request: Request, response: Response,
                    db: Session = Depends(get_db)):
    sess = load_session(request, db)
    if sess is None:
        raise HTTPException(status_code=401, detail="Not signed in.")
    from security import _from_session
    _from_session(request, db)  # enforces the CSRF check
    user = sess.user
    try:
        hasher.verify(user.password_hash, req.current_password)
    except (VerifyMismatchError, InvalidHashError):
        raise HTTPException(status_code=400, detail="Current password is incorrect.")
    check_password(req.new_password, user.email)
    user.password_hash = hasher.hash(req.new_password)
    # Sign out every other device.
    db.execute(delete(AuthSession).where(AuthSession.user_id == user.id,
                                         AuthSession.id != sess.id))
    return {"status": "password_changed"}
