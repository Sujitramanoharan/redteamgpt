"""Caller identity, rate limiting and hardening middleware.

Every request to a data endpoint resolves to a Principal: a signed-in dashboard
user (session cookie + CSRF token) or an integration (X-API-Key). Both belong
to exactly one organisation, and that org_id scopes everything downstream.
"""
import hashlib
import hmac
import secrets
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import timedelta
from threading import Lock
from typing import Optional

from fastapi import Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse
from sqlalchemy import select
from sqlalchemy.orm import Session
from starlette.middleware.base import BaseHTTPMiddleware

from config import settings
from db import get_db
from models_db import ApiKey, AuthSession, Organization, User, utcnow

SESSION_COOKIE = "rtg_session"
CSRF_COOKIE = "rtg_csrf"
CSRF_HEADER = "x-csrf-token"
API_KEY_PREFIX = "rtg_live_"
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
ROLE_RANK = {"member": 1, "admin": 2, "owner": 3}


def hash_token(token: str) -> str:
    """Tokens are long random strings, so a plain SHA-256 is enough; no salt
    or slow hash is needed the way it is for passwords."""
    return hashlib.sha256(token.encode()).hexdigest()


def new_token(nbytes: int = 32) -> str:
    return secrets.token_urlsafe(nbytes)


def _fingerprint(value: str) -> str:
    """Short, non-reversible id so logs and limits can attribute traffic."""
    return hash_token(value)[:12]


def client_ip(request: Request) -> str:
    # uvicorn runs with --proxy-headers behind Render's proxy, so this is the
    # real client address rather than the load balancer's.
    return request.client.host if request.client else "unknown"


@dataclass(frozen=True)
class Principal:
    org_id: str
    via: str                      # "session" or "api_key"
    role: str                     # owner | admin | member | api
    user_id: Optional[str] = None
    email: Optional[str] = None
    api_key_id: Optional[str] = None
    is_platform_admin: bool = False

    @property
    def client_id(self) -> str:
        return self.api_key_id or self.user_id or self.org_id


def _from_api_key(raw: str, db: Session) -> Principal:
    key = db.scalar(select(ApiKey).where(ApiKey.key_hash == hash_token(raw),
                                         ApiKey.revoked_at.is_(None)))
    if key is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or revoked API key.",
            headers={"WWW-Authenticate": "ApiKey"},
        )
    now = utcnow()
    # Writing on every request would turn each scan into a database write;
    # minute resolution is plenty for "last used".
    if key.last_used_at is None or now - _aware(key.last_used_at) > timedelta(minutes=1):
        key.last_used_at = now
    return Principal(org_id=key.org_id, via="api_key", role="api", api_key_id=key.id)


def _aware(dt):
    """SQLite returns naive datetimes even for timezone-aware columns."""
    from datetime import timezone
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def load_session(request: Request, db: Session) -> Optional[AuthSession]:
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        return None
    sess = db.scalar(select(AuthSession).where(AuthSession.token_hash == hash_token(token)))
    if sess is None or _aware(sess.expires_at) <= utcnow():
        return None
    return sess


def _from_session(request: Request, db: Session) -> Optional[Principal]:
    sess = load_session(request, db)
    if sess is None:
        return None

    # Cookies are sent automatically by the browser, so a state-changing
    # request must also prove it came from our own page: the CSRF token is
    # readable only by same-origin script.
    if request.method not in SAFE_METHODS:
        sent = request.headers.get(CSRF_HEADER, "")
        if not hmac.compare_digest(sent, sess.csrf_token):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                                detail="Missing or invalid CSRF token. Reload the page.")

    now = utcnow()
    # Sliding expiry, refreshed at most hourly to avoid a write per request.
    if now - _aware(sess.last_seen_at) > timedelta(hours=1):
        sess.last_seen_at = now
        sess.expires_at = now + timedelta(hours=settings.session_ttl_hours)

    user = sess.user
    return Principal(org_id=user.org_id, via="session", role=user.role,
                     user_id=user.id, email=user.email,
                     is_platform_admin=user.is_platform_admin)


def get_principal(request: Request, db: Session = Depends(get_db)) -> Principal:
    raw_key = request.headers.get("x-api-key", "").strip()
    if raw_key:
        principal = _from_api_key(raw_key, db)
    else:
        principal = _from_session(request, db)
        if principal is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Sign in, or send an API key in the X-API-Key header.",
                headers={"WWW-Authenticate": "ApiKey"},
            )
    # Commit the last-used / sliding-expiry bookkeeping now rather than at the
    # end of the request, so no write lock is held while the endpoint works.
    db.commit()
    request.state.principal = principal
    return principal


def require_session(principal: Principal = Depends(get_principal)) -> Principal:
    """Dashboard-only actions: managing keys, members and settings."""
    if principal.via != "session":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="This action is only available in the dashboard.")
    return principal


def require_role(minimum: str):
    """Dependency factory: the signed-in user's role must be at least `minimum`."""
    def dependency(principal: Principal = Depends(require_session)) -> Principal:
        if ROLE_RANK.get(principal.role, 0) < ROLE_RANK[minimum]:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                                detail=f"Requires the {minimum} role or higher.")
        return principal
    return dependency


def require_platform_admin(principal: Principal = Depends(require_session)) -> Principal:
    if not principal.is_platform_admin:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")
    return principal


def get_org(principal: Principal, db: Session) -> Organization:
    org = db.get(Organization, principal.org_id)
    if org is None:  # deleted while a session or key was still live
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Organisation no longer exists.")
    return org


# --- Rate limiting --------------------------------------------------------
class RateLimiter:
    """Sliding-window limiter. In-process, which is correct for a single
    instance; RedisRateLimiter shares state when running several."""

    def __init__(self, limit_per_minute: int):
        self.limit = limit_per_minute
        self._hits: dict[str, deque] = defaultdict(deque)
        self._lock = Lock()

    def check(self, client_id: str) -> tuple[bool, int, int]:
        """Returns (allowed, remaining, retry_after_seconds)."""
        now = time.monotonic()
        with self._lock:
            bucket = self._hits[client_id]
            while bucket and now - bucket[0] > 60:
                bucket.popleft()

            if len(bucket) >= self.limit:
                return False, 0, int(61 - (now - bucket[0]))

            bucket.append(now)
            return True, self.limit - len(bucket), 0

    def sweep(self) -> None:
        """Drop idle buckets so memory does not grow without bound."""
        now = time.monotonic()
        with self._lock:
            for cid in [c for c, b in self._hits.items() if not b or now - b[-1] > 300]:
                del self._hits[cid]

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()


class RedisRateLimiter:
    """Fixed one-minute windows in Redis, shared by every instance."""

    def __init__(self, limit_per_minute: int, url: str, namespace: str):
        import redis

        self.limit = limit_per_minute
        self.namespace = namespace
        self._redis = redis.Redis.from_url(url, socket_timeout=0.5)

    def check(self, client_id: str) -> tuple[bool, int, int]:
        window = int(time.time() // 60)
        key = f"rl:{self.namespace}:{client_id}:{window}"
        try:
            pipe = self._redis.pipeline()
            pipe.incr(key)
            pipe.expire(key, 61)
            count = int(pipe.execute()[0])
        except Exception:
            # Fail open on a Redis outage: rate limiting protects capacity, and
            # refusing every request would be a worse outage than the one it
            # prevents. The firewall itself still runs on every request.
            return True, self.limit, 0
        if count > self.limit:
            return False, 0, int(60 - time.time() % 60) + 1
        return True, self.limit - count, 0

    def sweep(self) -> None:
        pass  # keys expire on their own

    def reset(self) -> None:
        pass


def _make_limiter(limit: int, namespace: str):
    if settings.redis_url:
        return RedisRateLimiter(limit, settings.redis_url, namespace)
    return RateLimiter(limit)


limiter = _make_limiter(settings.rate_limit_per_minute, "api")
# Separate, much lower budget for sign-in and sign-up, keyed by IP, so
# password guessing and account-creation spam hit a wall quickly.
auth_limiter = _make_limiter(settings.auth_rate_limit_per_minute, "auth")
AUTH_LIMITED_PATHS = {
    "/api/auth/login", "/api/auth/signup", "/api/auth/forgot-password",
    "/api/auth/reset-password", "/api/auth/resend-verification",
    "/api/auth/accept-invite", "/api/auth/verify-email",
}


def _too_many(limit: int, retry_after: int) -> JSONResponse:
    return JSONResponse(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        content={"detail": "Too many requests. Slow down and retry shortly."},
        headers={"Retry-After": str(retry_after),
                 "X-RateLimit-Limit": str(limit), "X-RateLimit-Remaining": "0"},
    )


class RateLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        if request.method == "OPTIONS" or not path.startswith(("/api/", "/v1/")):
            return await call_next(request)

        if path in AUTH_LIMITED_PATHS and request.method == "POST":
            allowed, _, retry_after = auth_limiter.check(client_ip(request))
            if not allowed:
                return _too_many(auth_limiter.limit, retry_after)
            return await call_next(request)

        # Keyed by credential rather than IP, so customers behind one NAT do
        # not share a budget, and one customer cannot exhaust another's.
        key = request.headers.get("x-api-key", "")
        cookie = request.cookies.get(SESSION_COOKIE, "")
        client_id = (_fingerprint(key) if key else
                     _fingerprint(cookie) if cookie else client_ip(request))

        allowed, remaining, retry_after = limiter.check(client_id)
        if not allowed:
            return _too_many(limiter.limit, retry_after)

        response = await call_next(request)
        response.headers["X-RateLimit-Limit"] = str(limiter.limit)
        response.headers["X-RateLimit-Remaining"] = str(remaining)
        return response


# Content-Security-Policy for the dashboard. Everything is self-hosted except
# the Google Fonts stylesheet the design uses.
CSP = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
    "font-src 'self' https://fonts.gstatic.com; "
    "img-src 'self' data:; "
    "connect-src 'self'; "
    "frame-ancestors 'none'; "
    "base-uri 'self'; "
    "form-action 'self'"
)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        if not request.url.path.startswith(("/api/", "/v1/", "/docs", "/openapi.json")):
            response.headers["Content-Security-Policy"] = CSP
        if settings.is_production:
            response.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains"
            )
        return response
