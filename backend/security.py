"""Authentication, rate limiting and hardening middleware.

Auth is opt-in via REQUIRE_AUTH so a public demo deployment still works, but the
moment real keys are configured the whole API is gated.
"""
import hashlib
import hmac
import time
from collections import defaultdict, deque
from threading import Lock

from fastapi import Header, HTTPException, Request, status
from starlette.middleware.base import BaseHTTPMiddleware

from config import settings


def _fingerprint(key: str) -> str:
    """Short, non-reversible id so logs can attribute traffic without storing keys."""
    return hashlib.sha256(key.encode()).hexdigest()[:12]


async def require_api_key(x_api_key: str = Header(default="")) -> str:
    """Resolve the caller. Returns a client id used for rate limiting and audit."""
    if not settings.auth_enforced:
        return "public"

    # compare_digest on every candidate keeps rejection time independent of the key.
    for valid in settings.api_keys:
        if hmac.compare_digest(x_api_key, valid):
            return _fingerprint(x_api_key)

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or missing API key. Send it in the X-API-Key header.",
        headers={"WWW-Authenticate": "ApiKey"},
    )


class RateLimiter:
    """Sliding-window limiter. In-process, which is correct for a single
    instance; move to Redis when running more than one replica."""

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


limiter = RateLimiter(settings.rate_limit_per_minute)


class RateLimitMiddleware(BaseHTTPMiddleware):
    EXEMPT = {"/health", "/ready", "/metrics"}

    async def dispatch(self, request: Request, call_next):
        if request.url.path in self.EXEMPT or request.method == "OPTIONS":
            return await call_next(request)
        if not request.url.path.startswith(("/api/", "/v1/")):
            return await call_next(request)

        key = request.headers.get("x-api-key", "")
        client_id = _fingerprint(key) if key else (
            request.client.host if request.client else "unknown"
        )

        allowed, remaining, retry_after = limiter.check(client_id)
        if not allowed:
            from fastapi.responses import JSONResponse
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={"detail": "Rate limit exceeded. Slow down and retry shortly."},
                headers={
                    "Retry-After": str(retry_after),
                    "X-RateLimit-Limit": str(limiter.limit),
                    "X-RateLimit-Remaining": "0",
                },
            )

        response = await call_next(request)
        response.headers["X-RateLimit-Limit"] = str(limiter.limit)
        response.headers["X-RateLimit-Remaining"] = str(remaining)
        return response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        if settings.is_production:
            response.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains"
            )
        return response
