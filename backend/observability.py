"""Structured logging, request correlation and Prometheus instrumentation."""
import json
import logging
import sys
import time
import uuid
from contextvars import ContextVar

from fastapi import Request
from prometheus_client import Counter, Gauge, Histogram
from starlette.middleware.base import BaseHTTPMiddleware

from config import settings

request_id_ctx: ContextVar[str] = ContextVar("request_id", default="-")


class JsonFormatter(logging.Formatter):
    """One JSON object per line, which is what every log aggregator expects."""

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "request_id": request_id_ctx.get(),
        }
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        for key, value in getattr(record, "extra_fields", {}).items():
            payload[key] = value
        return json.dumps(payload, ensure_ascii=False)


def configure_logging() -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(
        JsonFormatter() if settings.log_json
        else logging.Formatter("%(asctime)s %(levelname)-8s %(name)s :: %(message)s")
    )
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(settings.log_level.upper())
    # Uvicorn duplicates access logs through its own handlers; route them here.
    for name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        lg = logging.getLogger(name)
        lg.handlers.clear()
        lg.propagate = True


# --- Prometheus metrics ---------------------------------------------------
REQUESTS = Counter(
    "redteamgpt_requests_total", "HTTP requests", ["method", "endpoint", "status"]
)
LATENCY = Histogram(
    "redteamgpt_request_duration_seconds", "Request latency", ["endpoint"],
    buckets=(0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0),
)
SCANS = Counter(
    "redteamgpt_prompt_scans_total", "Prompts scanned", ["verdict", "priority"]
)
INFERENCE = Histogram(
    "redteamgpt_inference_duration_seconds", "Model inference latency",
    buckets=(0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0),
)
MODEL_READY = Gauge("redteamgpt_model_ready", "1 when the detector is loaded")


def record_scan(result: dict) -> None:
    SCANS.labels(
        verdict=result.get("verdict", "UNKNOWN"),
        priority=(result.get("priority") or {}).get("level", "P4"),
    ).inc()
    INFERENCE.observe(result.get("latency_ms", 0) / 1000)


class RequestContextMiddleware(BaseHTTPMiddleware):
    """Attach a request id, time the call, and emit one structured access log."""

    async def dispatch(self, request: Request, call_next):
        request_id = request.headers.get("x-request-id") or uuid.uuid4().hex[:16]
        token = request_id_ctx.set(request_id)
        started = time.perf_counter()
        endpoint = request.url.path
        log = logging.getLogger("redteamgpt.access")

        try:
            response = await call_next(request)
            status_code = response.status_code
        except Exception:
            log.exception("Unhandled error", extra={"extra_fields": {"path": endpoint}})
            REQUESTS.labels(request.method, endpoint, "500").inc()
            request_id_ctx.reset(token)
            raise

        elapsed = time.perf_counter() - started
        REQUESTS.labels(request.method, endpoint, str(status_code)).inc()
        LATENCY.labels(endpoint).observe(elapsed)

        if endpoint not in ("/metrics", "/health", "/ready"):
            log.info(
                "%s %s %s", request.method, endpoint, status_code,
                extra={"extra_fields": {
                    "method": request.method,
                    "path": endpoint,
                    "status": status_code,
                    "duration_ms": round(elapsed * 1000, 2),
                    "client": request.client.host if request.client else None,
                }},
            )

        response.headers["X-Request-ID"] = request_id
        request_id_ctx.reset(token)
        return response
