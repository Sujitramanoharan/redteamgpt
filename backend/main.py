"""RedTeamGPT - production AI guardrail and prompt-injection firewall."""
import asyncio
import json
import logging
import sys
import time
from contextlib import asynccontextmanager
from datetime import timedelta
from pathlib import Path
from typing import List, Optional

_HERE = Path(__file__).parent
# Both dirs must be importable: sibling modules live in backend/, the engine in src/.
for _p in (str(_HERE), str(_HERE.parent / "src")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from fastapi import (Depends, FastAPI, File, HTTPException, Query, Request,
                     UploadFile, status)
from fastapi.concurrency import run_in_threadpool
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import delete
from sqlalchemy.orm import Session

from config import settings
from observability import (
    MODEL_READY,
    RequestContextMiddleware,
    configure_logging,
    record_scan,
)
import db as database
import usage
from db import get_db, session_scope
from models_db import SENSITIVITIES, AuthSession, EmailToken, Organization, utcnow
from security import (
    Principal,
    RateLimitMiddleware,
    SecurityHeadersMiddleware,
    auth_limiter,
    get_org,
    get_principal,
    limiter,
    require_role,
    require_session,
)
from review import store as review_store
from storage import store

configure_logging()
logger = logging.getLogger("redteamgpt")

ROOT = Path(__file__).parent.parent
FRONTEND = ROOT / "frontend"
DIST_DIR = FRONTEND / "dist"
METRICS_FILE = ROOT / "results" / "metrics.json"
START_TIME = time.time()
HOUSEKEEPING_INTERVAL_S = 6 * 3600


def _init_sentry() -> None:
    if not settings.sentry_dsn:
        return
    try:
        import sentry_sdk
    except ImportError:
        logger.warning("SENTRY_DSN is set but sentry-sdk is not installed")
        return
    # send_default_pii off: prompts and emails must not leave for a third party.
    sentry_sdk.init(dsn=settings.sentry_dsn, environment=settings.environment,
                    send_default_pii=False, traces_sample_rate=0.0)


def housekeeping() -> None:
    """Retention and expiry: old audit logs, dead sessions, used or stale links."""
    removed = store.prune_expired()
    now = utcnow()
    with session_scope() as s:
        sessions = s.execute(delete(AuthSession).where(AuthSession.expires_at < now)).rowcount
        tokens = s.execute(delete(EmailToken).where(
            EmailToken.expires_at < now - timedelta(days=1))).rowcount
    limiter.sweep()
    auth_limiter.sweep()
    if removed or sessions or tokens:
        logger.info("Housekeeping: %d audit rows past retention, %d expired sessions, "
                    "%d stale email links removed", removed, sessions, tokens)


async def _housekeeping_loop() -> None:
    while True:
        await asyncio.sleep(HOUSEKEEPING_INTERVAL_S)
        try:
            await run_in_threadpool(housekeeping)
        except Exception:
            logger.exception("Housekeeping failed")


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting %s v%s (env=%s)", settings.app_name, settings.version,
                settings.environment)
    problems = settings.production_problems()
    if problems:
        for p in problems:
            logger.critical("Refusing to start: %s", p)
        raise RuntimeError("Unsafe production configuration: " + "; ".join(problems))
    _init_sentry()

    if settings.auto_migrate:
        database.migrate()

    # Import here so a model failure surfaces as a clean startup error.
    from firewall import MODEL_INFO, detect

    detect("warmup")  # pay the first-inference cost before serving traffic
    MODEL_READY.set(1)
    logger.info("Detector ready: %s", MODEL_INFO)

    await run_in_threadpool(housekeeping)
    task = asyncio.create_task(_housekeeping_loop())
    if not settings.email_configured:
        logger.warning("SMTP is not configured - emails are logged instead of sent")
    yield
    task.cancel()
    MODEL_READY.set(0)
    logger.info("Shutdown complete")


app = FastAPI(
    title=settings.app_name,
    description="AI guardrail and real-time prompt-injection firewall. "
                "Authenticate with an API key from Settings → API keys, sent as X-API-Key.",
    version=settings.version,
    lifespan=lifespan,
    docs_url=None if settings.is_production else "/docs",
    redoc_url=None,
)

# Order matters: the outermost middleware is added last.
app.add_middleware(GZipMiddleware, minimum_size=1000)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RateLimitMiddleware)
if settings.cors_origins:
    # The dashboard is same-origin; this is only for customers calling the API
    # from their own browser apps.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=False,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["Content-Type", "X-API-Key", "X-Request-ID"],
    )
app.add_middleware(RequestContextMiddleware)

from auth import router as auth_router  # noqa: E402
from account import router as account_router  # noqa: E402

app.include_router(auth_router)
app.include_router(account_router)


# --- Schemas --------------------------------------------------------------
class PromptRequest(BaseModel):
    prompt: str = Field(..., max_length=settings.max_prompt_chars,
                        json_schema_extra={"example": "Ignore prior instructions."})


class BatchPromptRequest(BaseModel):
    prompts: List[str] = Field(..., max_length=settings.max_batch_size)

    @field_validator("prompts")
    @classmethod
    def _bound_each(cls, v):
        oversized = [i for i, p in enumerate(v) if len(p) > settings.max_prompt_chars]
        if oversized:
            raise ValueError(
                f"Prompts at index {oversized[:5]} exceed "
                f"{settings.max_prompt_chars} characters"
            )
        return v


class ChatMessage(BaseModel):
    model_config = ConfigDict(extra="allow")
    role: str
    content: Optional[str] = ""


class OpenAIChatCompletionRequest(BaseModel):
    # Extra OpenAI parameters (max_tokens, top_p, tools...) pass through untouched.
    model_config = ConfigDict(extra="allow")
    model: Optional[str] = None
    messages: List[ChatMessage]
    stream: Optional[bool] = False


# --- Scanning -------------------------------------------------------------
def _threshold(org: Organization) -> float:
    return SENSITIVITIES.get(org.sensitivity, settings.decision_threshold)


def _detect(prompt: str, org: Organization) -> dict:
    """Run the firewall. Fails closed: an error is a 503, never an ALLOWED."""
    from firewall import detect

    try:
        return detect(prompt, _threshold(org))
    except Exception:
        logger.exception("Detection failed")
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                            detail="The firewall could not analyse this prompt. "
                                   "Treat it as unscreened and retry.")


def _scan(prompt: str, principal: Principal, org: Organization, request: Request,
          channel: str, count_usage: bool = True) -> dict:
    """Run the firewall, persist the outcome, and queue it if borderline."""
    result = _detect(prompt, org)
    record_scan(result)
    store.record(result, org.id, channel=channel, api_key_id=principal.api_key_id,
                 request_id=request.headers.get("x-request-id"),
                 store_prompt=org.store_prompts)
    if count_usage:
        usage.increment(org.id, "scans")

    # A reviewer cannot judge a prompt the organisation chose not to keep.
    if settings.review_enabled and org.store_prompts:
        probability = result.get("malicious_probability", 0.0)
        if result.get("escalated_by_rules"):
            review_store.enqueue(result, "disagreement", org.id)
        elif settings.review_band_low <= probability <= settings.review_band_high:
            review_store.enqueue(result, "uncertain", org.id)
        elif (result.get("priority") or {}).get("level") == "P3":
            review_store.enqueue(result, "flagged", org.id)

    return result


def _channel(principal: Principal) -> str:
    return "api" if principal.via == "api_key" else "dashboard"


# --- Security API ---------------------------------------------------------
@app.post("/api/check", tags=["security"])
def check(req: PromptRequest, request: Request,
          principal: Principal = Depends(get_principal), db: Session = Depends(get_db)):
    """Analyse a single prompt for injection, jailbreak and policy violations."""
    return _scan(req.prompt, principal, get_org(principal, db), request, _channel(principal))


@app.post("/api/check-batch", tags=["security"])
def check_batch(req: BatchPromptRequest, request: Request,
                principal: Principal = Depends(get_principal), db: Session = Depends(get_db)):
    """Analyse up to the configured batch limit in one call."""
    if not req.prompts:
        return {"total": 0, "blocked_count": 0, "allowed_count": 0, "results": []}

    org = get_org(principal, db)
    results = [_scan(p, principal, org, request, _channel(principal), count_usage=False)
               for p in req.prompts]
    usage.increment(org.id, "scans", len(results))
    blocked = sum(1 for r in results if r["malicious"])
    return {
        "total": len(results),
        "blocked_count": blocked,
        "allowed_count": len(results) - blocked,
        "results": results,
    }


@app.post("/api/evasion-test", tags=["security"])
def evasion_test(req: PromptRequest, principal: Principal = Depends(get_principal),
                 db: Session = Depends(get_db)):
    """Run adversarial transformations to measure guardrail resiliency."""
    from firewall import run_evasion_test

    org = get_org(principal, db)
    usage.increment(org.id, "scans")
    return run_evasion_test(req.prompt, _threshold(org))


# --- OpenAI-compatible guardrail proxy ------------------------------------
def _guardrail_error(result: dict, message: str, code: str) -> JSONResponse:
    return JSONResponse(
        status_code=400,
        content={"error": {
            "message": message,
            "type": "guardrail_violation",
            "param": "messages",
            "code": code,
            # Output scans carry no risk score; only prompt scans do.
            "risk_score": result.get("risk_score"),
            "threat_category": result.get("category"),
            "priority": (result.get("priority") or {}).get("level"),
            "explanation": result.get("explanation"),
        }},
    )


@app.post("/v1/chat/completions", tags=["proxy"])
def openai_proxy(req: OpenAIChatCompletionRequest, request: Request,
                 principal: Principal = Depends(get_principal), db: Session = Depends(get_db)):
    """Drop-in replacement for the OpenAI chat endpoint.

    Screens the latest user message, forwards safe requests to the provider
    configured in Settings → Integrations using the organisation's own key,
    then screens the reply before returning it.
    """
    import crypto_box
    import llm_client
    from firewall import scan_output

    if req.stream:
        raise HTTPException(status_code=400,
                            detail="Streaming is not supported yet. Send stream=false.")
    if not req.messages:
        raise HTTPException(status_code=400, detail="No messages provided.")

    org = get_org(principal, db)
    user_msg = next((m.content for m in reversed(req.messages) if m.role == "user"), None)
    user_msg = user_msg if user_msg is not None else (req.messages[-1].content or "")
    if len(user_msg) > settings.max_prompt_chars:
        raise HTTPException(status_code=413, detail="Message exceeds maximum length.")

    result = _scan(user_msg, principal, org, request, "proxy")
    if result["malicious"]:
        return _guardrail_error(
            result, f"Security policy violation: prompt blocked by RedTeamGPT ({result['category']}).",
            "prompt_injection_detected")

    if not org.upstream_key_encrypted:
        return JSONResponse(status_code=400, content={"error": {
            "message": "No upstream LLM is configured for this organisation. Add one in "
                       "Settings → Integrations, or use POST /api/check to screen prompts only.",
            "type": "invalid_request_error",
            "code": "upstream_not_configured",
        }})

    try:
        api_key = crypto_box.decrypt(org.upstream_key_encrypted)
    except ValueError as exc:
        raise HTTPException(status_code=502, detail=str(exc))

    payload = req.model_dump(exclude_none=True)
    payload["model"] = req.model or org.upstream_model
    try:
        upstream_status, body = llm_client.forward_chat_completion(
            org.upstream_base_url, api_key, payload)
    except ValueError as exc:  # upstream URL failed the public-address check
        raise HTTPException(status_code=502, detail=str(exc))
    except llm_client.LLMError as exc:
        raise HTTPException(status_code=502, detail=str(exc))

    if upstream_status != 200:
        return JSONResponse(status_code=upstream_status, content=body)

    # Output guardrail: a reply can leak or be harmful even when the prompt was fine.
    reply = ""
    try:
        reply = body["choices"][0]["message"].get("content") or ""
    except (KeyError, IndexError, TypeError, AttributeError):
        pass
    if reply and settings.scan_output:
        out = scan_output(reply)
        if out["malicious"]:
            logger.warning("Proxy reply withheld by the output filter: %s", out["category"])
            return _guardrail_error(out, "The model's reply was withheld by the RedTeamGPT "
                                         "output filter.", "output_withheld")

    body["redteamgpt"] = {"verdict": result["verdict"], "risk_score": result["risk_score"],
                          "latency_ms": result["latency_ms"]}
    return body


# --- Human review ---------------------------------------------------------
class ReviewDecision(BaseModel):
    true_label: int = Field(..., ge=0, le=1,
                            description="0 = benign, 1 = malicious")
    note: str = Field(default="", max_length=1000)


class ReportRequest(BaseModel):
    prompt: str = Field(..., max_length=settings.max_prompt_chars)


@app.get("/api/review/queue", tags=["review"])
def review_queue(
    status: str = Query("pending", pattern="^(pending|reviewed)$"),
    limit: int = Query(50, ge=1, le=200),
    principal: Principal = Depends(get_principal),
):
    """Decisions awaiting human confirmation, or already confirmed."""
    items = (review_store.pending(principal.org_id, limit) if status == "pending"
             else review_store.reviewed(principal.org_id, limit))
    return {"status": status, "count": len(items), "items": items}


@app.post("/api/review/report", tags=["review"])
def report_decision(req: ReportRequest, principal: Principal = Depends(get_principal),
                    db: Session = Depends(get_db)):
    """Let a user dispute a verdict, putting it in front of a reviewer."""
    org = get_org(principal, db)
    result = _detect(req.prompt, org)
    queued = review_store.enqueue(result, "reported", org.id)
    return {
        "status": "queued" if queued else "already_queued",
        "verdict": result["verdict"],
    }


@app.get("/api/review/stats", tags=["review"])
def review_stats(principal: Principal = Depends(get_principal)):
    """How often the firewall is right, measured against human judgement."""
    return review_store.stats(principal.org_id)


# Declared after the literal /api/review/* routes: FastAPI matches in
# declaration order, so a path parameter here would swallow "report".
@app.post("/api/review/{item_id}", tags=["review"])
def submit_review(item_id: int, decision: ReviewDecision,
                  principal: Principal = Depends(require_role("admin"))):
    """Record whether the firewall was right."""
    item = review_store.submit(principal.org_id, item_id, decision.true_label,
                               decision.note, reviewer_id=principal.user_id)
    if item is None:
        raise HTTPException(status_code=404,
                            detail="No pending review with that id.")

    agreed = item["true_label"] == item["predicted_label"]
    logger.info("Review %s: firewall was %s", item_id,
                "correct" if agreed else "wrong")
    return {"status": "recorded", "firewall_was_correct": agreed, "item": item}


# --- Document scanning ----------------------------------------------------
@app.post("/api/scan-document", tags=["security"])
async def scan_document_endpoint(
    request: Request,
    file: UploadFile = File(...),
    principal: Principal = Depends(get_principal),
    db: Session = Depends(get_db),
):
    """Scan an uploaded document for hidden injection instructions.

    Guards against indirect prompt injection: the attacker plants the
    instruction in a file rather than typing it, so the victim uploads an
    ordinary-looking document and the AI reading it obeys the payload.
    """
    from document_scanner import DocumentError, SUPPORTED, scan_document

    suffix = Path(file.filename or "").suffix.lower()
    if suffix not in SUPPORTED:
        raise HTTPException(
            status_code=415,
            detail=f"Unsupported file type. Supported: {', '.join(sorted(SUPPORTED))}",
        )

    data = await file.read(settings.max_upload_bytes + 1)
    if len(data) > settings.max_upload_bytes:
        raise HTTPException(
            status_code=413,
            detail=f"File exceeds {settings.max_upload_bytes // (1024 * 1024)}MB limit.",
        )
    if not data:
        raise HTTPException(status_code=400, detail="File is empty.")

    org = get_org(principal, db)
    try:
        # Model inference is CPU-bound; keep it off the event loop.
        result = await run_in_threadpool(scan_document, file.filename, data, _threshold(org))
    except DocumentError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except Exception:
        logger.exception("Document scan failed")
        raise HTTPException(status_code=503, detail="Could not scan this document.")

    # One audit entry for the document rather than one per passage.
    store.record(
        {
            "prompt": f"[document] {file.filename}",
            "verdict": result["verdict"],
            "malicious": result["malicious"],
            "category": result["category"],
            "risk_score": result["risk_score"],
            "risk_level": (result["priority"] or {}).get("label"),
            "priority": result["priority"],
            "confidence": None,
            "latency_ms": None,
            "timestamp": None,
        },
        org.id, channel="document", api_key_id=principal.api_key_id,
        request_id=request.headers.get("x-request-id"),
    )
    usage.increment(org.id, "scans")
    return result


# --- Conversational assistant --------------------------------------------
class ChatTurn(BaseModel):
    role: str
    content: str


class ChatRequest(BaseModel):
    message: str = Field(..., max_length=settings.max_prompt_chars)
    history: List[ChatTurn] = Field(default_factory=list)


def _refusal_message(result: dict) -> str:
    """Compose a conversational refusal from the firewall's explanation.

    A bare "BLOCKED" teaches the user nothing, so the assistant explains what
    it saw and how to ask legitimately instead.
    """
    e = result["explanation"]
    parts = [
        f"I can't help with that one. {e['what_it_means']}",
        f"**Why this is blocked:** {e['why_risky']}" if e["why_risky"] else "",
    ]
    if e["evidence"]:
        phrases = ", ".join(f'"{ev["phrase"]}"' for ev in e["evidence"][:3])
        parts.append(f"**What triggered it:** {phrases}")
    parts.append(f"**What you can do instead:** {e['recommendation']}")
    return "\n\n".join(p for p in parts if p)


@app.post("/api/chat", tags=["assistant"])
def chat(req: ChatRequest, request: Request,
         principal: Principal = Depends(require_session), db: Session = Depends(get_db)):
    """Answer a user message, refusing with an explanation when unsafe.

    Dashboard only: it answers with the platform's LLM key, so each
    organisation has a daily message allowance.
    """
    import llm_client

    if not req.message.strip():
        raise HTTPException(status_code=400, detail="Message is empty.")

    org = get_org(principal, db)
    guardrail = _scan(req.message, principal, org, request, "chat")

    if guardrail["malicious"]:
        return {
            "blocked": True,
            "reply": _refusal_message(guardrail),
            "guardrail": guardrail,
            "provider": llm_client.provider_name(),
        }

    if not llm_client.is_configured():
        return {
            "blocked": False,
            "reply": "Your message passed the security check, but answering is not "
                     "available on this deployment. The firewall works either way.",
            "guardrail": guardrail,
            "provider": "none",
            "llm_unavailable": True,
        }

    used = usage.get_today(org.id)["chat_messages"]
    if used >= org.chat_daily_cap:
        return {
            "blocked": False,
            "reply": f"Your message passed the security check, but your organisation has "
                     f"used today's {org.chat_daily_cap} assistant answers. The allowance "
                     "resets at midnight UTC; scanning is unaffected.",
            "guardrail": guardrail,
            "provider": llm_client.provider_name(),
            "limit_reached": True,
        }

    try:
        answer = llm_client.generate(
            req.message, [t.model_dump() for t in req.history]
        )
    except llm_client.LLMError as exc:
        logger.warning("LLM generation failed: %s", exc)
        return {
            "blocked": False,
            "reply": "Your message passed the security check, but the language "
                     "model could not be reached. Please try again.",
            "guardrail": guardrail,
            "provider": llm_client.provider_name(),
        }
    usage.increment(org.id, "chat_messages")

    # Output guardrail: a reply can leak or be harmful even when the prompt
    # looked fine. Uses signature matching only - see firewall.scan_output.
    output_check = None
    if settings.scan_output:
        from firewall import scan_output

        output_check = scan_output(answer)
        if output_check["malicious"]:
            logger.warning("Model output withheld: %s", output_check["category"])
            return {
                "blocked": True,
                "blocked_stage": "output",
                "reply": "I generated a response, but it was withheld by the "
                         "output filter. Please rephrase your question.",
                "guardrail": guardrail,
                "output_guardrail": output_check,
                "provider": llm_client.provider_name(),
            }

    return {
        "blocked": False,
        "reply": answer,
        "guardrail": guardrail,
        "output_guardrail": output_check,
        "provider": llm_client.provider_name(),
    }


@app.get("/api/chat/status", tags=["assistant"])
def chat_status():
    """Lets the UI show whether answering is available before the first message."""
    import llm_client

    return {
        "configured": llm_client.is_configured(),
        "provider": llm_client.provider_name(),
        "model": settings.llm_model if llm_client.is_configured() else None,
        "output_scanning": settings.scan_output,
    }


# --- Telemetry ------------------------------------------------------------
@app.get("/api/logs", tags=["telemetry"])
def get_logs(
    limit: int = Query(50, ge=1, le=200),
    verdict: Optional[str] = Query(None, description="BLOCKED or ALLOWED"),
    priority: Optional[str] = Query(None, description="P1, P2, P3 or P4"),
    search: Optional[str] = Query(None, max_length=200),
    principal: Principal = Depends(get_principal),
):
    logs = store.query(principal.org_id, limit=limit, verdict=verdict,
                       priority=priority, search=search)
    return {"returned_count": len(logs), "logs": logs}


@app.post("/api/logs/clear", tags=["telemetry"])
def clear_logs(principal: Principal = Depends(require_role("admin"))):
    return {"status": "success", "cleared_count": store.clear(principal.org_id)}


@app.get("/api/logs/export", tags=["telemetry"])
def export_logs(principal: Principal = Depends(require_session)):
    return JSONResponse(
        content=store.query(principal.org_id, limit=10_000),
        headers={"Content-Disposition": "attachment; filename=redteamgpt_audit.json"},
    )


def _load_model_metrics() -> dict:
    """Read evaluation results produced by src/evaluate.py.

    These were previously hardcoded in this file and had drifted from the real
    numbers, so the dashboard reported figures no run had ever produced.
    """
    if METRICS_FILE.exists():
        try:
            return json.loads(METRICS_FILE.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            logger.warning("Could not parse %s", METRICS_FILE)
    return {
        "status": "NOT_EVALUATED",
        "note": "Run `python src/evaluate.py` to generate reproducible metrics.",
    }


@app.get("/api/metrics", tags=["telemetry"])
def api_metrics(principal: Principal = Depends(get_principal)):
    from firewall import MODEL_INFO

    return {
        "telemetry": store.aggregate(principal.org_id),
        "model_info": _load_model_metrics(),
        "model": MODEL_INFO,
        "uptime_seconds": round(time.time() - START_TIME, 1),
        "version": settings.version,
    }


# --- Operational endpoints ------------------------------------------------
@app.get("/health", tags=["ops"])
def health():
    """Liveness: the process is up. Never touches dependencies."""
    return {
        "status": "healthy",
        "service": "RedTeamGPT Firewall Engine",
        "version": settings.version,
        "uptime_seconds": round(time.time() - START_TIME, 1),
    }


@app.get("/ready", tags=["ops"])
def ready():
    """Readiness: only true when the model and database can actually serve."""
    model_ok = MODEL_READY._value.get() == 1
    db_ok = store.healthy()
    body = {"model": "loaded" if model_ok else "unavailable",
            "database": "connected" if db_ok else "unavailable"}
    if model_ok:
        from firewall import MODEL_INFO
        body["model_info"] = MODEL_INFO
    if model_ok and db_ok:
        return {"status": "ready", **body}
    return JSONResponse(status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                        content={"status": "not_ready", **body})


@app.get("/metrics", include_in_schema=False)
def prometheus_metrics(request: Request):
    if not settings.enable_metrics:
        raise HTTPException(status_code=404, detail="Not found")
    if settings.metrics_token:
        import hmac
        sent = request.headers.get("authorization", "").removeprefix("Bearer ").strip()
        if not hmac.compare_digest(sent, settings.metrics_token):
            raise HTTPException(status_code=404, detail="Not found")
    elif settings.is_production:
        raise HTTPException(status_code=404, detail="Not found")
    return PlainTextResponse(generate_latest(), media_type=CONTENT_TYPE_LATEST)


# --- Static frontend ------------------------------------------------------
if (DIST_DIR / "assets").exists():
    app.mount("/assets", StaticFiles(directory=str(DIST_DIR / "assets")), name="assets")

RESERVED_PREFIXES = ("api/", "v1/", "health", "ready", "metrics", "docs", "openapi.json")


@app.get("/", include_in_schema=False)
def home():
    index = DIST_DIR / "index.html"
    return FileResponse(index if index.exists() else FRONTEND / "index.html")


@app.get("/{catchall:path}", include_in_schema=False)
def spa_catchall(catchall: str):
    if catchall.startswith(RESERVED_PREFIXES):
        raise HTTPException(status_code=404, detail="Not found")

    candidate = (DIST_DIR / catchall).resolve()
    # Containment check: a crafted path must not escape the build directory.
    if DIST_DIR.exists() and candidate.is_file() \
            and candidate.is_relative_to(DIST_DIR.resolve()):
        return FileResponse(candidate)

    index = DIST_DIR / "index.html"
    return FileResponse(index if index.exists() else FRONTEND / "index.html")
