"""RedTeamGPT - production AI guardrail and prompt-injection firewall."""
import json
import logging
import sys
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import List, Optional

_HERE = Path(__file__).parent
# Both dirs must be importable: sibling modules live in backend/, the engine in src/.
for _p in (str(_HERE), str(_HERE.parent / "src")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from fastapi import Depends, FastAPI, HTTPException, Query, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from pydantic import BaseModel, Field, field_validator

from config import settings
from observability import (
    MODEL_READY,
    RequestContextMiddleware,
    configure_logging,
    record_scan,
)
from security import (
    RateLimitMiddleware,
    SecurityHeadersMiddleware,
    limiter,
    require_api_key,
)
from storage import store

configure_logging()
logger = logging.getLogger("redteamgpt")

ROOT = Path(__file__).parent.parent
FRONTEND = ROOT / "frontend"
DIST_DIR = FRONTEND / "dist"
METRICS_FILE = ROOT / "results" / "metrics.json"
START_TIME = time.time()


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting %s v%s (env=%s)", settings.app_name, settings.version,
                settings.environment)
    # Import here so a model failure surfaces as a clean startup error.
    from firewall import MODEL_SOURCE, detect

    detect("warmup")  # pay the first-inference cost before serving traffic
    MODEL_READY.set(1)
    logger.info("Detector ready (source=%s)", MODEL_SOURCE)

    if settings.audit_retention_days > 0:
        removed = store.prune(settings.audit_retention_days)
        if removed:
            logger.info("Pruned %d audit records older than %d days",
                        removed, settings.audit_retention_days)
    if not settings.auth_enforced:
        logger.warning("API key auth is DISABLED - set REQUIRE_AUTH=true and "
                       "API_KEYS before exposing this publicly")
    yield
    MODEL_READY.set(0)
    store.close()
    logger.info("Shutdown complete")


app = FastAPI(
    title=settings.app_name,
    description="Enterprise AI guardrail and real-time prompt-injection firewall.",
    version=settings.version,
    lifespan=lifespan,
    docs_url=None if settings.is_production else "/docs",
    redoc_url=None,
)

# Order matters: the outermost middleware is added last.
app.add_middleware(GZipMiddleware, minimum_size=1000)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RateLimitMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials="*" not in settings.cors_origins,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "X-API-Key", "X-Request-ID"],
)
app.add_middleware(RequestContextMiddleware)


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
    role: str
    content: str


class OpenAIChatCompletionRequest(BaseModel):
    model: Optional[str] = "gpt-4"
    messages: List[ChatMessage]
    temperature: Optional[float] = 0.7


def _scan(prompt: str, client_id: str, request: Request) -> dict:
    """Run the firewall and persist the outcome."""
    from firewall import detect

    result = detect(prompt)
    record_scan(result)
    store.record(result, client_id=client_id,
                 request_id=request.headers.get("x-request-id"))
    return result


# --- Security API ---------------------------------------------------------
@app.post("/api/check", tags=["security"])
def check(req: PromptRequest, request: Request,
          client_id: str = Depends(require_api_key)):
    """Analyse a single prompt for injection, jailbreak and policy violations."""
    return _scan(req.prompt, client_id, request)


@app.post("/api/check-batch", tags=["security"])
def check_batch(req: BatchPromptRequest, request: Request,
                client_id: str = Depends(require_api_key)):
    """Analyse up to the configured batch limit in one call."""
    if not req.prompts:
        return {"total": 0, "blocked_count": 0, "allowed_count": 0, "results": []}

    results = [_scan(p, client_id, request) for p in req.prompts]
    blocked = sum(1 for r in results if r["malicious"])
    return {
        "total": len(results),
        "blocked_count": blocked,
        "allowed_count": len(results) - blocked,
        "results": results,
    }


@app.post("/api/evasion-test", tags=["security"])
def evasion_test(req: PromptRequest, client_id: str = Depends(require_api_key)):
    """Run adversarial transformations to measure guardrail resiliency."""
    from firewall import run_evasion_test

    return run_evasion_test(req.prompt)


# --- OpenAI-compatible guardrail proxy ------------------------------------
@app.post("/v1/chat/completions", tags=["proxy"])
def openai_proxy(req: OpenAIChatCompletionRequest, request: Request,
                 client_id: str = Depends(require_api_key)):
    """Drop-in replacement for the OpenAI chat endpoint that screens the prompt first."""
    if not req.messages:
        raise HTTPException(status_code=400, detail="No messages provided.")

    user_msg = next((m.content for m in reversed(req.messages) if m.role == "user"), "")
    if not user_msg:
        user_msg = req.messages[-1].content
    if len(user_msg) > settings.max_prompt_chars:
        raise HTTPException(status_code=413, detail="Message exceeds maximum length.")

    result = _scan(user_msg, client_id, request)

    if result["malicious"]:
        return JSONResponse(
            status_code=400,
            content={"error": {
                "message": "Security policy violation: prompt blocked by RedTeamGPT "
                           f"({result['category']}).",
                "type": "guardrail_violation",
                "param": "messages",
                "code": "prompt_injection_detected",
                "risk_score": result["risk_score"],
                "threat_category": result["category"],
                "priority": result["priority"]["level"],
                "priority_label": result["priority"]["label"],
                "explanation": result["explanation"],
            }},
        )

    return {
        "id": f"chatcmpl-redteamgpt-{int(time.time())}",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": req.model,
        "choices": [{
            "index": 0,
            "message": {
                "role": "assistant",
                "content": "RedTeamGPT guardrail approved this prompt. "
                           f"(Risk {result['risk_score']}/100, "
                           f"{result['latency_ms']}ms)",
            },
            "finish_reason": "stop",
        }],
        "usage": {
            "prompt_tokens": len(user_msg.split()),
            "completion_tokens": 20,
            "total_tokens": len(user_msg.split()) + 20,
        },
        "guardrail_telemetry": result,
    }


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
         client_id: str = Depends(require_api_key)):
    """Answer a user message, refusing with an explanation when unsafe.

    This is the end-user surface: the firewall runs first, and only safe
    prompts reach the language model.
    """
    import llm_client

    if not req.message.strip():
        raise HTTPException(status_code=400, detail="Message is empty.")

    guardrail = _scan(req.message, client_id, request)

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
            "reply": (
                "Your message passed the security check, but no language model is "
                "connected yet, so I can't answer it.\n\n"
                "Set `LLM_PROVIDER` and `LLM_API_KEY` in your `.env` to enable "
                "answers. The firewall works either way."
            ),
            "guardrail": guardrail,
            "provider": "none",
            "llm_unavailable": True,
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
            "llm_error": str(exc)[:200],
        }

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
    client_id: str = Depends(require_api_key),
):
    logs = store.query(limit=limit, verdict=verdict, priority=priority, search=search)
    return {"returned_count": len(logs), "logs": logs}


@app.post("/api/logs/clear", tags=["telemetry"])
def clear_logs(client_id: str = Depends(require_api_key)):
    return {"status": "success", "cleared_count": store.clear()}


@app.get("/api/logs/export", tags=["telemetry"])
def export_logs(client_id: str = Depends(require_api_key)):
    return JSONResponse(
        content=store.query(limit=10_000),
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
def api_metrics(client_id: str = Depends(require_api_key)):
    return {
        "telemetry": store.aggregate(),
        "model_info": _load_model_metrics(),
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
    if model_ok and db_ok:
        return {"status": "ready", "model": "loaded", "database": "connected"}
    return JSONResponse(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        content={
            "status": "not_ready",
            "model": "loaded" if model_ok else "unavailable",
            "database": "connected" if db_ok else "unavailable",
        },
    )


@app.get("/metrics", include_in_schema=False)
def prometheus_metrics():
    if not settings.enable_metrics:
        raise HTTPException(status_code=404, detail="Metrics disabled")
    limiter.sweep()
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
