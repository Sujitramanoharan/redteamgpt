# RedTeamGPT production image.
# Multi-stage: the frontend is built with Node, then served by FastAPI as static
# files, so the whole app ships as one container on one port.

# ---------- Stage 1: frontend ----------
FROM node:20-slim AS frontend-builder
WORKDIR /build
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

# ---------- Stage 2: runtime ----------
FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PORT=7860 \
    HF_HOME=/app/.cache/huggingface \
    ENVIRONMENT=production \
    AUTO_MIGRATE=false \
    INFERENCE_BACKEND=onnx

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

# Serving needs no torch: the model runs on ONNX Runtime (src/export_onnx.py
# proves verdict parity before a model is published). Installing the full
# requirements.txt here used to pull torch from PyPI together with several GB
# of CUDA libraries, despite the CPU index.
COPY requirements-runtime.txt .
RUN pip install -r requirements-runtime.txt

COPY backend ./backend
COPY src ./src
COPY alembic ./alembic
COPY alembic.ini ./
COPY scripts/start.sh ./start.sh
COPY frontend/index.html ./frontend/
COPY --from=frontend-builder /build/dist ./frontend/dist
# Model weights are not baked in: the app downloads MODEL_HUB_ID at the pinned
# MODEL_HUB_REVISION on startup, so a model change never needs an image rebuild.
COPY result[s] ./results

RUN useradd -m -u 1000 appuser \
    && mkdir -p /app/data /app/.cache/huggingface \
    && chmod +x /app/start.sh \
    && chown -R appuser:appuser /app
USER appuser

EXPOSE 7860

# Readiness, not liveness: the model must be loaded and the database reachable.
HEALTHCHECK --interval=30s --timeout=5s --start-period=120s --retries=3 \
    CMD curl -fsS "http://localhost:${PORT}/ready" || exit 1

# One worker by default: each worker loads its own copy of the model. Scale
# with WEB_CONCURRENCY on a bigger instance, or with more instances plus
# REDIS_URL so rate limits are shared.
CMD ["/app/start.sh"]
