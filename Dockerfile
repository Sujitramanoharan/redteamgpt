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
    ENVIRONMENT=production

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

# CPU-only torch is ~750MB smaller than the default CUDA build and this runs on CPU.
COPY requirements.txt .
RUN pip install --extra-index-url https://download.pytorch.org/whl/cpu -r requirements.txt

COPY backend ./backend
COPY src ./src
COPY frontend/index.html ./frontend/
COPY --from=frontend-builder /build/dist ./frontend/dist
# models/ is gitignored; COPY only succeeds when weights are present locally.
# Without them the app falls back to MODEL_HUB_ID at startup.
COPY model[s] ./models
COPY result[s] ./results

# Spaces runs as uid 1000 and needs these paths writable.
RUN useradd -m -u 1000 appuser \
    && mkdir -p /app/data /app/.cache/huggingface \
    && chown -R appuser:appuser /app
USER appuser

EXPOSE 7860

HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
    CMD curl -fsS http://localhost:7860/health || exit 1

# One worker: each worker loads its own copy of the model, and the free tier
# cannot afford two. Scale with replicas behind a load balancer instead.
CMD ["sh", "-c", "uvicorn backend.main:app --host 0.0.0.0 --port ${PORT:-7860} --workers 1"]
