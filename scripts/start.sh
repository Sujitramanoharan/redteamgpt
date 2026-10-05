#!/bin/sh
# Container entrypoint: migrate, then serve.
#
# Migrations run here, once, before any worker starts - never from inside the
# app, where several workers would race to apply the same migration.
set -e

alembic upgrade head

# --proxy-headers: Render terminates TLS at its load balancer, so without this
# every request would appear to come from the proxy and per-IP limits on
# sign-in would throttle all users together.
exec uvicorn backend.main:app \
    --host 0.0.0.0 \
    --port "${PORT:-7860}" \
    --workers "${WEB_CONCURRENCY:-1}" \
    --proxy-headers \
    --forwarded-allow-ips="${FORWARDED_ALLOW_IPS:-*}"
