# syntax=docker/dockerfile:1.7
# ─────────────────────────────────────────────────────────────────────────
# PII Detection API — multi-stage build (Phase 8, T8.6).
#
# Stage 1: builder
#   * Installs build-essential + libpq for native wheels.
#   * Resolves dependencies via uv sync (uv.lock pinned).
#   * Downloads the Korean spaCy model (ko_core_news_lg, ~600 MB).
#
# Stage 2: runtime
#   * Slim Python image, only libpq5 needed for asyncpg/psycopg.
#   * Non-root user (uid=1000).
#   * Copies the prebuilt .venv from the builder stage.
#   * HEALTHCHECK probes /readyz so the orchestrator drains traffic
#     when the DB or Redis is unreachable.
#
# Single-worker uvicorn — asyncio handles concurrency, and the in-memory
# analyzer + policy caches cannot be shared across worker processes.
# Horizontal scaling is via more replicas, not more workers per replica.
# ─────────────────────────────────────────────────────────────────────────

FROM python:3.12-slim AS builder

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    UV_LINK_MODE=copy

# Build deps for wheels that compile from source (psycopg2, lxml, etc.).
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        libpq-dev \
        curl \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install uv into a stable path. We use the standalone installer because
# the python:3.12-slim base does not ship `pipx`.
RUN curl -LsSf https://astral.sh/uv/install.sh | sh \
    && cp /root/.local/bin/uv /usr/local/bin/uv

WORKDIR /app

# Copy lockfile first so changing app code doesn't bust the dep cache.
COPY pyproject.toml uv.lock README.md ./
COPY app ./app

# Resolve & install runtime deps only (no [dev]). --frozen ensures uv.lock
# is honoured byte-for-byte.
RUN uv sync --frozen --no-dev

# spaCy Korean model. Pinned via the registry redirect; this is ~600 MB
# and bumps the final image significantly. See PII_API_Development_Requirements
# §5.1.5 — the analyzer must run with ko_core_news_lg in production.
RUN /app/.venv/bin/python -m spacy download ko_core_news_lg

# ─────────────────────────────────────────────────────────────────────────
FROM python:3.12-slim AS runtime

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/app/.venv/bin:${PATH}"

# Runtime native deps — libpq5 for asyncpg/psycopg, curl for HEALTHCHECK.
RUN apt-get update && apt-get install -y --no-install-recommends \
        libpq5 \
        curl \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -m -u 1000 -s /bin/bash appuser

WORKDIR /app

# Pull the prebuilt venv (with spaCy model already extracted into it).
COPY --from=builder --chown=appuser:appuser /app/.venv /app/.venv

# Application source.
COPY --chown=appuser:appuser app /app/app
COPY --chown=appuser:appuser docs /app/docs
COPY --chown=appuser:appuser pyproject.toml alembic.ini /app/

USER appuser
EXPOSE 8000

# Liveness via curl on /readyz; the readiness check itself fans out to
# DB + Redis with a 1.5 s budget so the HEALTHCHECK timeout (3 s) gives
# headroom.
HEALTHCHECK --interval=10s --timeout=3s --start-period=20s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8000/readyz || exit 1

# Single uvicorn worker (asyncio handles concurrency; the analyzer cache
# is in-process and would not survive across worker boundaries).
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
