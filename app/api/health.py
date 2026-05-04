"""Health endpoints (Phase 8, T8.7).

Two probes following the k8s convention:

* ``GET /healthz`` — liveness. Always returns 200 if the process is up.
  No I/O, no auth, no DB / Redis ping. Used by Docker HEALTHCHECK and
  k8s livenessProbe.

* ``GET /readyz`` — readiness. Pings DB and Redis; returns 503 if either
  is unreachable. Used by k8s readinessProbe / load balancer to drain
  traffic from a partially-degraded pod.

Both endpoints are mounted unconditionally and require no auth — that's
the standard k8s pattern; production deployments should restrict access
via the cluster network policy or front-end nginx.

The legacy ``/healthz`` already lived in ``app/main.py``; this module
keeps the existing route shape but adds ``/readyz`` and a versioned
``/v1/readyz``.
"""

from __future__ import annotations

import asyncio
import logging

from fastapi import APIRouter
from fastapi.responses import JSONResponse
from sqlalchemy import text

from app.config import get_settings
from app.db.session import get_sessionmaker
from app.security.rate_limit import get_redis

logger = logging.getLogger(__name__)

router = APIRouter(tags=["health"])

# Hard cap so a hung dependency can't make the readiness probe itself
# exceed the k8s probe timeout (default 1s).
_PROBE_TIMEOUT_SECONDS = 1.5


@router.get("/readyz")
async def readyz() -> JSONResponse:
    """Readiness probe — DB + Redis must respond.

    Returns 200 with ``{"status":"ok",...}`` when both dependencies
    answer within the probe timeout, 503 with the failing component
    flagged otherwise. We never raise — the response itself encodes the
    failure so the load balancer sees a clean 503.
    """
    settings = get_settings()
    db_ok, db_err = await _check_db()
    redis_ok, redis_err = await _check_redis()

    payload: dict[str, object] = {
        "status": "ok" if (db_ok and redis_ok) else "degraded",
        "env": settings.app_env,
        "checks": {
            "database": {"ok": db_ok, "error": db_err},
            "redis": {"ok": redis_ok, "error": redis_err},
        },
    }
    status_code = 200 if (db_ok and redis_ok) else 503
    return JSONResponse(status_code=status_code, content=payload)


@router.get("/v1/readyz")
async def v1_readyz() -> JSONResponse:
    """Versioned readiness probe — identical body, kept for API parity."""
    return await readyz()


# ── Internal helpers ──────────────────────────────────────────────────────
async def _check_db() -> tuple[bool, str | None]:
    """``SELECT 1`` against the async engine; return (ok, error_message)."""
    try:
        async with asyncio.timeout(_PROBE_TIMEOUT_SECONDS):
            sm = get_sessionmaker()
            async with sm() as session:
                await session.execute(text("SELECT 1"))
        return True, None
    except Exception as e:  # surface any failure as 503
        msg = f"{type(e).__name__}: {e}"
        logger.debug("readyz: db check failed: %s", msg)
        return False, msg


async def _check_redis() -> tuple[bool, str | None]:
    """Redis ``PING``; return (ok, error_message)."""
    try:
        async with asyncio.timeout(_PROBE_TIMEOUT_SECONDS):
            client = get_redis()
            # `redis.asyncio.Redis.ping` returns an awaitable in async mode;
            # the union annotation in `redis-py` is overbroad.
            pong = await client.ping()  # type: ignore[misc]
        if not pong:
            return False, "redis ping returned falsy value"
        return True, None
    except Exception as e:
        msg = f"{type(e).__name__}: {e}"
        logger.debug("readyz: redis check failed: %s", msg)
        return False, msg
