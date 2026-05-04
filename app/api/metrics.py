"""GET /v1/admin/metrics — Prometheus exposition endpoint (Phase 8, T8.4).

Trust-zone separation
---------------------
Re-uses :func:`app.api.admin_audit.require_admin` so the same gate that
protects ``/v1/admin/audit-events`` also protects metrics:

1. ``require_auth`` — HMAC + API key + per-key rate limit
2. caller's API key has ``is_admin == True``
3. caller's source IP matches a CIDR in ``Settings.admin_ip_allowlist``

The router is mounted unconditionally (so metrics survives without
``admin_ip_allowlist`` being set, e.g. for k8s-only clusters where
network policy provides isolation), but the gate ALWAYS rejects when
``admin_ip_allowlist`` is empty — defence in depth.

Response format
---------------
``text/plain; version=0.0.4`` Prometheus exposition. The ``CONTENT_TYPE_LATEST``
constant is the canonical content-type recommended by the Prometheus
project.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Response
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

from app.api.admin_audit import require_admin
from app.config import get_settings
from app.security.hmac_auth import AuthedCaller

router = APIRouter(prefix="/v1/admin", tags=["admin-metrics"])


@router.get("/metrics")
async def metrics(
    _caller: AuthedCaller = Depends(require_admin),  # noqa: B008
) -> Response:
    """Render the default registry as Prometheus exposition text (production, auth required)."""
    payload = generate_latest()
    return Response(content=payload, media_type=CONTENT_TYPE_LATEST)


# ── 개발 전용 인증 없는 메트릭 엔드포인트 ────────────────────────────────────
# APP_ENV=development 일 때만 /metrics 에서 인증 없이 접근 가능.
# 운영 환경에서는 이 라우트가 등록되지 않는다.
dev_router = APIRouter(tags=["dev-metrics"])


@dev_router.get("/metrics")
async def metrics_dev() -> Response:
    """No-auth Prometheus metrics (development only, APP_ENV=development)."""
    payload = generate_latest()
    return Response(content=payload, media_type=CONTENT_TYPE_LATEST)


def get_dev_router() -> APIRouter | None:
    """Return dev_router only when running in development mode."""
    if get_settings().app_env == "development":
        return dev_router
    return None
