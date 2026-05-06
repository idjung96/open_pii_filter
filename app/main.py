"""FastAPI application entrypoint."""

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from app.api.detect import router as detect_router
from app.api.health import router as health_router
from app.api.jobs import router as jobs_router
from app.api.metrics import router as metrics_router
from app.api.responses import build_response
from app.config import get_settings
from app.core.codes import get_code

logger = logging.getLogger(__name__)


@contextlib.asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    """Start the nonce vacuum, Phase 4 job cleanup (Q4), Phase 6 audit cleanup,
    and Phase 7 feedback alerter. Also installs the PII log scrubber.

    Phase 9D — masked-artifact cleanup loop 제거 (마스킹 인프라 폐기).
    Phase 9E — pattern_listener 제거 (pii_patterns 테이블 폐기).
    """
    from app.core.api_ip_caller_cache import reload_api_ip_callers
    from app.core.blocklist_cache import reload_blocklist
    from app.core.exception_ip_cache import reload_exception_ips
    from app.db.session import get_sessionmaker
    from app.security.log_filter import install_pii_log_filter
    from app.workers.audit_cleanup import audit_cleanup_loop
    from app.workers.feedback_alerter import feedback_alerter_loop
    from app.workers.job_cleanup import job_cleanup_loop
    from app.workers.nonce_vacuum import nonce_vacuum_loop

    # Install before any worker starts so even their startup logs are
    # scrubbed (the filter is idempotent — safe across reloads).
    install_pii_log_filter()

    # Phase 9A — preload exception-IP and API-IP-caller caches. Failures
    # are swallowed by the helpers themselves so the API still boots
    # when the database is unavailable.
    try:
        async with get_sessionmaker()() as bootstrap_session:
            await reload_exception_ips(bootstrap_session)
            await reload_api_ip_callers(bootstrap_session)
            # Phase 4b — load attachment-format deny list before the
            # detect endpoint sees its first request.
            await reload_blocklist(bootstrap_session)
    except Exception as e:
        logger.warning("phase 9A cache preload failed: %s", e)

    tasks: list[asyncio.Task[None]] = []
    if get_settings().app_env != "test":
        tasks.append(asyncio.create_task(nonce_vacuum_loop(), name="pii-nonce-vacuum"))
        tasks.append(asyncio.create_task(job_cleanup_loop(), name="pii-job-cleanup"))
        tasks.append(asyncio.create_task(audit_cleanup_loop(), name="pii-audit-cleanup"))
        tasks.append(asyncio.create_task(feedback_alerter_loop(), name="pii-feedback-alerter"))
        logger.info("started %d background tasks", len(tasks))

    try:
        yield
    finally:
        for t in tasks:
            t.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await t


app = FastAPI(
    title="PII Detection & Masking API",
    version="0.1.0",
    description="기관 대표홈페이지 게시판용 개인정보 탐지·마스킹 API",
    lifespan=lifespan,
)

# Phase 3 — body size cap (T3.9). Registered before the router so the
# 413 response is emitted before any auth or analyzer cost.
from app.security.audit_middleware import AuditMiddleware  # noqa: E402
from app.security.auth import EnvelopeHTTPException  # noqa: E402
from app.security.body_size import BodySizeLimitMiddleware  # noqa: E402

app.add_middleware(
    BodySizeLimitMiddleware,
    max_bytes=get_settings().max_request_body_bytes,
)

# Phase 6 — append-only request audit. Registered AFTER BodySizeLimit so
# rejected oversize bodies are NOT recorded (no benefit, just noise).
app.add_middleware(AuditMiddleware)


@app.exception_handler(EnvelopeHTTPException)
async def _envelope_handler(_request: Request, exc: EnvelopeHTTPException) -> JSONResponse:
    """Q3 — return the envelope at top level (no `{"detail": ...}` wrap)."""
    return JSONResponse(
        status_code=exc.status_code,
        content=exc.detail,
        headers=exc.headers or None,
    )


app.include_router(detect_router)
app.include_router(jobs_router)

# Phase 8 — health probes (k8s-style, no auth) and Prometheus exposition.
# /healthz lives below as a separate inline route for back-compat with
# tests that import it from app.main; the new /readyz + /v1/readyz come
# from the dedicated router.
app.include_router(health_router)
# Metrics router is mounted unconditionally; the require_admin gate
# rejects every request when admin_ip_allowlist is empty (defence in
# depth — the surface returns 403, not 404, when an operator forgets to
# configure the allowlist; admin gate is enforced via a noisy denial
# rather than silent unmapped routes).
app.include_router(metrics_router)

# 개발 환경 전용: /metrics (no auth). APP_ENV=development 일 때만 마운트.
from app.api.metrics import get_dev_router as _get_dev_metrics_router  # noqa: E402

_dev_metrics = _get_dev_metrics_router()
if _dev_metrics is not None:
    app.include_router(_dev_metrics)

# Phase 7 — public privacy notice (operator-decision D); no auth.
from app.api.feedback import router as feedback_router  # noqa: E402
from app.api.legal import router as legal_router  # noqa: E402

app.include_router(legal_router)
app.include_router(feedback_router)

# Phase 9A — Jinja2 admin dashboard at /admin. The router enforces its
# own IP allowlist + session cookies; unrelated to the HMAC-protected
# /v1/admin/* endpoints.
from app.api.dashboard import (  # noqa: E402
    DashboardAuthError,
    dashboard_auth_exception_handler,
)
from app.api.dashboard import router as dashboard_router  # noqa: E402

app.include_router(dashboard_router)
app.add_exception_handler(DashboardAuthError, dashboard_auth_exception_handler)

# Phase 6 — admin audit-query router only mounts when the operator has
# explicitly configured an admin IP allowlist. Empty allowlist =
# external surface returns 404, hiding the endpoint from scanners.
# Phase 7 — admin stats router uses the same gate.
if get_settings().admin_ip_allowlist.strip():
    from app.api.admin_audit import router as admin_audit_router
    from app.api.admin_blocklist import router as admin_blocklist_router
    from app.api.admin_stats import router as admin_stats_router

    app.include_router(admin_audit_router)
    app.include_router(admin_stats_router)
    # Phase 4b — runtime CRUD for the attachment deny list.
    app.include_router(admin_blocklist_router)


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    """Liveness probe."""
    return {"status": "ok"}


@app.get("/v1/healthz")
async def v1_healthz() -> dict[str, str]:
    """Versioned liveness probe — reports current environment label."""
    settings = get_settings()
    return {"status": "ok", "env": settings.app_env}


# ── Request validation → REQ-4xxx envelope ────────────────────────────────
def _classify_validation(
    errors: list[dict[str, Any]],
) -> tuple[str, dict[str, object]]:
    """Pick the most specific REQ-* code for a pydantic validation failure."""
    error_types = {str(e.get("type", "")) for e in errors}
    locs = [list(e.get("loc", ())) for e in errors]

    if any("uuid" in t for t in error_types):
        return "REQ-4004", {}
    if any("json" in t for t in error_types):
        return "REQ-4003", {"detail": str(errors[0].get("msg", "invalid JSON"))}

    missing = [
        ".".join(str(p) for p in loc[1:] if p != "body")
        for loc, e in zip(locs, errors, strict=False)
        if "missing" in str(e.get("type", ""))
    ]
    if missing:
        return "REQ-4001", {"fields": ", ".join(missing)}

    # Author-specific shape errors
    if any(len(loc) >= 2 and loc[1] == "author" for loc in locs):
        bad = next((loc for loc in locs if len(loc) >= 3 and loc[1] == "author"), None)
        field = bad[2] if bad is not None and len(bad) >= 3 else "?"
        return "REQ-4002", {"field": str(field)}

    return "REQ-4003", {"detail": str(errors[0].get("msg", "validation error"))}


@app.exception_handler(RequestValidationError)
async def _validation_handler(
    request: Request,  # noqa: ARG001 — FastAPI signature
    exc: RequestValidationError,
) -> JSONResponse:
    code, vars_ = _classify_validation(list(exc.errors()))
    rc = get_code(code)

    request_id = _safe_request_id(exc)
    resp = build_response(
        request_id=request_id,
        code=code,
        processing_ms=0,
        template_vars=vars_,
    )
    payload = resp.model_dump(mode="json")
    payload["processed_at"] = datetime.now(tz=UTC).isoformat()
    return JSONResponse(status_code=rc.http_status, content=payload)


def _safe_request_id(exc: RequestValidationError) -> UUID:
    """Best-effort extraction of request_id from the offending payload."""
    body = exc.body if isinstance(exc.body, dict) else None
    if body is not None:
        raw = body.get("request_id")
        if isinstance(raw, str):
            try:
                return UUID(raw)
            except ValueError:
                return uuid4()
    return uuid4()
