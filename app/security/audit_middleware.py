"""Starlette middleware that records one ``audit_events`` row per request
(Phase 6, T6.4).

Design
------
The middleware runs *outside* of FastAPI's auth dependency, but the
endpoint handler can stash detection metadata on ``request.state`` after
running auth + analyzer. We then read that state to populate the audit
row.

We deliberately do **not** parse the response body — the streaming
JSONResponse may have been built lazily, and digging into a Pydantic
envelope from the middleware layer is fragile. Instead the detect
endpoint sets ``request.state.audit_payload`` with the response code,
detection count, and detection types.

If the endpoint never sets the field (validation error, 404, etc.) we
still record an audit row with whatever info we have. The PII-aware
fields stay zero/None in that case.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

from app.core import system_settings
from app.db.session import get_sessionmaker
from app.security.audit import record_request
from app.security.metrics_collector import observe_http

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)


@dataclass
class AuditPayload:
    """Endpoint-supplied metadata for the audit row.

    The detect endpoint sets ``request.state.audit_payload = AuditPayload(...)``
    after auth + analyzer have run. Middleware reads it post-response.

    Phase 7 — ``shadow_hit_types`` carries entity_types that fired only
    in the shadow analyzer (no verdict impact, audit-only).
    """

    response_code: str | None = None
    detected_entity_count: int = 0
    detected_entity_types: str | None = None
    shadow_hit_types: str | None = None


_BODY_LIMIT = 16 * 1024  # 16 KiB
_MASKED_HEADERS: frozenset[str] = frozenset(
    {"authorization", "cookie", "x-signature", "x-api-key", "x-nonce"}
)


def _capture_body(raw: bytes) -> str | None:
    """Decode raw bytes to a display string, truncating at 16 KiB."""
    if not raw:
        return None
    total = len(raw)
    chunk = raw[:_BODY_LIMIT]
    try:
        text = chunk.decode("utf-8")
    except Exception:
        return f"<binary {total}B>"
    if total > _BODY_LIMIT:
        text += f"\n... [TRUNCATED, total {total}B]"
    return text


def _capture_headers(request: Request) -> str | None:
    """Serialise request headers to JSON, masking sensitive values."""
    masked: dict[str, str] = {}
    for name, value in request.headers.items():
        if name.lower() in _MASKED_HEADERS:
            masked[name] = "***"
        else:
            masked[name] = value
    try:
        return json.dumps(masked, ensure_ascii=False)
    except Exception:
        return None


def _client_ip(request: Request) -> str:
    """Best-effort client IP — duplicates ``hmac_auth._client_ip`` minus
    the import dependency (we want the middleware to be safely usable
    even if hmac_auth fails to import in some test scenarios).
    """
    from app.config import get_settings

    if get_settings().trust_forwarded_for:
        fwd = request.headers.get("x-forwarded-for")
        if fwd:
            return fwd.split(",")[0].strip()
    if request.client is not None:
        return request.client.host
    return "0.0.0.0"  # noqa: S104 — sentinel for "no client info"


class AuditMiddleware(BaseHTTPMiddleware):
    """Record one append-only audit row per HTTP request.

    Best-effort — never breaks the request path on DB failure.
    """

    # Endpoints that do not warrant audit rows (cheap, frequent probes).
    _SKIP_PATHS: frozenset[str] = frozenset({"/healthz", "/v1/healthz"})

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        if request.url.path in self._SKIP_PATHS:
            return await call_next(request)

        # Pre-read the body so we can hash it. ``Request.body()`` is
        # idempotent (Starlette caches the bytes on the receive scope),
        # so subsequent reads in the endpoint return the same bytes.
        try:
            body = await request.body()
        except Exception:
            body = b""

        body_hash = hashlib.sha256(body).hexdigest() if body else None

        # Pull request_id from the body if present (the detect endpoint
        # makes it part of the JSON envelope; other endpoints leave it
        # blank). Avoids a JSON parse if the body is empty/short.
        request_id = _extract_request_id(body)

        # Phase 9B — capture detail if toggle is enabled.
        audit_detail = bool(system_settings.get("audit_detail_enabled"))
        req_body_text: str | None = None
        req_headers_text: str | None = None
        if audit_detail:
            req_body_text = _capture_body(body)
            req_headers_text = _capture_headers(request)

        started = time.perf_counter()
        response: Response | None = None
        raw_resp_bytes: bytes | None = None
        try:
            response = await call_next(request)
            # BaseHTTPMiddleware 가 반환하는 response 는 _StreamingResponse 라
            # ``.body`` 속성이 비어 있다. audit_detail=True 일 때만 body_iterator
            # 를 모두 모아 새 Response 로 다시 감싼다 (그렇게 안 하면
            # response_body_text 가 항상 None 이 된다).
            if audit_detail and hasattr(response, "body_iterator"):
                from starlette.responses import Response as _SResponse

                chunks: list[bytes] = []
                async for chunk in response.body_iterator:
                    chunks.append(chunk if isinstance(chunk, bytes) else bytes(chunk))
                raw_resp_bytes = b"".join(chunks)
                new_headers = {
                    k: v for k, v in response.headers.items() if k.lower() != "content-length"
                }
                response = _SResponse(
                    content=raw_resp_bytes,
                    status_code=response.status_code,
                    headers=new_headers,
                    media_type=response.media_type,
                )
            return response  # noqa: RET504 — finally block uses the variable
        finally:
            elapsed = time.perf_counter() - started
            processing_ms = int(elapsed * 1000)
            payload: AuditPayload | None = getattr(request.state, "audit_payload", None)
            # Phase 8 — Prometheus HTTP counter + latency histogram. Use
            # the route template (request.url.path is fine for everything
            # except /v1/jobs/{id}; we approximate by mapping known
            # parametric paths to their template form to keep cardinality
            # bounded).
            metric_path = _metric_path(request.url.path)
            metric_code = (payload.response_code if payload else None) or (
                f"http_{response.status_code}" if response else "http_0"
            )
            observe_http(
                method=request.method,
                path=metric_path,
                response_code=metric_code,
                duration_seconds=elapsed,
            )
            api_key_id: str | None = None
            caller = getattr(request.state, "caller", None)
            if caller is not None:
                api_key_id = getattr(caller, "key_id", None)

            # Capture response body when detail is enabled. We collected
            # the bytes from response.body_iterator above; fall back to
            # ``response.body`` for any handler that bypasses streaming.
            resp_body_text: str | None = None
            if audit_detail:
                src = raw_resp_bytes
                if src is None and response is not None:
                    fallback = getattr(response, "body", None)
                    if isinstance(fallback, bytes):
                        src = fallback
                if src is not None:
                    resp_body_text = _capture_body(src)

            # Fire-and-forget — never block the response. asyncio.shield
            # so a request cancellation doesn't kill the audit insert.
            try:
                asyncio.create_task(  # noqa: RUF006 — fire-and-forget
                    record_request(
                        request_id=request_id or "",
                        api_key_id=api_key_id,
                        source_ip=_client_ip(request),
                        method=request.method,
                        path=request.url.path,
                        http_status=(response.status_code if response else 0),
                        response_code=payload.response_code if payload else None,
                        detected_entity_count=(payload.detected_entity_count if payload else 0),
                        detected_entity_types=(payload.detected_entity_types if payload else None),
                        processing_ms=processing_ms,
                        body_hash=body_hash,
                        shadow_hit_types=(payload.shadow_hit_types if payload else None),
                        request_body_text=req_body_text,
                        response_body_text=resp_body_text,
                        request_headers_text=req_headers_text,
                        sessionmaker=get_sessionmaker(),
                    ),
                    name=f"audit-{request.url.path}",
                )
            except Exception:
                logger.exception("failed to spawn audit task")


def _metric_path(raw_path: str) -> str:
    """Normalise URL path → bounded-cardinality metric label.

    Paths with embedded ids (``/v1/jobs/{job_id}``,
    ``/v1/masked-artifacts/{token}``) get collapsed to their template so
    the Prometheus label space doesn't grow per-request.
    """
    if raw_path.startswith("/v1/jobs/"):
        return "/v1/jobs/{job_id}"
    if raw_path.startswith("/v1/masked-artifacts/"):
        return "/v1/masked-artifacts/{token}"
    return raw_path


def _extract_request_id(body: bytes) -> str | None:
    """Best-effort JSON parse to lift ``request_id`` from a detect call.

    Returns None on any error — the audit row simply gets an empty
    ``request_id`` instead of breaking the request flow.
    """
    if not body or len(body) > 1_000_000:  # 1 MB sanity cap
        return None
    try:
        import json

        parsed = json.loads(body)
    except (ValueError, UnicodeDecodeError):
        return None
    if not isinstance(parsed, dict):
        return None
    rid = parsed.get("request_id")
    if isinstance(rid, str):
        return rid
    return None
