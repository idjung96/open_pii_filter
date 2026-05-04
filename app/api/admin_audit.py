"""GET /v1/admin/audit-events — sysadmin-only audit log query (Phase 6).

Trust-zone separation
---------------------
This router is **only mounted** when ``Settings.admin_ip_allowlist`` is
non-empty. Empty allowlist → router not registered → external scanners
get 404 instead of a hint that the admin surface exists.

Authorization
-------------
Every request goes through three gates (composed dependency
``require_admin``):

1. ``require_auth`` — HMAC + API key + per-key rate limit
2. ``caller.is_admin == True``
3. caller's source IP must match a CIDR in
   ``Settings.admin_ip_allowlist``

Failure of any gate maps to ``REQ-4015`` (HTTP 403, same envelope as
existing IP-allowlist failures).
"""

from __future__ import annotations

import base64
import json
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field

from app.config import get_settings
from app.db.crud import list_audit_events
from app.db.session import get_sessionmaker
from app.security.auth import EnvelopeHTTPException, _envelope, require_auth
from app.security.hmac_auth import AuthedCaller
from app.security.ip_allowlist import IpNotAllowedError
from app.security.ip_allowlist import enforce as enforce_ip

router = APIRouter(prefix="/v1/admin", tags=["admin"])


# ── Authorization gate ────────────────────────────────────────────────────
def _admin_allowlist() -> list[str]:
    raw = (get_settings().admin_ip_allowlist or "").strip()
    return [c.strip() for c in raw.split(",") if c.strip()]


async def require_admin(
    caller: AuthedCaller = Depends(require_auth),  # noqa: B008
) -> AuthedCaller:
    """Compose admin-only checks on top of ``require_auth``.

    Both the ``is_admin`` flag and the IP allowlist must pass; failure
    surfaces the same ``REQ-4015`` envelope as a regular IP allowlist
    rejection so an attacker can't differentiate the two cases.
    """
    if not caller.is_admin:
        raise _envelope("REQ-4015", status=403, ip=caller.client_ip)
    allowlist = _admin_allowlist()
    if not allowlist:
        # Defence in depth — should never happen because the router is
        # only mounted when admin_ip_allowlist is non-empty, but if a
        # misconfiguration sneaks past the boot-time gate, fail closed.
        raise _envelope("REQ-4015", status=403, ip=caller.client_ip)
    try:
        enforce_ip(
            caller.client_ip,
            key_allowlist=None,
            global_allowlist=allowlist,
        )
    except IpNotAllowedError as e:
        raise _envelope("REQ-4015", status=403, ip=e.ip) from e
    return caller


# ── Response models ───────────────────────────────────────────────────────
class AuditEventOut(BaseModel):
    """Single audit row, sanitised for the admin API.

    Mirrors the DB columns 1:1 minus the surrogate ``id`` (callers should
    never depend on row ids directly — pagination uses an opaque cursor).
    """

    occurred_at: datetime
    request_id: str
    api_key_id: str | None
    source_ip: str
    method: str
    path: str
    http_status: int | None
    response_code: str | None
    detected_entity_count: int
    detected_entity_types: str | None
    processing_ms: int | None
    body_hash: str | None


class AuditEventsResponse(BaseModel):
    events: list[AuditEventOut] = Field(default_factory=list)
    next_cursor: str | None = None


# ── Cursor helpers ────────────────────────────────────────────────────────
def _encode_cursor(occurred_at: datetime, row_id: int) -> str:
    payload = {"o": occurred_at.isoformat(), "i": int(row_id)}
    return base64.urlsafe_b64encode(json.dumps(payload).encode("utf-8")).decode("ascii")


def _decode_cursor(cursor: str) -> tuple[datetime, int]:
    try:
        raw = base64.urlsafe_b64decode(cursor.encode("ascii"))
        parsed: dict[str, Any] = json.loads(raw)
        occurred_at = datetime.fromisoformat(parsed["o"])
        row_id = int(parsed["i"])
    except (ValueError, KeyError, json.JSONDecodeError) as e:
        raise EnvelopeHTTPException(
            status_code=400,
            detail={
                "code": "REQ-4003",
                "user_message": "invalid cursor",
                "developer_message": f"cursor decode failed: {e}",
            },
        ) from e
    return occurred_at, row_id


# ── Endpoint ──────────────────────────────────────────────────────────────
@router.get("/audit-events", response_model=AuditEventsResponse)
async def list_events(
    since: datetime | None = Query(default=None),  # noqa: B008
    until: datetime | None = Query(default=None),  # noqa: B008
    request_id: str | None = Query(default=None, max_length=64),
    api_key_id: str | None = Query(default=None, max_length=64),
    response_code: str | None = Query(default=None, max_length=16),
    limit: int = Query(default=100, ge=1, le=500),
    cursor: str | None = Query(default=None),
    _caller: AuthedCaller = Depends(require_admin),  # noqa: B008
) -> AuditEventsResponse:
    """Return audit events newest-first with keyset pagination."""
    if since is None:
        since = datetime.now(tz=UTC) - timedelta(hours=24)
    if until is None:
        until = datetime.now(tz=UTC)

    cursor_occurred_at: datetime | None = None
    cursor_id: int | None = None
    if cursor:
        cursor_occurred_at, cursor_id = _decode_cursor(cursor)

    sm = get_sessionmaker()
    async with sm() as session:
        rows = await list_audit_events(
            session,
            since=since,
            until=until,
            request_id=request_id,
            api_key_id=api_key_id,
            response_code=response_code,
            cursor_occurred_at=cursor_occurred_at,
            cursor_id=cursor_id,
            limit=limit,
        )

    events = [
        AuditEventOut(
            occurred_at=r.occurred_at,
            request_id=r.request_id,
            api_key_id=r.api_key_id,
            source_ip=r.source_ip,
            method=r.method,
            path=r.path,
            http_status=r.http_status,
            response_code=r.response_code,
            detected_entity_count=r.detected_entity_count,
            detected_entity_types=r.detected_entity_types,
            processing_ms=r.processing_ms,
            body_hash=r.body_hash,
        )
        for r in rows
    ]

    next_cursor: str | None = None
    if len(rows) == limit and rows:
        last = rows[-1]
        next_cursor = _encode_cursor(last.occurred_at, last.id)

    return AuditEventsResponse(events=events, next_cursor=next_cursor)
