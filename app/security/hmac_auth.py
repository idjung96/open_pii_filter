"""HMAC-SHA256 signature verification (Phase 3, T3.1~T3.4).

Headers
-------
- ``X-API-Key``    : public ``key_id`` from ``pii.api_keys``
- ``X-Timestamp``  : UNIX seconds (UTC); window is ±5 minutes
- ``X-Nonce``      : 16+ char random string, single-use within window
- ``X-Signature``  : hex-encoded HMAC-SHA256 of the canonical string

Canonical string
----------------
Constructed as::

    {timestamp}\\n{nonce}\\n{METHOD}\\n{PATH}\\n{sha256_hex(body)}

A digest of the body — not the body itself — is included so the canonical
string stays bounded regardless of payload size. The verifier performs
constant-time comparison of the resulting digest against ``X-Signature``.

Replay defense
--------------
Every accepted (key_id, nonce) pair is recorded in
``pii.api_key_nonces``. A repeated submission within the timestamp
window short-circuits to ``REQ-4013``.
"""

from __future__ import annotations

import hashlib
import hmac
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

from fastapi import Request
from fastapi.responses import JSONResponse
from sqlalchemy import delete
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.exc import IntegrityError

from app.api.responses import build_response
from app.core.codes import get_code
from app.db.models import ApiKey, ApiKeyNonce
from app.db.session import get_session
from app.security.api_key import find_active_key

if TYPE_CHECKING:
    from collections.abc import AsyncIterator
    from uuid import UUID

    from sqlalchemy.ext.asyncio import AsyncSession


# Public constants
TIMESTAMP_WINDOW_SECONDS = 5 * 60       # ±5 minutes per spec
NONCE_RETENTION_SECONDS = 10 * 60       # vacuum threshold; > 2x window


@dataclass(frozen=True)
class AuthedCaller:
    """The verified caller passed to handlers via Depends()."""

    key_id: str
    name: str
    rate_per_minute: int
    rate_per_hour: int
    ip_allowlist: tuple[str, ...] | None
    client_ip: str
    # Phase 6 — gates access to /v1/admin/* endpoints. Default false so the
    # field is back-compat for tests that build AuthedCaller directly.
    is_admin: bool = False


class HmacAuthError(Exception):
    """Raised by `verify_request` to signal a specific REQ-401x/4015 code."""

    def __init__(self, code: str, **template_vars: object) -> None:
        super().__init__(code)
        self.code = code
        self.template_vars = template_vars


# ── Canonical string + signature ──────────────────────────────────────────
def _canonical_string(
    *, timestamp: str, nonce: str, method: str, path: str, body: bytes
) -> str:
    body_digest = hashlib.sha256(body).hexdigest()
    return f"{timestamp}\n{nonce}\n{method.upper()}\n{path}\n{body_digest}"


def compute_signature(
    *,
    secret: str,
    timestamp: str,
    nonce: str,
    method: str,
    path: str,
    body: bytes,
) -> str:
    """Hex-encoded HMAC-SHA256 used by both clients and the server."""
    canonical = _canonical_string(
        timestamp=timestamp, nonce=nonce, method=method, path=path, body=body
    )
    return hmac.new(
        secret.encode("utf-8"),
        canonical.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


# ── Verifier ──────────────────────────────────────────────────────────────
def _check_timestamp(timestamp_header: str, *, now: float | None = None) -> None:
    try:
        ts = int(timestamp_header)
    except ValueError as e:
        raise HmacAuthError("REQ-4012") from e
    current = now if now is not None else time.time()
    if abs(current - ts) > TIMESTAMP_WINDOW_SECONDS:
        raise HmacAuthError("REQ-4012")


async def _claim_nonce(
    session: AsyncSession, key_id: str, nonce: str
) -> None:
    """Insert (key_id, nonce); raises HmacAuthError(REQ-4013) on conflict."""
    stmt = (
        pg_insert(ApiKeyNonce)
        .values(key_id=key_id, nonce=nonce)
        .on_conflict_do_nothing(index_elements=["key_id", "nonce"])
        .returning(ApiKeyNonce.key_id)
    )
    try:
        result = await session.execute(stmt)
    except IntegrityError as e:  # pragma: no cover — covered by ON CONFLICT
        raise HmacAuthError("REQ-4013") from e
    if result.first() is None:
        raise HmacAuthError("REQ-4013")
    await session.commit()


async def vacuum_old_nonces(
    session: AsyncSession, *, retention_seconds: int = NONCE_RETENTION_SECONDS
) -> int:
    """Periodic GC: delete nonces older than the retention window."""
    cutoff = datetime.now(tz=UTC) - timedelta(seconds=retention_seconds)
    stmt = delete(ApiKeyNonce).where(ApiKeyNonce.used_at < cutoff)
    res = await session.execute(stmt)
    await session.commit()
    return getattr(res, "rowcount", 0) or 0


def _client_ip(request: Request) -> str:
    """Best-effort client IP — honours X-Forwarded-For only when the
    operator opts in via ``Settings.trust_forwarded_for`` (Q5).

    Outside a trusted proxy deployment the header is attacker-controlled
    and would otherwise let any client spoof their IP for the allowlist.
    """
    from app.config import get_settings

    if get_settings().trust_forwarded_for:
        fwd = request.headers.get("x-forwarded-for")
        if fwd:
            # Left-most entry is the original client.
            return fwd.split(",")[0].strip()
    if request.client is not None:
        return request.client.host
    return "0.0.0.0"  # noqa: S104 — sentinel for "no client info"


async def verify_request(
    request: Request,
    session: AsyncSession,
    *,
    x_api_key: str | None,
    x_timestamp: str | None,
    x_nonce: str | None,
    x_signature: str | None,
) -> AuthedCaller:
    """Validate the four headers + signature; return the authed caller.

    Raises ``HmacAuthError`` with the appropriate REQ-401x / REQ-4015 code
    so the FastAPI dependency wrapper can map it to a response envelope.
    """
    if not x_api_key or not x_timestamp or not x_nonce or not x_signature:
        raise HmacAuthError("REQ-4011")

    # Timestamp window — cheap pre-check.
    _check_timestamp(x_timestamp)

    # API key lookup.
    row: ApiKey | None = await find_active_key(session, x_api_key)
    if row is None:
        raise HmacAuthError("REQ-4011")
    if not row.enabled or row.revoked_at is not None:
        raise HmacAuthError("REQ-4014")

    # Recover the body. FastAPI may have already drained the stream; the
    # router-level Request.body() is idempotent (ASGI cache).
    body = await request.body()

    # Standard HMAC-SHA256 with the plaintext secret as the key (Q1).
    # Plaintext-at-rest is the documented trade-off; Phase 6 wraps this
    # column with pgcrypto AES.
    expected = hmac.new(
        row.secret.encode("utf-8"),
        _canonical_string(
            timestamp=x_timestamp,
            nonce=x_nonce,
            method=request.method,
            path=request.url.path,
            body=body,
        ).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(expected, x_signature):
        raise HmacAuthError("REQ-4010")

    # All checks passed → claim the nonce. Replay attempts collide here.
    await _claim_nonce(session, row.key_id, x_nonce)

    return AuthedCaller(
        key_id=row.key_id,
        name=row.name,
        rate_per_minute=row.rate_per_minute,
        rate_per_hour=row.rate_per_hour,
        ip_allowlist=tuple(row.ip_allowlist) if row.ip_allowlist else None,
        client_ip=_client_ip(request),
        is_admin=bool(row.is_admin),
    )


# ── FastAPI dependency wrapper ────────────────────────────────────────────
def _error_response(code: str, request_id: UUID | None, **vars: object) -> JSONResponse:
    rc = get_code(code)
    resp = build_response(
        request_id=request_id or _zero_uuid(),
        code=code,
        processing_ms=0,
        template_vars=vars or None,
    )
    return JSONResponse(status_code=rc.http_status, content=resp.model_dump(mode="json"))


def _zero_uuid() -> UUID:
    from uuid import UUID

    return UUID("00000000-0000-0000-0000-000000000000")


async def session_dep() -> AsyncIterator[AsyncSession]:
    """Adapter: use existing get_session() generator as a FastAPI dependency.

    Used only by tests / future endpoints; the production endpoint reaches
    DB via :func:`app.security.auth.require_auth`.
    """
    async for s in get_session():
        yield s
