"""API key issue/lookup helpers (Phase 3, T3.5/T3.6).

Q1 (operator review): the secret is stored as plaintext so HMAC
verification uses the standard pattern (client signs with plaintext,
server recomputes). Plaintext-at-rest is a known trade-off; Phase 6
adds pgcrypto column-level encryption.
"""

from __future__ import annotations

import secrets
from typing import TYPE_CHECKING

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app.db.models import ApiKey

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession


KEY_ID_BYTES = 16  # 32 hex chars
SECRET_BYTES = 32  # 64 hex chars


class ApiKeyError(ValueError):
    """Raised when API-key issue/revoke validation fails."""


def _new_key_id() -> str:
    return "k_" + secrets.token_hex(KEY_ID_BYTES)


def _new_secret() -> str:
    return secrets.token_hex(SECRET_BYTES)


async def issue_api_key(
    session: AsyncSession,
    *,
    name: str,
    ip_allowlist: list[str] | None = None,
    rate_per_minute: int = 60,
    rate_per_hour: int = 1000,
    created_by: str = "cli",
    is_admin: bool = False,
) -> tuple[ApiKey, str]:
    """Insert a new ApiKey row and return (row, plaintext_secret).

    The secret is generated server-side; callers must capture it
    immediately because it cannot be recovered from the DB.

    ``is_admin=True`` (Phase 6) grants the key access to ``/v1/admin/*``
    endpoints when the caller's IP is also inside
    ``Settings.admin_ip_allowlist``.
    """
    if rate_per_minute <= 0 or rate_per_hour <= 0:
        raise ApiKeyError("rate_per_minute and rate_per_hour must be positive")

    key_id = _new_key_id()
    secret = _new_secret()

    row = ApiKey(
        key_id=key_id,
        secret=secret,
        name=name,
        ip_allowlist=ip_allowlist,
        rate_per_minute=rate_per_minute,
        rate_per_hour=rate_per_hour,
        enabled=True,
        is_admin=is_admin,
        created_by=created_by,
    )
    session.add(row)
    try:
        await session.flush()
    except IntegrityError as e:  # pragma: no cover — vanishingly small chance
        raise ApiKeyError("key_id collision; retry") from e
    return row, secret


async def find_active_key(session: AsyncSession, key_id: str) -> ApiKey | None:
    """Return the row for `key_id` if it exists, regardless of enabled state."""
    stmt = select(ApiKey).where(ApiKey.key_id == key_id)
    row: ApiKey | None = await session.scalar(stmt)
    return row


async def list_keys(session: AsyncSession, *, include_revoked: bool = False) -> list[ApiKey]:
    stmt = select(ApiKey).order_by(ApiKey.created_at.desc())
    if not include_revoked:
        stmt = stmt.where(ApiKey.revoked_at.is_(None))
    rows = await session.scalars(stmt)
    return list(rows)


async def set_enabled(session: AsyncSession, key_id: str, *, enabled: bool) -> ApiKey:
    row = await find_active_key(session, key_id)
    if row is None:
        raise ApiKeyError(f"key_id={key_id} not found")
    row.enabled = enabled
    await session.flush()
    return row


async def revoke(session: AsyncSession, key_id: str) -> ApiKey:
    """Revoke a key permanently (sets enabled=false + revoked_at=now)."""
    from datetime import UTC, datetime

    row = await find_active_key(session, key_id)
    if row is None:
        raise ApiKeyError(f"key_id={key_id} not found")
    row.enabled = False
    row.revoked_at = datetime.now(tz=UTC)
    await session.flush()
    return row


def verify_secret(row: ApiKey, secret: str) -> bool:
    """Constant-time comparison of presented secret against the stored value."""
    return secrets.compare_digest(secret, row.secret)
