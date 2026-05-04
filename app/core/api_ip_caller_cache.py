"""Process-wide cache of API IP callers (Phase 9A).

Allows registered IPs to authenticate without HMAC. Looked up by
``app.security.auth.require_auth`` whenever the incoming request has no
HMAC headers at all. A CIDR match yields an ``AuthedCaller`` with
``key_id='ip:<cidr>'`` and the row's per-minute / per-hour rate limits.
"""

from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING

from sqlalchemy import select

from app.db.models import ApiIpCaller

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ApiIpCallerEntry:
    """Snapshot of one ``api_ip_callers`` row used by the auth path."""

    cidr: str
    name: str
    rate_per_minute: int
    rate_per_hour: int


_cache: list[ApiIpCallerEntry] = []


async def reload_api_ip_callers(session: AsyncSession) -> int:
    """Reload ``_cache`` from ``pii.api_ip_callers`` (enabled rows only)."""
    global _cache
    try:
        stmt = select(
            ApiIpCaller.cidr,
            ApiIpCaller.name,
            ApiIpCaller.rate_per_minute,
            ApiIpCaller.rate_per_hour,
        ).where(ApiIpCaller.enabled.is_(True))
        result = await session.execute(stmt)
        rows = [
            ApiIpCallerEntry(
                cidr=cidr,
                name=name,
                rate_per_minute=rpm,
                rate_per_hour=rph,
            )
            for cidr, name, rpm, rph in result.all()
            if cidr
        ]
        _cache = rows
        logger.info("api_ip_caller_cache reloaded", extra={"count": len(rows)})
        return len(rows)
    except Exception as e:
        logger.warning("api_ip_caller_cache reload failed: %s", e)
        return 0


def find_caller_by_ip(ip: str) -> ApiIpCallerEntry | None:
    """Return the first cached entry whose CIDR contains ``ip``."""
    if not ip or not _cache:
        return None
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    for entry in _cache:
        try:
            net = ipaddress.ip_network(entry.cidr.strip(), strict=False)
        except ValueError:
            continue
        if addr in net:
            return entry
    return None


def _reset_for_tests() -> None:
    """Clear the module cache; tests use this between runs."""
    global _cache
    _cache = []
