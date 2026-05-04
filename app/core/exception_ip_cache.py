"""Process-wide cache of PII exception IPs (Phase 9A).

The cache holds a flat ``set[str]`` of CIDR strings loaded from
``pii.exception_ips``. The lookup walks the set converting each entry to
an ``ipaddress.ip_network`` on demand — adequate for the expected
cardinality (low hundreds) and avoids stale-cache complications when
operators delete a row from the admin dashboard.

When the database is unreachable the cache stays at its previous state
so the API keeps booting. The first successful reload after recovery
will refill it.
"""

from __future__ import annotations

import ipaddress
import logging
from typing import TYPE_CHECKING

from sqlalchemy import select

from app.db.models import ExceptionIp

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)

_cache: set[str] = set()


async def reload_exception_ips(session: AsyncSession) -> int:
    """Reload ``_cache`` from ``pii.exception_ips`` (enabled rows only).

    Returns the number of rows loaded. Failures are caught and logged so
    a transient DB outage doesn't block application startup.
    """
    global _cache
    try:
        stmt = select(ExceptionIp.cidr).where(ExceptionIp.enabled.is_(True))
        result = await session.execute(stmt)
        cidrs = {row[0] for row in result.all() if row[0]}
        _cache = cidrs
        logger.info(
            "exception_ip_cache reloaded", extra={"count": len(cidrs)}
        )
        return len(cidrs)
    except Exception as e:
        logger.warning("exception_ip_cache reload failed: %s", e)
        return 0


def is_exception_ip(ip: str) -> bool:
    """Return ``True`` when ``ip`` falls inside any cached CIDR."""
    if not ip or not _cache:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for cidr in _cache:
        try:
            net = ipaddress.ip_network(cidr.strip(), strict=False)
        except ValueError:
            continue
        if addr in net:
            return True
    return False


def _reset_for_tests() -> None:
    """Clear the module cache; tests use this between runs."""
    global _cache
    _cache = set()
