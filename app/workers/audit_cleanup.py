"""Periodic GC for ``pii.audit_events`` (Phase 6, T6.3).

Audit rows are retained for ``Settings.audit_log_retention_days`` (default
365) per ISMS-P guidance. This worker runs hourly inside the FastAPI
lifespan and deletes rows older than the retention window.

The append-only triggers reject DELETE by default; the cleanup worker
unlocks them inside the same transaction with::

    SET LOCAL app.bypass_audit_lock = 'on';

so it never affects concurrent INSERTs.
"""

from __future__ import annotations

import asyncio
import logging

from app.config import get_settings
from app.db.crud import cleanup_expired_audit_events
from app.db.session import get_sessionmaker

logger = logging.getLogger(__name__)

DEFAULT_INTERVAL_SECONDS = 3600.0  # 1 hour


async def audit_cleanup_loop(
    *,
    interval_seconds: float = DEFAULT_INTERVAL_SECONDS,
    retention_days: int | None = None,
) -> None:
    """Loop: every ``interval_seconds`` drop audit rows older than
    ``retention_days`` (default from Settings).
    """
    sm = get_sessionmaker()
    while True:
        try:
            days = retention_days or get_settings().audit_log_retention_days
            async with sm() as session:
                deleted = await cleanup_expired_audit_events(
                    session, retention_days=days
                )
                if deleted:
                    logger.info(
                        "audit_cleanup: deleted %d expired audit events", deleted
                    )
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("audit_cleanup failed; will retry next cycle")
        await asyncio.sleep(interval_seconds)
