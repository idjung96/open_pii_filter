"""Periodic GC for ``pii.extraction_jobs`` (Phase 4, T4.21).

Async jobs are retained for 24 hours after completion so callers can
poll ``/v1/jobs/{id}`` even when the webhook delivery fails. Past that
window the row is no longer useful and is reclaimed here.

Mirrors the structure of :mod:`app.workers.nonce_vacuum`.
"""

from __future__ import annotations

import asyncio
import logging

from app.db.crud import cleanup_expired_jobs
from app.db.session import get_sessionmaker

logger = logging.getLogger(__name__)

DEFAULT_INTERVAL_SECONDS = 3600.0  # 1 hour
DEFAULT_RETENTION_HOURS = 24


async def job_cleanup_loop(
    *,
    interval_seconds: float = DEFAULT_INTERVAL_SECONDS,
    retention_hours: int = DEFAULT_RETENTION_HOURS,
) -> None:
    """Loop: every ``interval_seconds`` drop jobs whose ``completed_at``
    is older than ``retention_hours``.
    """
    sm = get_sessionmaker()
    while True:
        try:
            async with sm() as session:
                deleted = await cleanup_expired_jobs(session, retention_hours=retention_hours)
                if deleted:
                    logger.info("job_cleanup: deleted %d expired jobs", deleted)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("job_cleanup failed; will retry next cycle")
        await asyncio.sleep(interval_seconds)
