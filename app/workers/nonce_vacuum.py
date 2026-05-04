"""Periodic GC for ``pii.api_key_nonces`` (Q4).

Replay-defence stores every (key_id, nonce) for ten minutes. Without a
periodic vacuum the table grows unbounded. This coroutine runs inside
the FastAPI lifespan (next to ``pattern_listener``) and deletes rows
older than the retention window every ``interval_seconds``.
"""

from __future__ import annotations

import asyncio
import logging

from app.db.session import get_sessionmaker
from app.security.hmac_auth import NONCE_RETENTION_SECONDS, vacuum_old_nonces

logger = logging.getLogger(__name__)

DEFAULT_INTERVAL_SECONDS = 600.0  # 10 minutes


async def nonce_vacuum_loop(
    *,
    interval_seconds: float = DEFAULT_INTERVAL_SECONDS,
    retention_seconds: int = NONCE_RETENTION_SECONDS,
) -> None:
    """Loop: every ``interval_seconds`` drop nonces older than retention."""
    sm = get_sessionmaker()
    while True:
        try:
            async with sm() as session:
                deleted = await vacuum_old_nonces(
                    session, retention_seconds=retention_seconds
                )
                if deleted:
                    logger.info(
                        "nonce_vacuum: deleted %d expired nonces", deleted
                    )
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("nonce_vacuum failed; will retry next cycle")
        await asyncio.sleep(interval_seconds)
