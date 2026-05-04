"""ClamAV INSTREAM scanner (Phase 4, T4.8).

Wraps the ``clamd`` library's TCP socket interface so the async worker
can hand off bytes to a long-lived ClamAV daemon. Connection failures
are treated as soft errors: we log a warning and let the pipeline
continue. A confirmed FOUND verdict aborts the attachment with
REQ-4050.
"""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING, Any

from app.config import get_settings
from app.extractors.fetcher import ExtractionError

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)


def _scan_sync(data: bytes) -> tuple[str, str | None]:
    """Run a single INSTREAM scan and return (verdict, signature).

    verdict ∈ {"OK", "FOUND", "ERROR"}; signature is set only for FOUND.
    Lazy-imports clamd so test environments without the package can
    still load this module.
    """
    import io

    import clamd  # type: ignore[import-untyped]

    settings = get_settings()
    cd = clamd.ClamdNetworkSocket(host=settings.clamav_host, port=settings.clamav_port, timeout=15)
    raw: dict[str, Any] = cd.instream(io.BytesIO(data))
    # clamd returns: {"stream": ("OK"|"FOUND"|"ERROR", signature_or_None)}
    status, signature = raw.get("stream", ("ERROR", "no stream key"))
    return status, signature


async def scan_bytes(data: bytes, filename: str) -> None:
    """Scan ``data`` against the configured ClamAV daemon.

    - CLEAN  → return None (caller continues)
    - FOUND  → raise ExtractionError(REQ-4050, signature=...)
    - ERROR / connection failure → log warning, return None (best-effort)
    """
    try:
        status, signature = await asyncio.to_thread(_scan_sync, data)
    except Exception as e:
        # Connection refused, timeout, etc.: don't block processing on a
        # scanner outage. Operators are alerted via metrics/logs instead.
        logger.warning("clamav unavailable for %s (%s); skipping scan", filename, e)
        return

    if status == "FOUND":
        raise ExtractionError(
            "REQ-4050",
            filename=filename,
            detail=signature or "unknown signature",
        )
    if status == "ERROR":
        logger.warning("clamav reported ERROR for %s: %s", filename, signature)
        return
    return
