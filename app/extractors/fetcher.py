"""Async attachment downloader + SHA256 verifier (Phase 4, T4.10/T4.11).

Issues a single HTTPS GET against ``Attachment.fetch_url`` with a hard
timeout, validates that the response stream's SHA-256 matches the
caller-supplied ``Attachment.sha256``, and returns the raw bytes.

The fetcher is the first per-attachment step inside the asyncio
worker; any failure here aborts the rest of the pipeline for that
specific attachment but never the whole job.
"""

from __future__ import annotations

import hashlib
import logging
from typing import TYPE_CHECKING

import httpx

from app.config import get_settings

if TYPE_CHECKING:
    from app.api.schemas import Attachment

logger = logging.getLogger(__name__)


class ExtractionError(Exception):
    """Per-attachment failure surfaced as an attachment-level error code.

    The asyncio worker traps these and writes them into the webhook
    payload for that specific attachment, leaving sibling attachments
    untouched.
    """

    def __init__(self, code: str, *, filename: str, detail: str | None = None) -> None:
        super().__init__(f"{code} {filename}: {detail or ''}")
        self.code = code
        self.filename = filename
        self.detail = detail


async def fetch_attachment(attachment: Attachment) -> bytes:
    """Download ``attachment.fetch_url`` and verify SHA-256.

    Raises:
        ExtractionError(REQ-4040): network/HTTP failure
        ExtractionError(REQ-4041): SHA-256 of payload != attachment.sha256
    """
    settings = get_settings()
    timeout = httpx.Timeout(settings.attachment_fetch_timeout_seconds)

    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
            resp = await client.get(attachment.fetch_url)
    except httpx.TimeoutException as e:
        raise ExtractionError(
            "REQ-4040",
            filename=attachment.filename,
            detail=f"timeout after {settings.attachment_fetch_timeout_seconds}s",
        ) from e
    except httpx.HTTPError as e:
        raise ExtractionError(
            "REQ-4040",
            filename=attachment.filename,
            detail=f"transport error: {type(e).__name__}",
        ) from e

    if resp.status_code >= 400:
        raise ExtractionError(
            "REQ-4040",
            filename=attachment.filename,
            detail=f"HTTP {resp.status_code}",
        )

    data = resp.content

    actual = hashlib.sha256(data).hexdigest()
    if actual.lower() != attachment.sha256.lower():
        raise ExtractionError(
            "REQ-4041",
            filename=attachment.filename,
            detail="sha256 mismatch",
        )

    return data
