"""HMAC-signed webhook delivery with exponential backoff (Phase 4, T4.18~T4.20).

The orchestrator hands off a fully-constructed ``WebhookPayload`` and a
target URL; this module:
  1. Renders the payload to JSON bytes.
  2. Signs (timestamp, nonce, METHOD, PATH, sha256(body)) per
     ``app.security.hmac_auth._canonical_string`` if a signing secret
     is configured.
  3. POSTs with up to 5 attempts spaced [1, 4, 16, 64, 256] seconds
     when the response is 5xx or transient (timeout/connection error).
  4. Returns True on first 2xx, False if all attempts fail. Permanent
     failure leaves the job COMPLETED so callers can still poll
     ``/v1/jobs/{id}``.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import secrets
import time
from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING
from urllib.parse import urlparse

import httpx

from app.config import get_settings

if TYPE_CHECKING:
    from app.api.schemas import WebhookPayload

logger = logging.getLogger(__name__)

# Per-spec exponential backoff: 1s, 4s, 16s, 64s, 256s = 5 attempts total.
RETRY_DELAYS_SECONDS: tuple[float, ...] = (1.0, 4.0, 16.0, 64.0, 256.0)
MAX_ATTEMPTS = len(RETRY_DELAYS_SECONDS)


def _canonical_string(
    *, timestamp: str, nonce: str, method: str, path: str, body: bytes
) -> str:
    """Mirror of ``app.security.hmac_auth._canonical_string``."""
    body_digest = hashlib.sha256(body).hexdigest()
    return f"{timestamp}\n{nonce}\n{method.upper()}\n{path}\n{body_digest}"


def _sign(secret: str, *, method: str, path: str, body: bytes) -> dict[str, str]:
    """Build the X-Timestamp/X-Nonce/X-Signature header trio."""
    ts = str(int(time.time()))
    nonce = secrets.token_hex(16)
    canonical = _canonical_string(
        timestamp=ts, nonce=nonce, method=method, path=path, body=body
    )
    sig = hmac.new(
        secret.encode("utf-8"), canonical.encode("utf-8"), hashlib.sha256
    ).hexdigest()
    return {"X-Timestamp": ts, "X-Nonce": nonce, "X-Signature": sig}


def _is_retryable(status: int) -> bool:
    return status >= 500 or status == 408 or status == 429


async def send_webhook(
    callback_url: str,
    payload: WebhookPayload,
    *,
    signing_secret: str | None = None,
    sleep: Callable[[float], Awaitable[None]] | None = None,
) -> bool:
    """POST ``payload`` to ``callback_url`` with retries.

    ``signing_secret`` defaults to ``Settings.webhook_signing_secret``.
    When empty, the payload is sent without an X-Signature header.

    ``sleep`` is injectable so tests can drive the retry loop without
    waiting real seconds.
    """
    settings = get_settings()
    secret = signing_secret if signing_secret is not None else settings.webhook_signing_secret
    sleep_fn = sleep or asyncio.sleep

    body_bytes = payload.model_dump_json().encode("utf-8")
    parsed = urlparse(callback_url)
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"

    timeout = httpx.Timeout(settings.webhook_post_timeout_seconds)

    for attempt in range(MAX_ATTEMPTS):
        delay = RETRY_DELAYS_SECONDS[attempt]
        if attempt > 0:
            await sleep_fn(delay)

        headers: dict[str, str] = {"content-type": "application/json"}
        if secret:
            headers.update(
                _sign(secret, method="POST", path=path, body=body_bytes)
            )

        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                resp = await client.post(
                    callback_url, content=body_bytes, headers=headers
                )
        except (httpx.TimeoutException, httpx.HTTPError) as e:
            logger.warning(
                "webhook attempt %d/%d to %s failed: %s",
                attempt + 1, MAX_ATTEMPTS, callback_url, e,
            )
            continue

        if 200 <= resp.status_code < 300:
            return True
        if not _is_retryable(resp.status_code):
            logger.warning(
                "webhook to %s gave non-retryable %d; giving up",
                callback_url, resp.status_code,
            )
            return False
        logger.warning(
            "webhook attempt %d/%d to %s gave %d; retrying",
            attempt + 1, MAX_ATTEMPTS, callback_url, resp.status_code,
        )

    return False


def serialize_payload(payload: WebhookPayload) -> str:
    """Helper used by the orchestrator to mirror a JSON snapshot into the
    ``extraction_jobs.attachments_json`` column."""
    return json.dumps(
        [r.model_dump(mode="json") for r in payload.attachment_results],
        ensure_ascii=False,
    )
