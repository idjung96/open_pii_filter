# SYNTHETIC DATA - NOT REAL PII
"""Phase 4b/D — `app.workers.webhook_sender.send_delete_request`.

Drives the helper against `httpx.MockTransport` so we cover:
  - happy-path 2xx → returns True after one attempt
  - non-retryable 4xx → returns False after one attempt
  - retryable 5xx → exhausts the retry budget then returns False
  - HMAC headers (X-Timestamp/X-Nonce/X-Signature) appear when a
    signing secret is configured
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
from typing import TYPE_CHECKING

import httpx
import pytest

from app.workers.webhook_sender import RETRY_DELAYS_SECONDS, send_delete_request

if TYPE_CHECKING:
    pass


async def _no_sleep(_seconds: float) -> None:
    return None


def _patch_transport(
    monkeypatch: pytest.MonkeyPatch,
    handler,  # type: ignore[no-untyped-def]
) -> list[httpx.Request]:
    transport = httpx.MockTransport(handler)
    seen: list[httpx.Request] = []

    real_init = httpx.AsyncClient.__init__

    def patched_init(self, *args, **kwargs):  # type: ignore[no-untyped-def]
        kwargs["transport"] = transport
        real_init(self, *args, **kwargs)

    def recording_handler(req: httpx.Request) -> httpx.Response:
        seen.append(req)
        return handler(req)

    monkeypatch.setattr(httpx.AsyncClient, "__init__", patched_init)
    monkeypatch.setattr(transport, "handler", recording_handler)
    return seen


async def test_send_delete_returns_true_on_first_2xx(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen = _patch_transport(monkeypatch, lambda _r: httpx.Response(200))
    ok = await send_delete_request(
        "https://board.example.test/cb",
        request_id="rid-1",
        job_id="job-1",
        code="BLOCK-2010",
        signing_secret="",
        sleep=_no_sleep,
    )
    assert ok is True
    assert len(seen) == 1
    assert seen[0].method == "DELETE"


async def test_send_delete_returns_false_on_non_retryable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen = _patch_transport(monkeypatch, lambda _r: httpx.Response(400))
    ok = await send_delete_request(
        "https://board.example.test/cb",
        request_id="rid-2",
        job_id="job-2",
        code="BLOCK-2010",
        signing_secret="",
        sleep=_no_sleep,
    )
    assert ok is False
    assert len(seen) == 1


async def test_send_delete_retries_on_5xx_then_gives_up(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen = _patch_transport(monkeypatch, lambda _r: httpx.Response(503))
    ok = await send_delete_request(
        "https://board.example.test/cb",
        request_id="rid-3",
        job_id="job-3",
        code="BLOCK-2010",
        signing_secret="",
        sleep=_no_sleep,
    )
    assert ok is False
    assert len(seen) == len(RETRY_DELAYS_SECONDS)


async def test_send_delete_signs_with_hmac_when_secret_set(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen = _patch_transport(monkeypatch, lambda _r: httpx.Response(200))
    ok = await send_delete_request(
        "https://board.example.test/cb?x=1",
        request_id="rid-4",
        job_id="job-4",
        code="BLOCK-2010",
        signing_secret="secret-shhh",  # noqa: S106 — synthetic test secret
        sleep=_no_sleep,
    )
    assert ok is True
    req = seen[0]
    assert "X-Timestamp" in req.headers
    assert "X-Nonce" in req.headers
    assert "X-Signature" in req.headers

    # Recompute and compare so we know the helper is actually using the
    # same canonical form as the receiver verifier expects.
    body = req.content
    canonical = (
        f"{req.headers['X-Timestamp']}\n"
        f"{req.headers['X-Nonce']}\n"
        f"DELETE\n"
        f"/cb?x=1\n"
        f"{hashlib.sha256(body).hexdigest()}"
    )
    expected = hmac.new(b"secret-shhh", canonical.encode("utf-8"), hashlib.sha256).hexdigest()
    assert req.headers["X-Signature"] == expected


async def test_send_delete_body_carries_correlation_ids(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen = _patch_transport(monkeypatch, lambda _r: httpx.Response(204))
    await send_delete_request(
        "https://board.example.test/cb",
        request_id="rid-5",
        job_id="job-5",
        code="BLOCK-2099",
        reason="custom reason",
        signing_secret="",
        sleep=_no_sleep,
    )
    body = seen[0].content.decode()
    assert "rid-5" in body
    assert "job-5" in body
    assert "BLOCK-2099" in body
    assert "custom reason" in body


async def test_send_delete_swallows_transport_errors_and_retries(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A timeout on the first call should retry; the second call's 200
    must surface as success."""
    counter = {"n": 0}

    def handler(req: httpx.Request) -> httpx.Response:
        counter["n"] += 1
        if counter["n"] == 1:
            raise httpx.ConnectTimeout("simulated", request=req)
        return httpx.Response(204)

    _patch_transport(monkeypatch, handler)
    ok = await send_delete_request(
        "https://board.example.test/cb",
        request_id="rid-6",
        job_id="job-6",
        code="BLOCK-2010",
        signing_secret="",
        sleep=_no_sleep,
    )
    assert ok is True
    assert counter["n"] == 2


# Sanity: make sure asyncio works in this test module (pytest-asyncio
# auto mode is configured project-wide in pyproject).
async def test_async_runs() -> None:
    await asyncio.sleep(0)
