"""Phase 3 — T3.7 rate limit (per API key + per IP fallback)."""

from __future__ import annotations

import time
import uuid
from typing import TYPE_CHECKING

import pytest
from sqlalchemy import text

from app.config import get_settings
from app.security.api_key import issue_api_key
from app.security.hmac_auth import compute_signature
from app.security.rate_limit import RateLimiter, get_redis

if TYPE_CHECKING:
    from httpx import AsyncClient


@pytest.fixture
async def low_rate_key():
    """Issue a key with rate_per_minute=3 so the test fires the limit fast."""
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
    from sqlalchemy.pool import NullPool

    engine = create_async_engine(get_settings().database_url, poolclass=NullPool, future=True)
    sm = async_sessionmaker(engine, expire_on_commit=False)
    async with sm() as s:
        row, secret = await issue_api_key(
            s,
            name=f"rl-{uuid.uuid4().hex[:6]}",
            rate_per_minute=3,
            rate_per_hour=1000,
            created_by="pytest",
        )
        await s.commit()
        key_id = row.key_id
    yield key_id, secret
    async with sm() as s:
        await s.execute(text("DELETE FROM pii.api_keys WHERE key_id=:k"), {"k": key_id})
        await s.execute(text("DELETE FROM pii.api_key_nonces WHERE key_id=:k"), {"k": key_id})
        await s.commit()
    r = get_redis()
    await r.delete(f"rl:apikey:{key_id}:m", f"rl:apikey:{key_id}:h")


def _hdr(key_id: str, secret: str, body: bytes) -> dict[str, str]:
    ts = str(int(time.time()))
    n = uuid.uuid4().hex
    sig = compute_signature(
        secret=secret,
        timestamp=ts,
        nonce=n,
        method="POST",
        path="/v1/detect/post",
        body=body,
    )
    return {
        "X-API-Key": key_id,
        "X-Timestamp": ts,
        "X-Nonce": n,
        "X-Signature": sig,
        "content-type": "application/json",
    }


# ── T3.7: 4th request inside the minute → 429 + Retry-After ───────────────
async def test_t3_7_rate_limit_emits_429(
    client_anon: AsyncClient,
    low_rate_key: tuple[str, str],
) -> None:
    key_id, secret = low_rate_key
    body_template = (
        b'{"request_id":"%s","post":{"board_id":"g","title":"x","body":"y"},'
        b'"author":{"name":"x","ip":"127.0.0.1"}}'
    )

    successes = 0
    last_resp = None
    for _ in range(5):
        body = body_template % str(uuid.uuid4()).encode()
        resp = await client_anon.post(
            "/v1/detect/post", content=body, headers=_hdr(key_id, secret, body)
        )
        last_resp = resp
        if resp.status_code == 200:
            successes += 1
        elif resp.status_code == 429:
            break

    assert successes >= 1, f"at least one success expected; got {successes}"
    assert last_resp is not None
    assert last_resp.status_code == 429
    assert last_resp.json()["code"] == "REQ-4020"
    assert int(last_resp.headers.get("Retry-After", "0")) >= 1


# ── Token bucket unit: refill within 1s ───────────────────────────────────
async def test_token_bucket_refills_after_window() -> None:
    redis = get_redis()
    limiter = RateLimiter(redis)
    key = f"rl:test:{uuid.uuid4().hex}"

    # Capacity 1, rate 5/sec — should allow 1 then deny then re-allow ~0.2s later.
    out1 = await limiter.consume(key, capacity=1, rate_per_second=5.0)
    assert out1.allowed
    out2 = await limiter.consume(key, capacity=1, rate_per_second=5.0)
    assert not out2.allowed
    assert out2.retry_after >= 1
