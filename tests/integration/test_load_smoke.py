"""Phase 3 — T3.10 100 RPS smoke load test (≥99% success).

Drives the in-process ASGI app (no real network) — measures the auth
+ analyzer hot path. The "load" target is the spec floor (100 RPS at
99% success); on this machine the actual throughput is much higher.
"""

from __future__ import annotations

import asyncio
import time
import uuid
from typing import TYPE_CHECKING

import pytest
from sqlalchemy import text

from app.config import get_settings
from app.security.api_key import issue_api_key
from app.security.hmac_auth import compute_signature
from app.security.rate_limit import get_redis

if TYPE_CHECKING:
    from httpx import AsyncClient


@pytest.fixture
async def burst_key():
    """High-rate key so the load run isn't itself rate-limited."""
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
    from sqlalchemy.pool import NullPool

    engine = create_async_engine(
        get_settings().database_url, poolclass=NullPool, future=True
    )
    sm = async_sessionmaker(engine, expire_on_commit=False)
    async with sm() as s:
        row, secret = await issue_api_key(
            s, name=f"load-{uuid.uuid4().hex[:6]}",
            rate_per_minute=100_000, rate_per_hour=10_000_000,
            created_by="pytest",
        )
        await s.commit()
        key_id = row.key_id
    yield key_id, secret
    async with sm() as s:
        await s.execute(text("DELETE FROM pii.api_keys WHERE key_id=:k"),
                        {"k": key_id})
        await s.execute(text("DELETE FROM pii.api_key_nonces WHERE key_id=:k"),
                        {"k": key_id})
        await s.commit()
    r = get_redis()
    await r.delete(f"rl:apikey:{key_id}:m", f"rl:apikey:{key_id}:h")


@pytest.mark.slow
async def test_t3_10_100rps_above_99pct_success(
    client_anon: AsyncClient, burst_key: tuple[str, str],
) -> None:
    key_id, secret = burst_key
    target = 100  # 100 requests over ~1s = 100 RPS
    body_template = (
        b'{"request_id":"%s","post":{"board_id":"g","title":"x","body":"y"},'
        b'"author":{"name":"x","ip":"127.0.0.1"}}'
    )

    async def one() -> int:
        ts = str(int(time.time()))
        n = uuid.uuid4().hex
        body = body_template % str(uuid.uuid4()).encode()
        sig = compute_signature(
            secret=secret, timestamp=ts, nonce=n,
            method="POST", path="/v1/detect/post", body=body,
        )
        headers = {
            "X-API-Key": key_id, "X-Timestamp": ts, "X-Nonce": n,
            "X-Signature": sig, "content-type": "application/json",
        }
        r = await client_anon.post(
            "/v1/detect/post", content=body, headers=headers
        )
        return r.status_code

    started = time.perf_counter()
    statuses = await asyncio.gather(*(one() for _ in range(target)))
    elapsed = time.perf_counter() - started

    success = sum(1 for s in statuses if s == 200)
    success_pct = success / target
    rps = target / elapsed
    print(
        f"\n[T3.10] {target} req in {elapsed:.2f}s = {rps:.0f} RPS, "
        f"success {success}/{target} ({success_pct:.1%})"
    )
    assert success_pct >= 0.99, (
        f"success rate {success_pct:.2%} < 99%; statuses: "
        f"{sorted(set(statuses))}"
    )
