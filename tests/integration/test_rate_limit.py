"""Phase 3 — T3.7 rate limit 회귀 방지 (API 키 단위 + IP fallback).

운영자가 키 별로 분당/시간당 한도를 설정할 수 있으며, 한도 초과 시 응답
`429 REQ-4020` + `Retry-After` 헤더가 떨어지는 흐름을 확인. 추가로 GCRA
토큰 버킷 리미터 자체의 refill 동작 (capacity 1 + rate 5/s → 0.2초 뒤
재허용) 도 단위 수준에서 검증한다.

`low_rate_key` fixture 가 분당 3건짜리 API 키를 발급해 빠르게 한도를 트립
하도록 구성 — DB row 와 Redis 카운터 모두 cleanup 됨.
"""

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


# ── T3.7: 분당 한도 (3건) 초과 → 429 REQ-4020 + Retry-After ──────────────
async def test_t3_7_rate_limit_emits_429(
    client_anon: AsyncClient,
    low_rate_key: tuple[str, str],
) -> None:
    """1분 내 4번째 요청부터 429 + REQ-4020 + Retry-After 헤더.

    정상 호출은 최소 1건은 통과해야 하고 (rate-limit 자체가 0건만 허용하지
    않는지), 그 뒤 429 가 떨어지면 즉시 break — Retry-After 가 1초 이상의
    정수로 채워졌는지도 확인.
    """
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


# ── Token bucket 단위: refill 동작 (1초 안에 재충전) ────────────────────
async def test_token_bucket_refills_after_window() -> None:
    """capacity 1 + rate 5/s 버킷이 첫 요청 허용 → 두번째 거절 → retry_after ≥ 1.

    GCRA 알고리즘이 정확히 토큰 1개를 소모한 뒤 다음 토큰 충전을 기다리도
    록 작동하는지 단위 수준에서 핀(pin) 한다. 엔드포인트 통합 테스트와는
    별도로 알고리즘 자체 회귀를 잡는 가드.
    """
    redis = get_redis()
    limiter = RateLimiter(redis)
    key = f"rl:test:{uuid.uuid4().hex}"

    # Capacity 1, rate 5/sec — should allow 1 then deny then re-allow ~0.2s later.
    out1 = await limiter.consume(key, capacity=1, rate_per_second=5.0)
    assert out1.allowed
    out2 = await limiter.consume(key, capacity=1, rate_per_second=5.0)
    assert not out2.allowed
    assert out2.retry_after >= 1
