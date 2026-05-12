"""Phase 3 — T3.10 100 RPS smoke 부하 테스트 (성공률 ≥ 99%).

ASGI 인-프로세스 클라이언트로 실제 네트워크 없이 인증 + 분석기 핫패스를
측정한다. "100 RPS / 99% 성공" 은 스펙 최저선이며 실제 머신 처리량은
훨씬 높다. CI 환경 노이즈에 의해 가끔 1% 미만이 실패해도 견딜 수 있도록
허용 마진을 살짝 두고, 이 단위 미달 시 즉시 실패해 회귀 알람을 띄운다.
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
    """부하 테스트 전용 고-rate API 키 발급 (테스트가 rate-limit 에 막히지 않게).

    분당/시간당 한도를 매우 크게 잡은 임시 키를 새로 만들어 yield 하고, 끝나면
    DB row + Redis 카운터까지 명시적으로 정리한다. 같은 키가 다른 테스트의
    nonce 캐시에 남으면 안 되므로 cleanup 이 중요.
    """
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
    from sqlalchemy.pool import NullPool

    engine = create_async_engine(get_settings().database_url, poolclass=NullPool, future=True)
    sm = async_sessionmaker(engine, expire_on_commit=False)
    async with sm() as s:
        row, secret = await issue_api_key(
            s,
            name=f"load-{uuid.uuid4().hex[:6]}",
            rate_per_minute=100_000,
            rate_per_hour=10_000_000,
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


@pytest.mark.slow
async def test_t3_10_100rps_above_99pct_success(
    client_anon: AsyncClient,
    burst_key: tuple[str, str],
) -> None:
    """100건을 동시에 발사해 성공률이 99% 이상인지 확인한다.

    `asyncio.gather` 로 한 번에 100 요청을 보내고 최종 status 통계를 집계.
    성공 = HTTP 200. 1% 이상 실패 시 어느 상태가 떨어졌는지 메시지에 포함해
    디버깅에 도움. `slow` 마커가 붙어 평소 단위 실행에서는 제외된다.
    """
    key_id, secret = burst_key
    target = 100  # 100건을 ~1초에 처리 = 100 RPS
    body_template = (
        b'{"request_id":"%s","post":{"board_id":"g","title":"x","body":"y"},'
        b'"author":{"name":"x","ip":"127.0.0.1"}}'
    )

    async def one() -> int:
        ts = str(int(time.time()))
        n = uuid.uuid4().hex
        body = body_template % str(uuid.uuid4()).encode()
        sig = compute_signature(
            secret=secret,
            timestamp=ts,
            nonce=n,
            method="POST",
            path="/v1/detect/post",
            body=body,
        )
        headers = {
            "X-API-Key": key_id,
            "X-Timestamp": ts,
            "X-Nonce": n,
            "X-Signature": sig,
            "content-type": "application/json",
        }
        r = await client_anon.post("/v1/detect/post", content=body, headers=headers)
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
        f"success rate {success_pct:.2%} < 99%; statuses: {sorted(set(statuses))}"
    )
