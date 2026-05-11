"""Phase 3 — T3.8 IP allowlist 회귀 방지.

`is_allowed()` 헬퍼와 endpoint 단의 통합 검증을 함께 다룬다:

  - 헬퍼 단위 — CIDR 매칭 / 전역 allowlist / 둘 다 적용 시 AND 조건
  - 엔드포인트 단 — 키 단위 allowlist 에 없는 IP 호출은 403 REQ-4015

IP allowlist 가 깨지면 ① 무관한 호출자가 API 를 사용하거나 (보안 사고)
② 의도된 호출자가 막혀 운영이 중단되는 두 방향의 회귀가 모두 가능하다.
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
from app.security.ip_allowlist import is_allowed
from app.security.rate_limit import get_redis

if TYPE_CHECKING:
    from httpx import AsyncClient


def test_is_allowed_cidr_match() -> None:
    """키 단위 allowlist 의 CIDR 매칭 — `10.0.0.0/24` 안의 IP 만 통과."""
    assert is_allowed("10.0.0.5", key_allowlist=["10.0.0.0/24"])
    assert not is_allowed("10.0.1.5", key_allowlist=["10.0.0.0/24"])


def test_is_allowed_global_only() -> None:
    """전역 allowlist 만 설정됐을 때 (키 단위 allowlist 없음) — 전역만 만족하면 통과."""
    assert is_allowed("192.168.1.1", global_allowlist=["192.168.0.0/16"])
    assert not is_allowed("10.0.0.1", global_allowlist=["192.168.0.0/16"])


def test_is_allowed_both_must_pass() -> None:
    """전역 + 키 단위 allowlist 가 함께 있으면 둘 다 만족해야 통과 (AND).

    전역 only-allow 만 보고 키 제약을 무시하는 회귀 방지 — 핵심 권한 분리.
    """
    # 전역은 허용하지만 키 단위가 더 엄격한 경우.
    assert not is_allowed(
        "192.168.1.1",
        global_allowlist=["192.168.0.0/16"],
        key_allowlist=["10.0.0.0/24"],
    )


@pytest.fixture
async def restricted_key():
    """`10.99.99.99/32` 만 허용하는 API 키 — 테스트 클라이언트 IP (127.0.0.1) 와 불일치.

    의도적으로 호출 IP 가 키 allowlist 밖에 있도록 구성해 거절 경로를 확인.
    fixture cleanup 으로 DB row + Redis 카운터 모두 정리.
    """
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
    from sqlalchemy.pool import NullPool

    engine = create_async_engine(get_settings().database_url, poolclass=NullPool, future=True)
    sm = async_sessionmaker(engine, expire_on_commit=False)
    async with sm() as s:
        row, secret = await issue_api_key(
            s,
            name=f"ip-{uuid.uuid4().hex[:6]}",
            rate_per_minute=10_000,
            rate_per_hour=10_000_000,
            ip_allowlist=["10.99.99.99/32"],
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


async def test_t3_8_ip_outside_allowlist_403(
    client_anon: AsyncClient,
    restricted_key: tuple[str, str],
) -> None:
    """allowlist 밖 IP 에서 정상 HMAC 으로 호출해도 403 REQ-4015 반환.

    HMAC 자체는 유효하므로 401 (REQ-4010) 이 아니라 403 (REQ-4015) 으로 떨어
    져야 한다 — 운영자가 두 상황을 코드만 봐도 구별 가능해야 디버깅 가능.
    """
    key_id, secret = restricted_key
    body = (
        b'{"request_id":"00000000-0000-0000-0000-000000000aaa",'
        b'"post":{"board_id":"g","title":"x","body":"y"},'
        b'"author":{"name":"x","ip":"127.0.0.1"}}'
    )
    resp = await client_anon.post(
        "/v1/detect/post",
        content=body,
        headers=_hdr(key_id, secret, body),
    )
    assert resp.status_code == 403
    assert resp.json()["code"] == "REQ-4015"
