"""Phase 3 — HMAC 인증 통합 테스트 회귀 방지 (T3.1~T3.6).

신규 API 키를 발급한 뒤 ``client_anon`` (require_auth 우회 없음) 으로 모든
실패 경로를 검증한다. 보안 게이트가 의도된 코드와 매핑되는지 정확히 핀
(pin) 해야 운영자가 응답 코드만 보고 즉시 원인 파악 가능.

검증 경로:
  - T3.1 — 정상 HMAC → 200
  - T3.2 — 서명 위조 → 401 REQ-4010
  - T3.3 — timestamp 5분+ 차이 → 401 REQ-4012
  - T3.4 — 같은 (timestamp, nonce) 재전송 → 401 REQ-4013 (리플레이 방어)
  - T3.5 — X-API-Key 누락 → 401 REQ-4011
  - T3.6 — 폐기된 키 → 403 REQ-4014

Q1/Q3 후속 결정 메모:
- HMAC 키는 평문 시크릿 (SHA-256 wrapping 없음)
- 인증 실패 응답 body 는 flat envelope (`{"detail": ...}` 형식 미사용)
"""

from __future__ import annotations

import time
import uuid
from typing import TYPE_CHECKING

import pytest
from sqlalchemy import text

from app.config import get_settings
from app.security.api_key import issue_api_key, revoke
from app.security.hmac_auth import compute_signature
from app.security.rate_limit import get_redis

if TYPE_CHECKING:
    from httpx import AsyncClient
    from sqlalchemy.ext.asyncio import AsyncSession


def _payload(request_id: str | None = None) -> dict[str, object]:
    return {
        "request_id": request_id or str(uuid.uuid4()),
        "post": {"board_id": "general", "title": "x", "body": "오늘 날씨가 좋네요"},
        "author": {"name": "홍길동", "ip": "127.0.0.1"},
    }


@pytest.fixture
async def issued_key(db_session: AsyncSession) -> tuple[str, str]:
    """Issue a key in a *committed* transaction so the request handler
    (which uses its own session) can see it. Cleaned up at teardown."""
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
    from sqlalchemy.pool import NullPool

    engine = create_async_engine(get_settings().database_url, poolclass=NullPool, future=True)
    sm = async_sessionmaker(engine, expire_on_commit=False)
    async with sm() as s:
        row, secret = await issue_api_key(
            s,
            name=f"pytest-{uuid.uuid4().hex[:6]}",
            rate_per_minute=10_000,
            rate_per_hour=10_000_000,
            created_by="pytest",
        )
        await s.commit()
        key_id = row.key_id

    yield key_id, secret

    async with sm() as s:
        await s.execute(text("DELETE FROM pii.api_keys WHERE key_id = :k"), {"k": key_id})
        await s.execute(text("DELETE FROM pii.api_key_nonces WHERE key_id = :k"), {"k": key_id})
        await s.commit()
    r = get_redis()
    await r.delete(f"rl:apikey:{key_id}:m", f"rl:apikey:{key_id}:h")


def _build_headers(
    *,
    key_id: str,
    secret: str,
    body: bytes,
    path: str = "/v1/detect/post",
    ts: int | None = None,
    nonce: str | None = None,
) -> dict[str, str]:
    """Construct full header set the server expects (Q1: plaintext secret)."""
    ts_str = str(ts if ts is not None else int(time.time()))
    n = nonce or uuid.uuid4().hex
    sig = compute_signature(
        secret=secret,
        timestamp=ts_str,
        nonce=n,
        method="POST",
        path=path,
        body=body,
    )
    return {
        "X-API-Key": key_id,
        "X-Timestamp": ts_str,
        "X-Nonce": n,
        "X-Signature": sig,
        "content-type": "application/json",
    }


# ── T3.1: valid HMAC → 200 ────────────────────────────────────────────────
async def test_t3_1_valid_hmac_passes(
    client_anon: AsyncClient,
    issued_key: tuple[str, str],
) -> None:
    key_id, secret = issued_key
    body = (
        b'{"request_id":"00000000-0000-0000-0000-000000000001",'
        b'"post":{"board_id":"g","title":"x","body":"\\u050c"},'
        b'"author":{"name":"x","ip":"127.0.0.1"}}'
    )
    headers = _build_headers(key_id=key_id, secret=secret, body=body)
    resp = await client_anon.post("/v1/detect/post", content=body, headers=headers)
    assert resp.status_code == 200, resp.text


# ── T3.2: bad signature → 401 (REQ-4010) ──────────────────────────────────
async def test_t3_2_bad_signature_401(
    client_anon: AsyncClient,
    issued_key: tuple[str, str],
) -> None:
    key_id, secret = issued_key
    body = b"{}"
    headers = _build_headers(key_id=key_id, secret=secret, body=body)
    headers["X-Signature"] = "0" * 64
    resp = await client_anon.post("/v1/detect/post", content=body, headers=headers)
    assert resp.status_code == 401
    assert resp.json()["code"] == "REQ-4010"


# ── T3.3: timestamp >5min off → 401 (REQ-4012) ────────────────────────────
async def test_t3_3_timestamp_out_of_window_401(
    client_anon: AsyncClient,
    issued_key: tuple[str, str],
) -> None:
    key_id, secret = issued_key
    body = b"{}"
    headers = _build_headers(
        key_id=key_id,
        secret=secret,
        body=body,
        ts=int(time.time()) - 6 * 60,
    )
    resp = await client_anon.post("/v1/detect/post", content=body, headers=headers)
    assert resp.status_code == 401
    assert resp.json()["code"] == "REQ-4012"


# ── T3.4: same (timestamp, nonce) replay → 401 (REQ-4013) ─────────────────
async def test_t3_4_replay_blocked_401(
    client_anon: AsyncClient,
    issued_key: tuple[str, str],
) -> None:
    key_id, secret = issued_key
    body = (
        b'{"request_id":"00000000-0000-0000-0000-00000000abcd",'
        b'"post":{"board_id":"g","title":"x","body":"y"},'
        b'"author":{"name":"x","ip":"127.0.0.1"}}'
    )
    headers = _build_headers(key_id=key_id, secret=secret, body=body)

    r1 = await client_anon.post("/v1/detect/post", content=body, headers=headers)
    assert r1.status_code == 200
    r2 = await client_anon.post("/v1/detect/post", content=body, headers=headers)
    assert r2.status_code == 401
    assert r2.json()["code"] == "REQ-4013"


# ── T3.5: missing X-API-Key → 401 (REQ-4011) ──────────────────────────────
async def test_t3_5_missing_api_key_401(client_anon: AsyncClient) -> None:
    resp = await client_anon.post(
        "/v1/detect/post",
        json=_payload(),
        headers={
            "X-Timestamp": str(int(time.time())),
            "X-Nonce": uuid.uuid4().hex,
            "X-Signature": "0" * 64,
        },
    )
    assert resp.status_code == 401
    assert resp.json()["code"] == "REQ-4011"


# ── T3.6: revoked key → 403 (REQ-4014) ────────────────────────────────────
async def test_t3_6_revoked_key_403(
    client_anon: AsyncClient,
    issued_key: tuple[str, str],
) -> None:
    key_id, secret = issued_key
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
    from sqlalchemy.pool import NullPool

    engine = create_async_engine(get_settings().database_url, poolclass=NullPool, future=True)
    sm = async_sessionmaker(engine, expire_on_commit=False)
    async with sm() as s:
        await revoke(s, key_id)
        await s.commit()

    body = b"{}"
    headers = _build_headers(key_id=key_id, secret=secret, body=body)
    resp = await client_anon.post("/v1/detect/post", content=body, headers=headers)
    assert resp.status_code == 403
    assert resp.json()["code"] == "REQ-4014"
