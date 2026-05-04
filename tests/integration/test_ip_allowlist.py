"""Phase 3 — T3.8 IP allowlist."""

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
    assert is_allowed("10.0.0.5", key_allowlist=["10.0.0.0/24"])
    assert not is_allowed("10.0.1.5", key_allowlist=["10.0.0.0/24"])


def test_is_allowed_global_only() -> None:
    assert is_allowed("192.168.1.1", global_allowlist=["192.168.0.0/16"])
    assert not is_allowed("10.0.0.1", global_allowlist=["192.168.0.0/16"])


def test_is_allowed_both_must_pass() -> None:
    # Global allows but per-key restricts further.
    assert not is_allowed(
        "192.168.1.1",
        global_allowlist=["192.168.0.0/16"],
        key_allowlist=["10.0.0.0/24"],
    )


@pytest.fixture
async def restricted_key():
    """Key allowlist accepts only 10.99.99.99 — the test client IP is 127.0.0.1."""
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
