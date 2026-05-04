# SYNTHETIC DATA - NOT REAL PII
"""Phase 7 — admin stats endpoints (T7.5).

Covers:
  - GET /v1/admin/stats/detections returns counts grouped by entity_type
  - GET /v1/admin/stats/verdicts returns block/warn/pass ratios
  - GET /v1/admin/stats/feedback returns counts grouped by original_code
  - non-admin caller → 403 REQ-4015
  - empty admin_ip_allowlist → router not mounted (404)
"""

from __future__ import annotations

import time
import uuid
from typing import TYPE_CHECKING

import pytest
from sqlalchemy import text

from app.config import Settings, get_settings
from app.db.crud import insert_audit_event, insert_feedback
from app.db.session import get_sessionmaker
from app.security.api_key import issue_api_key
from app.security.hmac_auth import compute_signature
from app.security.rate_limit import get_redis

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession


def _settings_with(**overrides):  # type: ignore[no-untyped-def]
    base = Settings().model_dump()
    base.update(overrides)
    return Settings(**base)


@pytest.fixture
async def clean_state() -> None:
    sm = get_sessionmaker()
    async with sm() as s:
        await s.execute(text("DELETE FROM pii.pii_feedback"))
        await s.execute(text("SET LOCAL app.bypass_audit_lock = 'on'"))
        await s.execute(text("DELETE FROM pii.audit_events"))
        await s.commit()
    yield


@pytest.fixture
async def admin_key(db_session: AsyncSession) -> tuple[str, str]:
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
    from sqlalchemy.pool import NullPool

    engine = create_async_engine(
        get_settings().database_url, poolclass=NullPool, future=True
    )
    sm = async_sessionmaker(engine, expire_on_commit=False)
    async with sm() as s:
        row, secret = await issue_api_key(
            s,
            name=f"pytest-admin-{uuid.uuid4().hex[:6]}",
            rate_per_minute=10_000,
            rate_per_hour=10_000_000,
            created_by="pytest",
            is_admin=True,
        )
        await s.commit()
        key_id = row.key_id
    yield key_id, secret
    async with sm() as s:
        await s.execute(
            text("DELETE FROM pii.api_keys WHERE key_id = :k"), {"k": key_id}
        )
        await s.execute(
            text("DELETE FROM pii.api_key_nonces WHERE key_id = :k"),
            {"k": key_id},
        )
        await s.commit()
    r = get_redis()
    await r.delete(f"rl:apikey:{key_id}:m", f"rl:apikey:{key_id}:h")


@pytest.fixture
async def non_admin_key(db_session: AsyncSession) -> tuple[str, str]:
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
    from sqlalchemy.pool import NullPool

    engine = create_async_engine(
        get_settings().database_url, poolclass=NullPool, future=True
    )
    sm = async_sessionmaker(engine, expire_on_commit=False)
    async with sm() as s:
        row, secret = await issue_api_key(
            s,
            name=f"pytest-nonadmin-{uuid.uuid4().hex[:6]}",
            rate_per_minute=10_000,
            rate_per_hour=10_000_000,
            created_by="pytest",
            is_admin=False,
        )
        await s.commit()
        key_id = row.key_id
    yield key_id, secret
    async with sm() as s:
        await s.execute(
            text("DELETE FROM pii.api_keys WHERE key_id = :k"), {"k": key_id}
        )
        await s.execute(
            text("DELETE FROM pii.api_key_nonces WHERE key_id = :k"),
            {"k": key_id},
        )
        await s.commit()
    r = get_redis()
    await r.delete(f"rl:apikey:{key_id}:m", f"rl:apikey:{key_id}:h")


def _signed_headers(
    *, key_id: str, secret: str, path: str, body: bytes = b"",
) -> dict[str, str]:
    ts = str(int(time.time()))
    n = uuid.uuid4().hex
    sig = compute_signature(
        secret=secret, timestamp=ts, nonce=n,
        method="GET", path=path, body=body,
    )
    return {
        "X-API-Key": key_id,
        "X-Timestamp": ts,
        "X-Nonce": n,
        "X-Signature": sig,
    }


def _patch_admin_allowlist(
    monkeypatch: pytest.MonkeyPatch, *, allowlist: str
) -> None:
    fake = lambda: _settings_with(admin_ip_allowlist=allowlist)  # noqa: E731
    monkeypatch.setattr("app.config.get_settings", fake)
    import app.api.admin_audit as adm_aud
    import app.api.admin_stats as adm_stats
    import app.main as main_mod

    monkeypatch.setattr(adm_aud, "get_settings", fake)
    monkeypatch.setattr(adm_stats, "get_settings", fake, raising=False)
    monkeypatch.setattr(main_mod, "get_settings", fake)


def _admin_app(monkeypatch: pytest.MonkeyPatch):  # type: ignore[no-untyped-def]
    _patch_admin_allowlist(monkeypatch, allowlist="127.0.0.0/8")
    import importlib

    import app.main as main_mod
    importlib.reload(main_mod)
    fake = lambda: _settings_with(admin_ip_allowlist="127.0.0.0/8")  # noqa: E731
    monkeypatch.setattr(main_mod, "get_settings", fake)
    import app.api.admin_audit as adm_aud
    import app.api.admin_stats as adm_stats
    monkeypatch.setattr(adm_aud, "get_settings", fake)
    monkeypatch.setattr(adm_stats, "get_settings", fake, raising=False)
    return main_mod.app


def _no_admin_app(monkeypatch: pytest.MonkeyPatch):  # type: ignore[no-untyped-def]
    _patch_admin_allowlist(monkeypatch, allowlist="")
    import importlib

    import app.main as main_mod
    importlib.reload(main_mod)
    fake = lambda: _settings_with(admin_ip_allowlist="")  # noqa: E731
    monkeypatch.setattr(main_mod, "get_settings", fake)
    return main_mod.app


# ── T7.5: detections stats with seeded data ────────────────────────────────
async def test_t7_5_detections_stats_returns_counts(
    monkeypatch: pytest.MonkeyPatch,
    admin_key: tuple[str, str],
    clean_state: None,
) -> None:
    from httpx import ASGITransport, AsyncClient

    sm = get_sessionmaker()
    # Seed 3 audit rows with detected_entity_types.
    async with sm() as s:
        for et in ("KR_RRN", "KR_RRN", "EMAIL_ADDRESS"):
            await insert_audit_event(
                s,
                request_id=str(uuid.uuid4()),
                api_key_id="seed",
                source_ip="127.0.0.1",
                method="POST",
                path="/v1/detect/post",
                http_status=200,
                response_code="WARN-1099",
                detected_entity_count=1,
                detected_entity_types=et,
            )

    key_id, secret = admin_key
    app = _admin_app(monkeypatch)
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as c:
        path = "/v1/admin/stats/detections"
        headers = _signed_headers(key_id=key_id, secret=secret, path=path)
        resp = await c.get(path, headers=headers)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    by_type: dict[str, int] = {}
    for b in body["buckets"]:
        by_type[b["entity_type"]] = by_type.get(b["entity_type"], 0) + b["count"]
    assert by_type.get("KR_RRN", 0) >= 2
    assert by_type.get("EMAIL_ADDRESS", 0) >= 1


async def test_t7_5_verdicts_stats(
    monkeypatch: pytest.MonkeyPatch,
    admin_key: tuple[str, str],
    clean_state: None,
) -> None:
    from httpx import ASGITransport, AsyncClient

    sm = get_sessionmaker()
    async with sm() as s:
        for code in ("BLOCK-2001", "WARN-1001", "OK-0000", "OK-0000"):
            await insert_audit_event(
                s,
                request_id=str(uuid.uuid4()),
                api_key_id="seed",
                source_ip="127.0.0.1",
                method="POST",
                path="/v1/detect/post",
                http_status=200,
                response_code=code,
            )

    key_id, secret = admin_key
    app = _admin_app(monkeypatch)
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as c:
        path = "/v1/admin/stats/verdicts"
        headers = _signed_headers(key_id=key_id, secret=secret, path=path)
        resp = await c.get(path, headers=headers)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["block"] >= 1
    assert body["warn"] >= 1
    assert body["pass"] >= 2


async def test_t7_5_feedback_stats(
    monkeypatch: pytest.MonkeyPatch,
    admin_key: tuple[str, str],
    clean_state: None,
) -> None:
    from httpx import ASGITransport, AsyncClient

    sm = get_sessionmaker()
    async with sm() as s:
        for code in ("BLOCK-2001", "BLOCK-2001", "WARN-1001"):
            await insert_feedback(
                s,
                request_id=str(uuid.uuid4()),
                original_code=code,
                reason="seed",
                reporter_hash="abc",
            )

    key_id, secret = admin_key
    app = _admin_app(monkeypatch)
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as c:
        path = "/v1/admin/stats/feedback"
        headers = _signed_headers(key_id=key_id, secret=secret, path=path)
        resp = await c.get(path, headers=headers)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["total"] >= 3
    assert body["by_code"].get("BLOCK-2001", 0) >= 2
    assert body["by_code"].get("WARN-1001", 0) >= 1


async def test_t7_5_non_admin_gets_403(
    monkeypatch: pytest.MonkeyPatch,
    non_admin_key: tuple[str, str],
) -> None:
    from httpx import ASGITransport, AsyncClient

    key_id, secret = non_admin_key
    app = _admin_app(monkeypatch)
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as c:
        path = "/v1/admin/stats/detections"
        headers = _signed_headers(key_id=key_id, secret=secret, path=path)
        resp = await c.get(path, headers=headers)
    assert resp.status_code == 403
    assert resp.json()["code"] == "REQ-4015"


async def test_t7_5_stats_not_mounted_when_allowlist_empty(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from httpx import ASGITransport, AsyncClient

    app = _no_admin_app(monkeypatch)
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as c:
        resp = await c.get("/v1/admin/stats/detections")
    assert resp.status_code == 404
