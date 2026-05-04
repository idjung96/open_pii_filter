# SYNTHETIC DATA - NOT REAL PII
"""Phase 8 — Prometheus exporter (T8.4).

Covers:
* The default registry exposes the Phase 8 counters/histograms after a
  detect call.
* ``GET /v1/admin/metrics`` is gated by ``require_admin`` (admin key +
  IP allowlist).
* The exposition response uses the Prometheus text content type.
"""

from __future__ import annotations

import time
import uuid
from typing import TYPE_CHECKING

import pytest
from sqlalchemy import text

from app.config import Settings, get_settings
from app.security.api_key import issue_api_key
from app.security.hmac_auth import compute_signature
from app.security.rate_limit import get_redis

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession


def _settings_with(**overrides):  # type: ignore[no-untyped-def]
    base = Settings().model_dump()
    base.update(overrides)
    return Settings(**base)


def _patch_admin_allowlist(monkeypatch: pytest.MonkeyPatch, *, allowlist: str) -> None:
    """Re-target every importer of get_settings so they see the allowlist."""
    fake = lambda: _settings_with(admin_ip_allowlist=allowlist)  # noqa: E731
    monkeypatch.setattr("app.config.get_settings", fake)
    import app.api.admin_audit as adm_mod
    import app.main as main_mod

    monkeypatch.setattr(adm_mod, "get_settings", fake)
    monkeypatch.setattr(main_mod, "get_settings", fake)


def _admin_app(monkeypatch: pytest.MonkeyPatch):  # type: ignore[no-untyped-def]
    """Re-import main so the conditional admin_audit/admin_stats routers attach."""
    _patch_admin_allowlist(monkeypatch, allowlist="127.0.0.0/8")
    import importlib

    import app.main as main_mod
    importlib.reload(main_mod)
    fake = lambda: _settings_with(admin_ip_allowlist="127.0.0.0/8")  # noqa: E731
    monkeypatch.setattr(main_mod, "get_settings", fake)
    import app.api.admin_audit as adm_mod
    monkeypatch.setattr(adm_mod, "get_settings", fake)
    return main_mod.app


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


def _signed_headers(
    *, key_id: str, secret: str, path: str, body: bytes = b""
) -> dict[str, str]:
    ts = str(int(time.time()))
    n = uuid.uuid4().hex
    sig = compute_signature(
        secret=secret, timestamp=ts, nonce=n, method="GET", path=path, body=body,
    )
    return {
        "X-API-Key": key_id,
        "X-Timestamp": ts,
        "X-Nonce": n,
        "X-Signature": sig,
    }


# ── T8.4: counters increment on detect calls ──────────────────────────────
async def test_t8_4_metrics_counters_present_after_detect(
    monkeypatch: pytest.MonkeyPatch,
    admin_key: tuple[str, str],
) -> None:
    """A successful detect call followed by GET /v1/admin/metrics returns
    Prometheus exposition text containing the Phase 8 counter names."""
    from httpx import ASGITransport, AsyncClient

    from app.security.auth import require_auth

    def _stub_caller():  # type: ignore[no-untyped-def]
        from app.security.hmac_auth import AuthedCaller

        return AuthedCaller(
            key_id="metrics-stub",
            name="pytest",
            rate_per_minute=10_000,
            rate_per_hour=10_000_000,
            ip_allowlist=None,
            client_ip="127.0.0.1",
        )

    key_id, secret = admin_key
    app = _admin_app(monkeypatch)

    # Stub auth so the detect call doesn't need HMAC (we still hit the
    # real admin gate on /v1/admin/metrics below).
    app.dependency_overrides[require_auth] = _stub_caller
    try:
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as c:
            # 1. Trigger one detect to populate http_requests_total.
            payload = {
                "request_id": str(uuid.uuid4()),
                "post": {"board_id": "g", "title": "x", "body": "y"},
                "author": {"name": "x", "ip": "127.0.0.1"},
            }
            r = await c.post("/v1/detect/post", json=payload)
            assert r.status_code == 200
    finally:
        app.dependency_overrides.pop(require_auth, None)

    # 2. GET /v1/admin/metrics — admin key + 127.0.0.1 in allowlist.
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as c:
        path = "/v1/admin/metrics"
        headers = _signed_headers(key_id=key_id, secret=secret, path=path)
        resp = await c.get(path, headers=headers)
    assert resp.status_code == 200, resp.text
    assert resp.headers["content-type"].startswith("text/plain")
    body_text = resp.text
    # Default process metrics shipped by prometheus_client.
    assert "process_cpu_seconds_total" in body_text
    # Our custom counters / histogram (HELP lines must be present even
    # for buckets that have not yet recorded a sample because we already
    # bumped at least one entry above).
    assert "http_requests_total" in body_text
    assert "http_request_duration_seconds" in body_text
    assert "pii_detections_total" in body_text
    assert "extraction_jobs_total" in body_text
    assert "feedback_total" in body_text
    assert "rate_limit_rejections_total" in body_text


# ── Gate: non-admin caller → 403 ──────────────────────────────────────────
async def test_metrics_endpoint_rejects_non_admin(
    monkeypatch: pytest.MonkeyPatch,
    db_session: AsyncSession,
) -> None:
    """Non-admin API key against /v1/admin/metrics → 403 REQ-4015."""
    from httpx import ASGITransport, AsyncClient
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

    try:
        app = _admin_app(monkeypatch)
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as c:
            path = "/v1/admin/metrics"
            headers = _signed_headers(key_id=key_id, secret=secret, path=path)
            resp = await c.get(path, headers=headers)
        assert resp.status_code == 403
        assert resp.json()["code"] == "REQ-4015"
    finally:
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
