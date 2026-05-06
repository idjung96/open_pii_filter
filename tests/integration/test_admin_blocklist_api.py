# SYNTHETIC DATA - NOT REAL PII
"""Phase 4b — admin CRUD for `pii.attachment_blocklist` (T4b.1).

Verifies:
  - GET    /v1/admin/attachment-blocklist (admin-only, returns seeded rows)
  - POST   /v1/admin/attachment-blocklist (round-trips through the cache)
  - DELETE /v1/admin/attachment-blocklist/{id} (404 on missing, 204 on
    success, removes from cache)
  - non-admin caller → 403 REQ-4015
  - empty admin_ip_allowlist → router not mounted (404)
"""

from __future__ import annotations

import importlib
import time
import uuid
from typing import TYPE_CHECKING

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

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


@pytest.fixture
async def admin_key(db_session: AsyncSession) -> tuple[str, str]:
    engine = create_async_engine(get_settings().database_url, poolclass=NullPool, future=True)
    sm = async_sessionmaker(engine, expire_on_commit=False)
    async with sm() as s:
        row, secret = await issue_api_key(
            s,
            name=f"pytest-admin-blocklist-{uuid.uuid4().hex[:6]}",
            rate_per_minute=10_000,
            rate_per_hour=10_000_000,
            created_by="pytest",
            is_admin=True,
        )
        await s.commit()
        key_id = row.key_id
    yield key_id, secret
    async with sm() as s:
        await s.execute(text("DELETE FROM pii.api_keys WHERE key_id = :k"), {"k": key_id})
        await s.execute(
            text("DELETE FROM pii.api_key_nonces WHERE key_id = :k"),
            {"k": key_id},
        )
        await s.commit()
    r = get_redis()
    await r.delete(f"rl:apikey:{key_id}:m", f"rl:apikey:{key_id}:h")


@pytest.fixture
async def non_admin_key(db_session: AsyncSession) -> tuple[str, str]:
    engine = create_async_engine(get_settings().database_url, poolclass=NullPool, future=True)
    sm = async_sessionmaker(engine, expire_on_commit=False)
    async with sm() as s:
        row, secret = await issue_api_key(
            s,
            name=f"pytest-blocklist-noadmin-{uuid.uuid4().hex[:6]}",
            rate_per_minute=10_000,
            rate_per_hour=10_000_000,
            created_by="pytest",
            is_admin=False,
        )
        await s.commit()
        key_id = row.key_id
    yield key_id, secret
    async with sm() as s:
        await s.execute(text("DELETE FROM pii.api_keys WHERE key_id = :k"), {"k": key_id})
        await s.execute(
            text("DELETE FROM pii.api_key_nonces WHERE key_id = :k"),
            {"k": key_id},
        )
        await s.commit()


def _signed_headers(
    *,
    key_id: str,
    secret: str,
    method: str,
    path: str,
    body: bytes = b"",
) -> dict[str, str]:
    ts = str(int(time.time()))
    n = uuid.uuid4().hex
    sig = compute_signature(
        secret=secret,
        timestamp=ts,
        nonce=n,
        method=method,
        path=path,
        body=body,
    )
    return {
        "X-API-Key": key_id,
        "X-Timestamp": ts,
        "X-Nonce": n,
        "X-Signature": sig,
    }


def _patch_admin_settings(monkeypatch: pytest.MonkeyPatch, *, allowlist: str) -> None:
    fake = lambda: _settings_with(admin_ip_allowlist=allowlist)  # noqa: E731
    monkeypatch.setattr("app.config.get_settings", fake)
    import app.api.admin_audit as adm_aud
    import app.main as main_mod

    monkeypatch.setattr(adm_aud, "get_settings", fake)
    monkeypatch.setattr(main_mod, "get_settings", fake)


def _admin_app(monkeypatch: pytest.MonkeyPatch):  # type: ignore[no-untyped-def]
    _patch_admin_settings(monkeypatch, allowlist="127.0.0.0/8")
    import app.main as main_mod

    importlib.reload(main_mod)
    fake = lambda: _settings_with(admin_ip_allowlist="127.0.0.0/8")  # noqa: E731
    monkeypatch.setattr(main_mod, "get_settings", fake)
    import app.api.admin_audit as adm_aud

    monkeypatch.setattr(adm_aud, "get_settings", fake)
    return main_mod.app


def _no_admin_app(monkeypatch: pytest.MonkeyPatch):  # type: ignore[no-untyped-def]
    _patch_admin_settings(monkeypatch, allowlist="")
    import app.main as main_mod

    importlib.reload(main_mod)
    fake = lambda: _settings_with(admin_ip_allowlist="")  # noqa: E731
    monkeypatch.setattr(main_mod, "get_settings", fake)
    return main_mod.app


# ── T4b.1: list rows reflects the seeded blocklist ─────────────────────────
async def test_list_blocklist_returns_seeded_rows(
    monkeypatch: pytest.MonkeyPatch,
    admin_key: tuple[str, str],
) -> None:
    from httpx import ASGITransport, AsyncClient

    app_mod = _admin_app(monkeypatch)
    key_id, secret = admin_key
    path = "/v1/admin/attachment-blocklist"
    headers = _signed_headers(key_id=key_id, secret=secret, method="GET", path=path)
    async with AsyncClient(transport=ASGITransport(app=app_mod), base_url="http://test") as ac:
        resp = await ac.get(path, headers=headers)
    assert resp.status_code == 200, resp.text
    payload = resp.json()
    rows = payload["rows"]
    extensions = {r["extension"] for r in rows if r["extension"]}
    # The seed should at minimum contain HWP/HWPX and a couple of archives.
    assert {"hwp", "hwpx", "zip", "rar"}.issubset(extensions)


# ── T4b.2: POST adds a row, cache updates immediately ──────────────────────
async def test_post_adds_row_and_reloads_cache(
    monkeypatch: pytest.MonkeyPatch,
    admin_key: tuple[str, str],
) -> None:
    from httpx import ASGITransport, AsyncClient

    from app.core.blocklist_cache import is_blocked

    app_mod = _admin_app(monkeypatch)
    key_id, secret = admin_key
    path = "/v1/admin/attachment-blocklist"

    body = b'{"extension":"xyzzy42","reason":"pytest synthetic"}'
    headers = _signed_headers(key_id=key_id, secret=secret, method="POST", path=path, body=body)
    headers["Content-Type"] = "application/json"
    async with AsyncClient(transport=ASGITransport(app=app_mod), base_url="http://test") as ac:
        resp = await ac.post(path, headers=headers, content=body)
    assert resp.status_code == 201, resp.text
    new_id = resp.json()["id"]

    # Cache must reflect the new entry without a process restart.
    blocked, kind = is_blocked(filename="payload.xyzzy42", mime_type="application/octet-stream")
    assert blocked is True
    assert kind == "extension"

    # Cleanup — DELETE to leave the database tidy for following tests.
    del_path = f"/v1/admin/attachment-blocklist/{new_id}"
    headers = _signed_headers(key_id=key_id, secret=secret, method="DELETE", path=del_path)
    async with AsyncClient(transport=ASGITransport(app=app_mod), base_url="http://test") as ac:
        resp = await ac.delete(del_path, headers=headers)
    assert resp.status_code == 204, resp.text


# ── T4b.3: DELETE removes a row and unloads the cache entry ────────────────
async def test_delete_unloads_cache(
    monkeypatch: pytest.MonkeyPatch,
    admin_key: tuple[str, str],
) -> None:
    from httpx import ASGITransport, AsyncClient

    from app.core.blocklist_cache import is_blocked

    app_mod = _admin_app(monkeypatch)
    key_id, secret = admin_key
    path = "/v1/admin/attachment-blocklist"

    body = b'{"extension":"shred99","reason":"pytest delete-test"}'
    headers = _signed_headers(key_id=key_id, secret=secret, method="POST", path=path, body=body)
    headers["Content-Type"] = "application/json"
    async with AsyncClient(transport=ASGITransport(app=app_mod), base_url="http://test") as ac:
        post = await ac.post(path, headers=headers, content=body)
    assert post.status_code == 201
    new_id = post.json()["id"]

    blocked_before, _ = is_blocked(filename="x.shred99", mime_type="application/octet-stream")
    assert blocked_before is True

    del_path = f"/v1/admin/attachment-blocklist/{new_id}"
    headers = _signed_headers(key_id=key_id, secret=secret, method="DELETE", path=del_path)
    async with AsyncClient(transport=ASGITransport(app=app_mod), base_url="http://test") as ac:
        resp = await ac.delete(del_path, headers=headers)
    assert resp.status_code == 204, resp.text

    blocked_after, _ = is_blocked(filename="x.shred99", mime_type="application/octet-stream")
    assert blocked_after is False


# ── T4b.4: DELETE on missing row → 404 ─────────────────────────────────────
async def test_delete_missing_row_returns_404(
    monkeypatch: pytest.MonkeyPatch,
    admin_key: tuple[str, str],
) -> None:
    from httpx import ASGITransport, AsyncClient

    app_mod = _admin_app(monkeypatch)
    key_id, secret = admin_key
    del_path = "/v1/admin/attachment-blocklist/9999999"
    headers = _signed_headers(key_id=key_id, secret=secret, method="DELETE", path=del_path)
    async with AsyncClient(transport=ASGITransport(app=app_mod), base_url="http://test") as ac:
        resp = await ac.delete(del_path, headers=headers)
    assert resp.status_code == 404, resp.text


# ── T4b.5: non-admin → REQ-4015 ────────────────────────────────────────────
async def test_non_admin_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
    non_admin_key: tuple[str, str],
) -> None:
    from httpx import ASGITransport, AsyncClient

    app_mod = _admin_app(monkeypatch)
    key_id, secret = non_admin_key
    path = "/v1/admin/attachment-blocklist"
    headers = _signed_headers(key_id=key_id, secret=secret, method="GET", path=path)
    async with AsyncClient(transport=ASGITransport(app=app_mod), base_url="http://test") as ac:
        resp = await ac.get(path, headers=headers)
    assert resp.status_code == 403, resp.text
    body = resp.json()
    assert body["code"] == "REQ-4015"


# ── T4b.6: empty admin_ip_allowlist → router not mounted ───────────────────
async def test_router_not_mounted_when_allowlist_empty(
    monkeypatch: pytest.MonkeyPatch,
    admin_key: tuple[str, str],
) -> None:
    from httpx import ASGITransport, AsyncClient

    app_mod = _no_admin_app(monkeypatch)
    key_id, secret = admin_key
    path = "/v1/admin/attachment-blocklist"
    headers = _signed_headers(key_id=key_id, secret=secret, method="GET", path=path)
    async with AsyncClient(transport=ASGITransport(app=app_mod), base_url="http://test") as ac:
        resp = await ac.get(path, headers=headers)
    assert resp.status_code == 404, resp.text
