# SYNTHETIC DATA - NOT REAL PII
"""Phase 6 — `audit_events` 삽입 + append-only 트리거 + 운영자 API 회귀 방지.

감사 로그 인프라의 핵심 보장을 한 모듈에서 검증한다:

  - T6.4 — 모든 요청마다 audit_events row 가 정확히 1건 기록됨
  - T6.5 — BEFORE UPDATE/DELETE 트리거가 통상 INSERT 외 변경을 거절
  - T6.5b — 단, `SET LOCAL app.bypass_audit_lock = 'on'` 가 켜진 cleanup
    워커는 1년 retention GC 를 위해 DELETE 가능
  - 운영자 API 게이트 — `is_admin` 체크 + IP allowlist + 빈 allowlist 시
    라우터 비마운트 + 페이지네이션 동작 확인

audit 행을 사후 변조하지 못하게 막는 트리거가 핵심 컴플라이언스 가드 —
회귀 시 ISMS-P 심사 통과 불가.
"""

from __future__ import annotations

import asyncio
import time
import uuid
from typing import TYPE_CHECKING

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from app.config import Settings, get_settings
from app.db.crud import (
    cleanup_expired_audit_events,
    insert_audit_event,
    list_audit_events,
)
from app.db.session import get_sessionmaker
from app.security.api_key import issue_api_key
from app.security.hmac_auth import compute_signature
from app.security.rate_limit import get_redis

if TYPE_CHECKING:
    from httpx import AsyncClient
    from sqlalchemy.ext.asyncio import AsyncSession


def _settings_with(**overrides):  # type: ignore[no-untyped-def]
    base = Settings().model_dump()
    base.update(overrides)
    return Settings(**base)


@pytest.fixture
async def clean_audit() -> None:
    """Wipe audit_events for a fresh slate (uses cleanup helper to bypass triggers)."""
    sm = get_sessionmaker()
    async with sm() as session:
        await cleanup_expired_audit_events(session, retention_days=0)
    yield
    async with sm() as session:
        await cleanup_expired_audit_events(session, retention_days=0)


# ── T6.4: audit row inserted per detect call ──────────────────────────────
async def test_t6_4_detect_request_records_audit_row(
    client: AsyncClient,
    clean_audit: None,
) -> None:
    request_id = str(uuid.uuid4())
    payload = {
        "request_id": request_id,
        "post": {"board_id": "general", "title": "x", "body": "오늘 날씨가 좋네요"},
        "author": {"name": "홍길동", "ip": "127.0.0.1"},
    }
    resp = await client.post("/v1/detect/post", json=payload)
    assert resp.status_code == 200

    # Audit row write is fire-and-forget; let the event loop drain.
    for _ in range(50):
        sm = get_sessionmaker()
        async with sm() as session:
            rows = await list_audit_events(session, request_id=request_id, limit=10)
        if rows:
            break
        await asyncio.sleep(0.05)

    assert len(rows) >= 1, "audit row not recorded"
    row = rows[0]
    assert row.request_id == request_id
    assert row.method == "POST"
    assert row.path == "/v1/detect/post"
    assert row.http_status == 200
    assert row.response_code is not None
    assert row.body_hash is not None and len(row.body_hash) == 64


# ── T6.5: UPDATE / DELETE without bypass is rejected ──────────────────────
async def test_t6_5_audit_log_is_append_only() -> None:
    """Each mutation uses its own session because Postgres aborts the
    transaction on RAISE EXCEPTION; we need a fresh tx for the next try.
    """
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
    from sqlalchemy.pool import NullPool

    engine = create_async_engine(get_settings().database_url, poolclass=NullPool, future=True)
    sm = async_sessionmaker(engine, expire_on_commit=False)

    # Insert one row.
    async with sm() as s:
        row = await insert_audit_event(
            s,
            request_id=str(uuid.uuid4()),
            api_key_id="k_test",
            source_ip="127.0.0.1",
            method="POST",
            path="/v1/detect/post",
            http_status=200,
            response_code="OK-0000",
            detected_entity_count=0,
        )
        inserted_id = row.id

    # UPDATE must fail (its own session/transaction).
    async with sm() as s:
        with pytest.raises(DBAPIError):
            await s.execute(
                text("UPDATE pii.audit_events SET response_code = 'TAMPERED' WHERE id = :id"),
                {"id": inserted_id},
            )
            await s.commit()

    # DELETE must fail (its own session/transaction, no bypass).
    async with sm() as s:
        with pytest.raises(DBAPIError):
            await s.execute(
                text("DELETE FROM pii.audit_events WHERE id = :id"),
                {"id": inserted_id},
            )
            await s.commit()

    # Cleanup the row using the bypass.
    async with sm() as s:
        await s.execute(text("SET LOCAL app.bypass_audit_lock = 'on'"))
        await s.execute(
            text("DELETE FROM pii.audit_events WHERE id = :id"),
            {"id": inserted_id},
        )
        await s.commit()
    await engine.dispose()


# ── T6.5b: cleanup worker can DELETE under app.bypass_audit_lock ──────────
async def test_t6_5b_cleanup_can_delete(db_session: AsyncSession) -> None:
    # Insert a row that's already older than retention.
    await insert_audit_event(
        db_session,
        request_id=str(uuid.uuid4()),
        api_key_id="k_old",
        source_ip="127.0.0.1",
        method="GET",
        path="/v1/old",
        http_status=200,
        response_code="OK-0000",
    )

    # Force occurred_at to a past date by raw UPDATE — but UPDATE is
    # blocked by the trigger, so we use bypass first.
    await db_session.execute(text("SET LOCAL app.bypass_audit_lock = 'on'"))
    await db_session.execute(
        text(
            "UPDATE pii.audit_events SET occurred_at = now() - interval '500 days' "
            "WHERE api_key_id = 'k_old'"
        )
    )
    await db_session.commit()

    # cleanup_expired_audit_events with 30-day retention should drop the row.
    deleted = await cleanup_expired_audit_events(db_session, retention_days=30)
    assert deleted >= 1


# ── T6.4-extra: admin endpoint integration (mount + auth) ─────────────────
@pytest.fixture
async def admin_mode(monkeypatch: pytest.MonkeyPatch) -> Settings:
    """Re-mount the FastAPI app with admin allowlist enabled."""
    monkeypatch.setattr(
        "app.config.get_settings",
        lambda: _settings_with(admin_ip_allowlist="127.0.0.0/8"),
    )
    return get_settings()


@pytest.fixture
async def admin_key(db_session: AsyncSession) -> tuple[str, str]:
    """Issue an is_admin=True key, committed, then clean up at teardown."""
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
    from sqlalchemy.pool import NullPool

    engine = create_async_engine(get_settings().database_url, poolclass=NullPool, future=True)
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
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
    from sqlalchemy.pool import NullPool

    engine = create_async_engine(get_settings().database_url, poolclass=NullPool, future=True)
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
        await s.execute(text("DELETE FROM pii.api_keys WHERE key_id = :k"), {"k": key_id})
        await s.execute(
            text("DELETE FROM pii.api_key_nonces WHERE key_id = :k"),
            {"k": key_id},
        )
        await s.commit()
    r = get_redis()
    await r.delete(f"rl:apikey:{key_id}:m", f"rl:apikey:{key_id}:h")


def _signed_headers(*, key_id: str, secret: str, path: str, body: bytes = b"") -> dict[str, str]:
    ts = str(int(time.time()))
    n = uuid.uuid4().hex
    sig = compute_signature(
        secret=secret,
        timestamp=ts,
        nonce=n,
        method="GET",
        path=path,
        body=body,
    )
    return {
        "X-API-Key": key_id,
        "X-Timestamp": ts,
        "X-Nonce": n,
        "X-Signature": sig,
    }


def _patch_admin_allowlist(monkeypatch: pytest.MonkeyPatch, *, allowlist: str) -> None:
    """Patch every module that already imported ``get_settings`` so the
    new allowlist value is observed everywhere.
    """
    fake = lambda: _settings_with(admin_ip_allowlist=allowlist)  # noqa: E731
    monkeypatch.setattr("app.config.get_settings", fake)
    # Re-target already-imported references.
    import app.api.admin_audit as adm_mod
    import app.main as main_mod

    monkeypatch.setattr(adm_mod, "get_settings", fake)
    monkeypatch.setattr(main_mod, "get_settings", fake)


def _admin_app(monkeypatch: pytest.MonkeyPatch):  # type: ignore[no-untyped-def]
    """Build a fresh FastAPI app instance with admin router mounted."""
    _patch_admin_allowlist(monkeypatch, allowlist="127.0.0.0/8")
    # Re-import main so the conditional include_router runs against the
    # patched settings.
    import importlib

    import app.main as main_mod

    importlib.reload(main_mod)
    # The reloaded module re-imports get_settings, so re-patch.
    fake = lambda: _settings_with(admin_ip_allowlist="127.0.0.0/8")  # noqa: E731
    monkeypatch.setattr(main_mod, "get_settings", fake)
    import app.api.admin_audit as adm_mod

    monkeypatch.setattr(adm_mod, "get_settings", fake)
    return main_mod.app


def _no_admin_app(monkeypatch: pytest.MonkeyPatch):  # type: ignore[no-untyped-def]
    _patch_admin_allowlist(monkeypatch, allowlist="")
    import importlib

    import app.main as main_mod

    importlib.reload(main_mod)
    fake = lambda: _settings_with(admin_ip_allowlist="")  # noqa: E731
    monkeypatch.setattr(main_mod, "get_settings", fake)
    return main_mod.app


async def test_admin_endpoint_with_admin_key_returns_events(
    monkeypatch: pytest.MonkeyPatch,
    admin_key: tuple[str, str],
) -> None:
    """T6.4-extra: GET /v1/admin/audit-events with admin key + allowed IP."""
    from httpx import ASGITransport, AsyncClient

    key_id, secret = admin_key
    app = _admin_app(monkeypatch)

    # Insert one audit row directly so the response is non-empty.
    sm = get_sessionmaker()
    async with sm() as session:
        await insert_audit_event(
            session,
            request_id=str(uuid.uuid4()),
            api_key_id=key_id,
            source_ip="127.0.0.1",
            method="POST",
            path="/v1/detect/post",
            http_status=200,
            response_code="OK-0000",
        )

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        path = "/v1/admin/audit-events"
        headers = _signed_headers(key_id=key_id, secret=secret, path=path)
        resp = await c.get(path, headers=headers)
    assert resp.status_code == 200, resp.text
    payload = resp.json()
    assert "events" in payload
    assert isinstance(payload["events"], list)


async def test_admin_endpoint_with_non_admin_key_403(
    monkeypatch: pytest.MonkeyPatch,
    non_admin_key: tuple[str, str],
) -> None:
    """T6.4-extra2: same call with non-admin key → 403 REQ-4015."""
    from httpx import ASGITransport, AsyncClient

    key_id, secret = non_admin_key
    app = _admin_app(monkeypatch)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        path = "/v1/admin/audit-events"
        headers = _signed_headers(key_id=key_id, secret=secret, path=path)
        resp = await c.get(path, headers=headers)
    assert resp.status_code == 403
    assert resp.json()["code"] == "REQ-4015"


async def test_admin_endpoint_disallowed_ip_403(
    monkeypatch: pytest.MonkeyPatch,
    admin_key: tuple[str, str],
) -> None:
    """T6.4-extra3: admin key but IP outside admin_ip_allowlist → 403."""
    from httpx import ASGITransport, AsyncClient

    key_id, secret = admin_key
    # Boot with a /8 that DOES include 127.0.0.1 so the router mounts,
    # then narrow to a non-127 CIDR before the call.
    _patch_admin_allowlist(monkeypatch, allowlist="127.0.0.0/8")
    import importlib

    import app.main as main_mod

    importlib.reload(main_mod)
    app = main_mod.app

    # Now narrow the allowlist for the actual auth check.
    fake = lambda: _settings_with(admin_ip_allowlist="10.0.0.0/8")  # noqa: E731
    monkeypatch.setattr("app.config.get_settings", fake)
    import app.api.admin_audit as adm_mod

    monkeypatch.setattr(adm_mod, "get_settings", fake)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        path = "/v1/admin/audit-events"
        headers = _signed_headers(key_id=key_id, secret=secret, path=path)
        resp = await c.get(path, headers=headers)
    assert resp.status_code == 403
    assert resp.json()["code"] == "REQ-4015"


async def test_admin_endpoint_not_mounted_when_allowlist_empty(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """T6.4-extra4: empty admin_ip_allowlist → router not mounted → 404."""
    from httpx import ASGITransport, AsyncClient

    app = _no_admin_app(monkeypatch)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        resp = await c.get("/v1/admin/audit-events")
    assert resp.status_code == 404


async def test_admin_endpoint_pagination(
    monkeypatch: pytest.MonkeyPatch,
    admin_key: tuple[str, str],
    clean_audit: None,
) -> None:
    """T6.4-extra5: pagination with limit=2 returns next_cursor; following
    page contains the remaining rows.
    """
    from httpx import ASGITransport, AsyncClient

    # Seed 5 rows.
    sm = get_sessionmaker()
    async with sm() as session:
        for _ in range(5):
            await insert_audit_event(
                session,
                request_id=str(uuid.uuid4()),
                api_key_id="paging-test",
                source_ip="127.0.0.1",
                method="POST",
                path="/v1/detect/post",
                http_status=200,
                response_code="OK-0000",
            )

    key_id, secret = admin_key
    app = _admin_app(monkeypatch)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        # Page 1 — limit=2. HMAC canonical path excludes query string.
        path = "/v1/admin/audit-events"
        url1 = f"{path}?limit=2&api_key_id=paging-test"
        headers = _signed_headers(key_id=key_id, secret=secret, path=path)
        r1 = await c.get(url1, headers=headers)
        assert r1.status_code == 200, r1.text
        p1 = r1.json()
        assert len(p1["events"]) == 2
        assert p1["next_cursor"]

        # Page 2 — same limit + cursor (re-sign because nonce + timestamp differ).
        from urllib.parse import quote

        url2 = f"{path}?limit=2&api_key_id=paging-test&cursor={quote(p1['next_cursor'], safe='')}"
        headers2 = _signed_headers(key_id=key_id, secret=secret, path=path)
        r2 = await c.get(url2, headers=headers2)
        assert r2.status_code == 200, r2.text
        p2 = r2.json()
        assert len(p2["events"]) == 2
        # No event ids overlap.
        ids1 = {e["request_id"] for e in p1["events"]}
        ids2 = {e["request_id"] for e in p2["events"]}
        assert ids1.isdisjoint(ids2)
