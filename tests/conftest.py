"""Shared pytest fixtures."""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import TYPE_CHECKING

import pytest
from httpx import ASGITransport, AsyncClient

from app.main import app
from app.security.auth import require_auth
from app.security.hmac_auth import AuthedCaller

if TYPE_CHECKING:
    from presidio_analyzer import AnalyzerEngine
    from sqlalchemy.ext.asyncio import AsyncSession


def _stub_caller() -> AuthedCaller:
    """Auth bypass used by `client` so legacy detect-tests stay simple.

    Auth-specific tests use the `client_anon` fixture which clears the
    override and exercises the real require_auth dependency.
    """
    return AuthedCaller(
        key_id="test-stub",
        name="pytest",
        rate_per_minute=10_000,
        rate_per_hour=10_000_000,
        ip_allowlist=None,
        client_ip="127.0.0.1",
    )


@pytest.fixture(autouse=True)
async def _reset_caches_per_test() -> AsyncIterator[None]:
    """Loop-scoped session means engines and Redis clients can be cached
    across tests, but we still flush per-IP rate-limit state so failed-
    auth counters from one test don't leak into the next (Q2).
    """
    from app.security.rate_limit import get_redis

    r = get_redis()
    # Flush every per-IP bucket so each test starts from a clean slate.
    # ASGITransport's client.host is '127.0.0.1' under uvloop and
    # 'testclient' under the default loop, so we wildcard the suffix.
    keys = await r.keys("rl:ip:*:m")
    if keys:
        await r.delete(*keys)
    yield
    keys = await r.keys("rl:ip:*:m")
    if keys:
        await r.delete(*keys)


@pytest.fixture
async def client() -> AsyncIterator[AsyncClient]:
    """Async HTTP client with auth dependency overridden to a stub.

    Existing detect tests don't need to construct HMAC signatures.
    """
    app.dependency_overrides[require_auth] = _stub_caller
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            yield c
    finally:
        app.dependency_overrides.pop(require_auth, None)


@pytest.fixture
async def client_anon() -> AsyncIterator[AsyncClient]:
    """Client without the auth override — exercises the real dependency."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c


@pytest.fixture(scope="session")
def analyzer() -> AnalyzerEngine:
    """Session-scoped Presidio AnalyzerEngine (spaCy load ~1.5s)."""
    from app.core.analyzer import build_analyzer

    return build_analyzer()


@pytest.fixture
async def db_session() -> AsyncIterator[AsyncSession]:
    """Per-test AsyncSession that rolls back at the end for isolation.

    Builds a fresh NullPool engine per test to avoid event-loop reuse
    issues with asyncpg connections across pytest's function-scoped loops.
    """
    from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
    from sqlalchemy.pool import NullPool

    from app.config import get_settings

    engine = create_async_engine(get_settings().database_url, poolclass=NullPool, future=True)
    try:
        async with engine.connect() as conn:
            trans = await conn.begin()
            async with AsyncSession(bind=conn, expire_on_commit=False) as session:
                try:
                    yield session
                finally:
                    await session.close()
                    await trans.rollback()
    finally:
        await engine.dispose()
