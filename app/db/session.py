"""Async SQLAlchemy engine + session factory for the `pii` schema.

The async engine is used for runtime (`/v1/detect/post`) traffic. A sync
engine variant is also exposed for Alembic migrations and one-shot CLI
operations that don't need asyncio.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from functools import lru_cache

from sqlalchemy import Engine, create_engine
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.config import get_settings


@lru_cache(maxsize=1)
def get_async_engine() -> AsyncEngine:
    """Return a process-wide async engine bound to DATABASE_URL."""
    settings = get_settings()
    return create_async_engine(
        settings.database_url,
        pool_pre_ping=True,
        pool_size=10,
        max_overflow=20,
        future=True,
    )


@lru_cache(maxsize=1)
def get_sync_engine() -> Engine:
    """Return a process-wide sync engine for Alembic / CLI usage."""
    settings = get_settings()
    return create_engine(
        settings.database_url_sync,
        pool_pre_ping=True,
        future=True,
    )


@lru_cache(maxsize=1)
def get_sessionmaker() -> async_sessionmaker[AsyncSession]:
    """Cached async_sessionmaker bound to the async engine."""
    return async_sessionmaker(
        bind=get_async_engine(),
        expire_on_commit=False,
        class_=AsyncSession,
    )


async def get_session() -> AsyncIterator[AsyncSession]:
    """FastAPI dependency yielding an `AsyncSession`."""
    async with get_sessionmaker()() as session:
        yield session
