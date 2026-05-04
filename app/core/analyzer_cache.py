"""Process-wide analyzer cache.

Phase 9E — pii_patterns 인프라가 폐기되어 hot-reload / shadow analyzer
경로가 제거됐다. 캐시는 이제 ``build_analyzer_with_deny_list()`` 결과를
래핑하는 단순한 lazy-init singleton 으로 동작한다. deny_list 행이
변경되어도 분석 엔진을 즉시 갱신할 필요가 적어 명시적인 재로드 트리거
없이 프로세스 수명 동안 1회만 빌드한다 (운영자가 deny_list 추가 후
서비스 재시작으로 반영).
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from presidio_analyzer import AnalyzerEngine
    from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)


class AnalyzerCache:
    """Singleton holding the live `AnalyzerEngine`.

    Phase 9E — shadow analyzer / hot-reload 트리거 제거. ``request_reload()``
    는 호환을 위해 남겨두지만 다음 ``get()`` 호출 시 단순 재빌드만 수행한다.
    """

    def __init__(self) -> None:
        self._engine: AnalyzerEngine | None = None
        self._lock = asyncio.Lock()
        self._reload_pending = True  # build on first use
        self._last_built_at: float = 0.0
        self._last_build_seconds: float = 0.0
        self._reload_count: int = 0

    def request_reload(self) -> None:
        """Mark the cache stale; the next `get()` rebuilds.

        Phase 9E — pattern hot-reload 트리거가 사라져 호출처가 거의 없지만
        시그니처 호환을 위해 보존.
        """
        self._reload_pending = True

    async def get(self, session: AsyncSession) -> AnalyzerEngine:
        """Return the analyzer, rebuilding if reload is pending."""
        if not self._reload_pending and self._engine is not None:
            return self._engine

        async with self._lock:
            if not self._reload_pending and self._engine is not None:
                return self._engine
            await self._build(session)
            self._reload_pending = False
            assert self._engine is not None
            return self._engine

    async def get_shadow(
        self,
        session: AsyncSession,  # noqa: ARG002 — back-compat shim
    ) -> AnalyzerEngine | None:
        """Phase 9E — shadow analyzer 폐기. 항상 ``None`` 을 반환한다.

        Phase 7 의 ``mode='shadow'`` 패턴 인프라가 함께 사라졌으므로
        ``_run_shadow`` 호출자는 항상 빈 결과를 받는다.
        """
        return None

    async def _build(self, session: AsyncSession) -> None:
        from app.core.analyzer import build_analyzer_with_deny_list

        started = time.perf_counter()
        engine = await build_analyzer_with_deny_list(session)

        self._engine = engine
        elapsed = time.perf_counter() - started
        self._last_built_at = time.time()
        self._last_build_seconds = elapsed
        self._reload_count += 1
        logger.info(
            "analyzer rebuilt",
            extra={"build_seconds": round(elapsed, 3), "reload_count": self._reload_count},
        )

    @property
    def last_build_seconds(self) -> float:
        return self._last_build_seconds

    @property
    def reload_count(self) -> int:
        return self._reload_count

    @property
    def has_shadow(self) -> bool:
        """Phase 9E — shadow analyzer 폐기. 항상 ``False``."""
        return False


_CACHE: AnalyzerCache | None = None


def get_analyzer_cache() -> AnalyzerCache:
    """Process-wide singleton accessor."""
    global _CACHE
    if _CACHE is None:
        _CACHE = AnalyzerCache()
    return _CACHE


def reset_analyzer_cache_for_tests() -> None:
    """Reset the singleton; tests use this to start with a clean slate."""
    global _CACHE
    _CACHE = None
