"""Phase 7 — DB policy resolution layered on top of ``policies.py``.

Resolution
----------
1. Look up ``mode='enabled'`` rows from ``pii_policies`` matching
   ``entity_type`` and ``score_min <= score <= score_max`` — narrowest
   band wins (ties on highest ``score_min``).
2. If a DB row matches, its ``action`` and (optional)
   ``user_message_template`` override the code-defined ``policies.py``
   verdict mapping.
3. If no DB row matches, fall back to the existing
   ``map_detection_to_code`` result.

Shadow rows (``mode='shadow'``) are never evaluated by the production
resolver; the shadow analyzer evaluates them separately for audit only.

Cache
-----
The active policy list is held in a process-wide cache that mirrors the
analyzer cache. ``request_reload()`` 는 외부 트리거(예: 운영 도구) 가
호출하면 다음 ``get()`` 시 재빌드 한다. Phase 9E 에서 pattern_listener
가 폐기되어 자동 NOTIFY 트리거는 사라졌으나 시그니처는 보존된다.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

    from app.db.models import PiiPolicy

logger = logging.getLogger(__name__)


PolicyAction = Literal["BLOCK", "WARN", "MASK", "LOG_ONLY", "PASS"]


@dataclass(frozen=True)
class ResolvedPolicy:
    """The outcome of resolving a single detection through the engine."""

    action: PolicyAction
    code: str
    user_message: str | None
    # ``True`` if the action came from a DB policy row, ``False`` if it
    # fell back to the code-defined ``policies.py`` mapping.
    from_db: bool


class PolicyCache:
    """Process-wide cache of active ``pii_policies`` rows.

    Rebuilds from DB on demand; reload is triggered the same way as
    :class:`AnalyzerCache` — a NOTIFY landing on ``pii_pattern_changed``
    flips ``_reload_pending`` and the next ``get()`` rebuilds.
    """

    def __init__(self) -> None:
        self._policies: list[PiiPolicy] = []
        self._lock = asyncio.Lock()
        self._reload_pending = True
        self._last_built_at: float = 0.0
        self._reload_count: int = 0

    def request_reload(self) -> None:
        self._reload_pending = True

    async def get(self, session: AsyncSession) -> list[PiiPolicy]:
        if not self._reload_pending:
            return self._policies
        async with self._lock:
            # Re-check inside the lock to avoid duplicated rebuilds when
            # multiple tasks race the first request.
            if self._reload_pending:
                from app.db.crud import list_active_policies

                self._policies = await list_active_policies(session)
                self._reload_pending = False
                self._last_built_at = time.time()
                self._reload_count += 1
                logger.info(
                    "policy cache rebuilt",
                    extra={"row_count": len(self._policies),
                           "reload_count": self._reload_count},
                )
            return self._policies

    @property
    def reload_count(self) -> int:
        return self._reload_count


_CACHE: PolicyCache | None = None


def get_policy_cache() -> PolicyCache:
    global _CACHE
    if _CACHE is None:
        _CACHE = PolicyCache()
    return _CACHE


def reset_policy_cache_for_tests() -> None:
    global _CACHE
    _CACHE = None


# ── Resolver ──────────────────────────────────────────────────────────────
def _match(policy: PiiPolicy, *, entity_type: str, score: float) -> bool:
    return (
        policy.entity_type == entity_type
        and policy.score_min <= score <= policy.score_max
    )


def resolve_action(
    *,
    entity_type: str,
    score: float,
    code_default_action: PolicyAction,
    code_default_code: str,
    code_default_user_message: str | None,
    policies: list[PiiPolicy],
) -> ResolvedPolicy:
    """Apply DB policies on top of the code-defined fallback.

    Parameters
    ----------
    code_default_action :
        The action implied by ``policies.py`` for this detection (i.e.
        BLOCK / WARN / PASS — derived from the band of the resolved
        ``code_default_code``).
    code_default_code :
        The response code chosen by ``map_detection_to_code``.
    code_default_user_message :
        The pre-rendered user_message from the code's template; used as
        fallback when a DB policy doesn't supply its own template.
    policies :
        Pre-fetched, specificity-ordered policy rows (the cache returns
        them in the right order already).
    """
    for p in policies:
        if _match(p, entity_type=entity_type, score=score):
            # The CHECK constraint on pii_policies guarantees one of the
            # five literal values, but mypy can't see Postgres CHECKs.
            action: PolicyAction = p.action  # type: ignore[assignment]
            user_message = p.user_message_template or code_default_user_message
            code = _action_to_code(action, code_default_code)
            return ResolvedPolicy(
                action=action,
                code=code,
                user_message=user_message,
                from_db=True,
            )

    return ResolvedPolicy(
        action=code_default_action,
        code=code_default_code,
        user_message=code_default_user_message,
        from_db=False,
    )


def _action_to_code(action: PolicyAction, fallback: str) -> str:
    """Map a DB-policy action to a canonical response code.

    BLOCK / WARN keep the code-default's specific code (e.g. BLOCK-2001
    for KR_RRN); MASK forces WARN-1010; LOG_ONLY / PASS resolve to
    OK-0000 because the entity is dropped from the caller-visible
    response.
    """
    if action == "MASK":
        return "WARN-1010"
    if action in {"LOG_ONLY", "PASS"}:
        return "OK-0000"
    # BLOCK / WARN — preserve the specific code chosen by the default
    # mapping (e.g. BLOCK-2001 for KR_RRN). The DB policy effectively
    # confirms or upgrades the band rather than re-routing the code.
    return fallback
