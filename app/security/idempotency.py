"""In-memory idempotency cache for `request_id` (§2.6).

Phase 1 ships an in-process dict with a 24 h TTL. Phase 3+ swaps this for
Redis so the cache survives restarts and is shared across replicas.

Behavior:
  - First time we see a `request_id` → `reserve()` registers it as
    `in_progress` and returns `Reserved`.
  - Same `request_id` arrives again while still `in_progress` → caller
    should respond with REQ-4005 (duplicate request).
  - Same `request_id` arrives again after `complete()` → caller should
    return the cached response (idempotent replay).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import Enum
from threading import Lock
from typing import TYPE_CHECKING
from uuid import UUID

if TYPE_CHECKING:
    from app.api.schemas import DetectPostResponse

DEFAULT_TTL = timedelta(hours=24)


class ReserveOutcome(Enum):
    NEW = "new"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"


@dataclass
class _Entry:
    state: ReserveOutcome  # NEW is never stored; only IN_PROGRESS or COMPLETED
    response: DetectPostResponse | None
    created_at: datetime


class IdempotencyCache:
    """Thread-safe in-memory cache of recent request_ids."""

    def __init__(self, ttl: timedelta = DEFAULT_TTL) -> None:
        self._store: dict[UUID, _Entry] = {}
        self._ttl = ttl
        self._lock = Lock()

    def reserve(self, request_id: UUID) -> tuple[ReserveOutcome, DetectPostResponse | None]:
        """Reserve a slot for ``request_id``.

        Returns the outcome and, if COMPLETED, the previously cached response.
        """
        with self._lock:
            self._evict_expired()
            entry = self._store.get(request_id)
            if entry is None:
                self._store[request_id] = _Entry(
                    state=ReserveOutcome.IN_PROGRESS,
                    response=None,
                    created_at=datetime.now(tz=UTC),
                )
                return ReserveOutcome.NEW, None
            return entry.state, entry.response

    def complete(self, request_id: UUID, response: DetectPostResponse) -> None:
        """Mark ``request_id`` as completed and cache the response."""
        with self._lock:
            self._store[request_id] = _Entry(
                state=ReserveOutcome.COMPLETED,
                response=response,
                created_at=datetime.now(tz=UTC),
            )

    def release(self, request_id: UUID) -> None:
        """Drop an in-progress reservation (used when processing errors out)."""
        with self._lock:
            entry = self._store.get(request_id)
            if entry is not None and entry.state is ReserveOutcome.IN_PROGRESS:
                self._store.pop(request_id, None)

    def clear(self) -> None:
        """Drop every entry (test hook)."""
        with self._lock:
            self._store.clear()

    def _evict_expired(self) -> None:
        cutoff = datetime.now(tz=UTC) - self._ttl
        stale = [k for k, v in self._store.items() if v.created_at < cutoff]
        for k in stale:
            self._store.pop(k, None)


# Process-wide singleton (Phase 1 only — Phase 3 replaces with Redis-backed)
_default_cache = IdempotencyCache()


def get_cache() -> IdempotencyCache:
    """Return the process-wide idempotency cache."""
    return _default_cache
