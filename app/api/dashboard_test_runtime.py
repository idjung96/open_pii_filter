"""In-memory state backing the ``/admin/test`` attachment dry-run flow.

The dashboard's manual checker exercises the same async pipeline that
production traffic does — the worker fetches each attachment via
``Attachment.fetch_url`` and POSTs its results back to ``callback_url``.
For a self-contained UI test we need both endpoints to be reachable
locally, so this module:

  - stages each uploaded file in a token-keyed in-memory map
    (so a sibling internal endpoint can serve it as the fetch URL),
  - parks an :class:`asyncio.Event` per token that the test handler
    awaits while the worker pipeline runs,
  - records the webhook payload the worker POSTs to the callback URL.

The state is intentionally process-local and short-lived (10-minute
TTL), and never written to disk — it only ever holds synthetic test
input the operator just uploaded through the dashboard. A janitor
loop sweeps expired tokens so a forgotten browser tab cannot leak
memory.
"""

from __future__ import annotations

import asyncio
import logging
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


_TTL_SECONDS = 600  # 10 minutes — long enough for a slow OCR run.
_MAX_SESSIONS = 32  # Cap concurrent in-flight tests; prune oldest first.


@dataclass
class StagedFile:
    attachment_id: str
    filename: str
    mime_type: str
    data: bytes
    sha256: str


@dataclass
class TestSession:
    token: str
    files: dict[str, StagedFile] = field(default_factory=dict)
    callback_event: asyncio.Event = field(default_factory=asyncio.Event)
    callback_payload: dict[str, Any] | None = None
    created_at: float = field(default_factory=time.monotonic)


_sessions: dict[str, TestSession] = {}
_lock = asyncio.Lock()


async def create_session() -> TestSession:
    """Allocate a fresh test session and return its handle."""
    token = uuid.uuid4().hex
    sess = TestSession(token=token)
    async with _lock:
        _prune_expired_locked()
        # Hard cap — if the operator is firing tests faster than they
        # complete, drop the oldest in-flight one rather than growing
        # unbounded.
        if len(_sessions) >= _MAX_SESSIONS:
            oldest = min(_sessions.values(), key=lambda s: s.created_at)
            _sessions.pop(oldest.token, None)
        _sessions[token] = sess
    return sess


def get_session(token: str) -> TestSession | None:
    sess = _sessions.get(token)
    if sess is None:
        return None
    if time.monotonic() - sess.created_at > _TTL_SECONDS:
        _sessions.pop(token, None)
        return None
    return sess


async def end_session(token: str) -> None:
    async with _lock:
        _sessions.pop(token, None)


def _prune_expired_locked() -> None:
    """Drop sessions older than the TTL. Caller must hold ``_lock``."""
    now = time.monotonic()
    expired = [t for t, s in _sessions.items() if now - s.created_at > _TTL_SECONDS]
    for t in expired:
        _sessions.pop(t, None)
        logger.debug("dashboard test session %s expired and pruned", t)
