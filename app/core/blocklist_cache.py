"""Process-wide cache of attachment-blocklist rows (Phase 4b).

The cache holds two flat sets — `extension` (lowercase, no dot) and
`mime_type` (full string) — populated from `pii.attachment_blocklist`
on startup and again after every admin-API mutation.

Lookups (`is_blocked`) cost two set hits with no DB round-trip; the
admin endpoint's `reload_blocklist` pays the price once per change.

A transient DB failure during reload leaves the previous cache state
in place — the API keeps booting and the next successful reload
refills the cache.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from sqlalchemy import select

from app.db.models import AttachmentBlocklist

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)

_extensions: set[str] = set()
_mimes: set[str] = set()


def _norm_ext(filename_or_ext: str) -> str:
    """Return the trailing extension as lowercase with no leading dot."""
    if not filename_or_ext:
        return ""
    tail = filename_or_ext.rsplit(".", 1)[-1] if "." in filename_or_ext else filename_or_ext
    return tail.strip().lower()


async def reload_blocklist(session: AsyncSession) -> int:
    """Reload the in-memory blocklist from the DB (enabled rows only).

    Returns the number of rows loaded across both extension and mime_type
    sets (a row contributing both is counted once). Failures are caught
    and logged so a transient DB outage does not block startup or admin
    mutations.
    """
    global _extensions, _mimes
    try:
        stmt = select(AttachmentBlocklist.extension, AttachmentBlocklist.mime_type).where(
            AttachmentBlocklist.enabled.is_(True)
        )
        result = await session.execute(stmt)
        ext_set: set[str] = set()
        mime_set: set[str] = set()
        for ext, mime in result.all():
            if ext:
                ext_set.add(_norm_ext(str(ext)))
            if mime:
                mime_set.add(str(mime).strip().lower())
        _extensions = ext_set
        _mimes = mime_set
        logger.info(
            "attachment_blocklist_cache reloaded",
            extra={"extension_count": len(ext_set), "mime_count": len(mime_set)},
        )
        return len(ext_set) + len(mime_set)
    except Exception as e:
        logger.warning("attachment_blocklist_cache reload failed: %s", e)
        return 0


def is_blocked(*, filename: str, mime_type: str) -> tuple[bool, str | None]:
    """Return (blocked, match_kind) — `match_kind` is 'extension'/'mime'/None."""
    ext = _norm_ext(filename)
    if ext and ext in _extensions:
        return True, "extension"
    mime = (mime_type or "").strip().lower()
    if mime and mime in _mimes:
        return True, "mime"
    return False, None


def snapshot() -> dict[str, list[str]]:
    """Return a copy of both sets — used by admin/debug endpoints and tests."""
    return {
        "extensions": sorted(_extensions),
        "mime_types": sorted(_mimes),
    }


def _reset_for_tests() -> None:
    """Clear both module-level sets; tests use this between runs."""
    global _extensions, _mimes
    _extensions = set()
    _mimes = set()
