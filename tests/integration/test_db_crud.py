"""Phase 2 deny-list CRUD coverage.

Phase 9E — pii_patterns 테이블 폐기로 패턴 CRUD / 히스토리 검증 케이스
가 모두 제거됐다. deny_list 만 남았다.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from app.db.crud import (
    PolicyValidationError,
    add_deny_entry,
    list_deny_entries,
)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession


# ── Deny-list CRUD ────────────────────────────────────────────────────────
async def test_deny_list_add_and_list(db_session: AsyncSession) -> None:
    await add_deny_entry(
        db_session,
        entity_type="INTERNAL_NAME",
        value="가나다",
        score=0.95,
        note="test",
    )
    entries = await list_deny_entries(db_session, entity_type="INTERNAL_NAME")
    assert any(e.value == "가나다" for e in entries)


async def test_deny_list_duplicate_rejected(db_session: AsyncSession) -> None:
    await add_deny_entry(
        db_session, entity_type="INTERNAL_NAME", value="라마바", score=0.95
    )
    with pytest.raises(PolicyValidationError):
        await add_deny_entry(
            db_session, entity_type="INTERNAL_NAME", value="라마바", score=0.95
        )
