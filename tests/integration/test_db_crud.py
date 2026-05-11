"""Phase 2 — deny-list CRUD 회귀 방지.

`pii.deny_list` 테이블에 신규 항목 추가 / 조회 / 중복 거절이 SQLAlchemy
async 세션을 통해 정상 동작하는지 확인한다.

Phase 9E 메모: `pii_patterns` 테이블 폐기로 패턴 CRUD / 히스토리 검증
케이스가 모두 제거됐고 deny_list 만 남았다 (이름 매칭이 단일 진실 원천).
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
    """`add_deny_entry` 로 추가한 항목이 `list_deny_entries` 결과에 등장.

    가장 기본적인 round-trip — 운영자가 dashboard 에서 직원명을 추가하면
    같은 세션의 후속 조회에서 즉시 보여야 한다 (캐시 reload 와는 별도의
    DB-수준 동작 검증).
    """
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
    """같은 (entity_type, value) 조합으로 두 번 추가 시 `PolicyValidationError`.

    silent duplicate 가 허용되면 unique index 회귀 / 중복 차단 사고 발생.
    운영자가 같은 이름을 두 번 등록해도 명시적 에러로 안내되어야 한다.
    """
    await add_deny_entry(db_session, entity_type="INTERNAL_NAME", value="라마바", score=0.95)
    with pytest.raises(PolicyValidationError):
        await add_deny_entry(db_session, entity_type="INTERNAL_NAME", value="라마바", score=0.95)
