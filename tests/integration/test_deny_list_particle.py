"""UX-3 — deny_list 매칭 우측 경계가 한국어 조사 부착을 허용해야 한다.

원효대사**와** / 홍길동**에게** / 이순신**의** 처럼 조사가 붙은 형태에서도
deny-listed 이름이 검출되어야 한다.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from app.core.analyzer import build_analyzer_with_deny_list
from app.db.crud import add_deny_entry

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession


PARTICLES = ["와", "과", "은", "는", "이", "가", "을", "를", "에게", "의"]


@pytest.mark.parametrize("particle", PARTICLES)
async def test_deny_list_matches_with_korean_particle(
    db_session: AsyncSession,
    particle: str,
) -> None:
    name = "원효대사"  # synthetic; not a current employee
    await add_deny_entry(db_session, entity_type="INTERNAL_NAME", value=name, score=0.95)
    analyzer = await build_analyzer_with_deny_list(db_session)
    text = f"{name}{particle} 강연합니다"
    hits = [
        r for r in analyzer.analyze(text=text, language="ko") if r.entity_type == "INTERNAL_NAME"
    ]
    assert hits, f"deny_list missed {name!r} when followed by particle {particle!r}"
    assert any(text[h.start : h.end] == name for h in hits)
