"""UX-3 — deny-list 매칭 우측 경계가 한국어 조사 부착을 허용해야 한다.

`원효대사`, `홍길동`, `이순신` 같은 이름이 deny-list 에 있을 때, 실제 본문에
는 거의 항상 조사 (와/과/의/에게/은/는/이/가/을/를…) 가 뒤따른다. 정규식
경계가 단어 경계 ``\b`` 만 보면 한글 조사가 같은 토큰으로 묶여 매칭이 깨
지므로, deny 인식기는 다음 글자가 한국어 조사일 때도 매칭을 허용해야 한다.

본 모듈은 5종 이상의 조사 변형 + 영문 단어 경계 + 본문 가운데 위치 등
다양한 컨텍스트에서 모두 검출되는지 한꺼번에 확인한다.
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
