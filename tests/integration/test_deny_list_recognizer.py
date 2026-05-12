"""T2.6 — deny-list 100명 직원명 전부 검출 회귀 방지.

`build_analyzer_with_deny_list` 가 DB 의 deny-list 행을 모두 읽어 인식기에
주입하고, 100건 모두를 본문 안에서 INTERNAL_NAME entity 로 잡아내는지
검증한다. 2~3자 한글 음절을 무작위 합성 → 실재 인명과 충돌 가능성 회피.

추가로 `KR_EMPLOYEE_ID` 같은 entity_type 별 deny 행이 INTERNAL_NAME 이
아닌 자기 타입으로 잡히는지도 같이 확인 (타입 라우팅 회귀 방지).
"""

from __future__ import annotations

import random
import string
from typing import TYPE_CHECKING

from app.core.analyzer import build_analyzer_with_deny_list
from app.db.crud import add_deny_entry

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession


# Hangul syllable block range commonly used: 가(0xAC00) ~ 힣(0xD7A3).
def _random_hangul(n: int, rng: random.Random) -> str:
    return "".join(chr(rng.randint(0xAC00, 0xD7A3)) for _ in range(n))


def _generate_unique_names(count: int, *, seed: int = 20260425) -> list[str]:
    rng = random.Random(seed)
    out: set[str] = set()
    while len(out) < count:
        # 2-3 char Hangul "names" — synthetic, won't collide with real KR names.
        out.add(_random_hangul(rng.choice([2, 3]), rng))
    return sorted(out)


async def test_t2_6_100_deny_names_all_detected(db_session: AsyncSession) -> None:
    """deny-list 의 100명 직원명이 모두 INTERNAL_NAME 으로 검출되어야 한다.

    25명 단위로 한 문장에 모아 분석기에 흘려 누락 없이 잡히는지 확인.
    하나라도 누락되면 빠진 이름의 처음 3개를 에러 메시지에 포함해 디버깅
    실마리 제공.
    """
    names = _generate_unique_names(100)

    for name in names:
        await add_deny_entry(
            db_session,
            entity_type="INTERNAL_NAME",
            value=name,
            score=0.95,
            note="t2.6-test",
        )

    analyzer = await build_analyzer_with_deny_list(db_session)

    # 25 names per sentence keeps each analyze() call fast.
    chunks = [names[i : i + 25] for i in range(0, len(names), 25)]

    detected: set[str] = set()
    for chunk in chunks:
        text = "직원 명단: " + ", ".join(chunk) + " 입니다."
        results = analyzer.analyze(text=text, language="ko")
        for r in results:
            if r.entity_type != "INTERNAL_NAME":
                continue
            detected.add(text[r.start : r.end])

    missing = set(names) - detected
    assert not missing, f"deny-list misses {len(missing)} names; e.g. {sorted(missing)[:3]}"


async def test_t2_6_deny_recognizer_filters_by_entity(
    db_session: AsyncSession,
) -> None:
    """deny 행의 `entity_type` 컬럼이 detection 의 entity_type 으로 그대로 흘러야 한다.

    `KR_EMPLOYEE_ID` 로 등록된 sentinel 값이 INTERNAL_NAME 이 아니라
    KR_EMPLOYEE_ID 로 잡혀야 정책 매핑이 올바른 코드로 분기 가능.
    """
    # Sentinel value chosen so it's distinct from any seeded regex.
    sentinel = "ZX" + "".join(random.choices(string.ascii_uppercase, k=8))
    await add_deny_entry(
        db_session,
        entity_type="KR_EMPLOYEE_ID",
        value=sentinel,
        score=0.9,
    )
    analyzer = await build_analyzer_with_deny_list(db_session)
    results = analyzer.analyze(text=f"사번 {sentinel} 입니다", language="ko")
    matched = [r for r in results if r.entity_type == "KR_EMPLOYEE_ID"]
    assert any(
        text_slice == sentinel
        for r in matched
        for text_slice in [f"사번 {sentinel} 입니다"[r.start : r.end]]
    )
