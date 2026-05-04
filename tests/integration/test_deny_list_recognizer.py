"""T2.6 — deny_list 100 employee names → all detected via build_analyzer_with_deny_list.

Builds a synthetic deny list of 100 made-up Korean names (3 char Hangul,
non-real), inserts them into pii.pii_deny_list, builds an analyzer, and
asserts every name is detected when embedded in a sentence.
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
    """All 100 deny-listed names are detected as INTERNAL_NAME."""
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
    """A KR_PHONE deny entry must surface as KR_PHONE, not INTERNAL_NAME."""
    # Sentinel value chosen so it's distinct from any seeded regex.
    sentinel = "ZX" + "".join(random.choices(string.ascii_uppercase, k=8))
    await add_deny_entry(
        db_session,
        entity_type="KR_EMPLOYEE_ID",
        value=sentinel,
        score=0.9,
    )
    analyzer = await build_analyzer_with_deny_list(db_session)
    results = analyzer.analyze(
        text=f"사번 {sentinel} 입니다", language="ko"
    )
    matched = [r for r in results if r.entity_type == "KR_EMPLOYEE_ID"]
    assert any(text_slice == sentinel
               for r in matched
               for text_slice in [f"사번 {sentinel} 입니다"[r.start : r.end]])
