"""Phase 1c → 9D — threshold/mapping coverage for app.core.policies.

Phase 9D 변경: WARN 등급 폐기. PASS/BLOCK 2단계 검증으로 갱신.
"""

from __future__ import annotations

import pytest

from app.core.policies import (
    ENTITY_TO_CODE,
    map_detection_to_code,
    score_to_band,
)


# ── Threshold sanity per strictness ────────────────────────────────────────
@pytest.mark.parametrize(
    ("strictness", "score", "expected"),
    [
        # low: block ≥ 0.65
        ("low",    0.30, "pass"),
        ("low",    0.50, "pass"),
        ("low",    0.65, "block"),
        # medium: block ≥ 0.78
        ("medium", 0.40, "pass"),
        ("medium", 0.77, "pass"),
        ("medium", 0.78, "block"),
        # high: block ≥ 0.88
        ("high",   0.60, "pass"),
        ("high",   0.87, "pass"),
        ("high",   0.88, "block"),
    ],
)
def test_score_to_band_thresholds(
    strictness: str, score: float, expected: str
) -> None:
    assert score_to_band(score, strictness) == expected  # type: ignore[arg-type]


# ── Phase 9D: high strictness drops weak bank pattern ──────────────────────
def test_high_strictness_drops_weak_bank_pattern() -> None:
    """A bare 10~14 digit run scores ~0.5 from KrBankAccountWeak.

    At medium strictness the score is below the BLOCK threshold (0.78);
    at high strictness even further below (0.88). Both must PASS now
    that the WARN tier is gone.
    """
    weak_score = 0.5

    medium = map_detection_to_code(
        entity_type="KR_BANK_ACCOUNT_WEAK",
        score=weak_score,
        field="post.body",
        strictness="medium",
    )
    high = map_detection_to_code(
        entity_type="KR_BANK_ACCOUNT_WEAK",
        score=weak_score,
        field="post.body",
        strictness="high",
    )
    assert medium == "OK-0000"
    assert high == "OK-0000"


# ── BLOCK canonical mappings (medium) ─────────────────────────────────────
@pytest.mark.parametrize(
    ("entity_type", "score", "expected"),
    [
        ("KR_RRN", 0.95, "BLOCK-2001"),
        ("KR_DRIVERLICENSE", 0.90, "BLOCK-2002"),
        ("KR_PASSPORT", 0.90, "BLOCK-2003"),
        ("CREDIT_CARD", 0.95, "BLOCK-2005"),
        ("KR_BANK_ACCOUNT", 0.85, "BLOCK-2006"),
        # Phase 9D — phone/email/etc 도 임계값 이상이면 BLOCK 흡수.
        ("KR_PHONE", 0.95, "BLOCK-2099"),
        ("EMAIL_ADDRESS", 0.95, "BLOCK-2099"),
        ("LOCATION", 0.95, "BLOCK-2099"),
        ("PERSON", 0.95, "BLOCK-2099"),
        ("KR_BUSINESS_NUM", 0.90, "BLOCK-2099"),
    ],
)
def test_map_detection_to_code_medium_block(
    entity_type: str, score: float, expected: str
) -> None:
    code = map_detection_to_code(
        entity_type=entity_type,
        score=score,
        field="post.body",
        strictness="medium",
    )
    assert code == expected


# ── PASS band — score below threshold ─────────────────────────────────────
@pytest.mark.parametrize(
    ("entity_type", "score"),
    [
        ("KR_PHONE", 0.70),
        ("EMAIL_ADDRESS", 0.70),
        ("LOCATION", 0.60),
        ("PERSON", 0.60),
        ("KR_BUSINESS_NUM", 0.60),
    ],
)
def test_map_detection_to_code_medium_pass(
    entity_type: str, score: float
) -> None:
    code = map_detection_to_code(
        entity_type=entity_type,
        score=score,
        field="post.body",
        strictness="medium",
    )
    assert code == "OK-0000"


# ── Attachment field maps to BLOCK-2010 when blocked ───────────────────────
def test_attachment_block_uses_2010() -> None:
    code = map_detection_to_code(
        entity_type="KR_RRN",
        score=0.95,
        field="attachment.att_001",
        strictness="medium",
    )
    assert code == "BLOCK-2010"


def test_attachment_pass_band_drops() -> None:
    code = map_detection_to_code(
        entity_type="KR_RRN",
        score=0.30,
        field="attachment.att_001",
        strictness="medium",
    )
    assert code == "OK-0000"


# ── Unknown entity_type at BLOCK band → fallback BLOCK-2099 ───────────────
def test_unknown_entity_falls_back() -> None:
    block_fallback = map_detection_to_code(
        entity_type="MYSTERY_ENTITY",
        score=0.95,
        field="post.body",
        strictness="medium",
    )
    pass_fallback = map_detection_to_code(
        entity_type="MYSTERY_ENTITY",
        score=0.30,
        field="post.body",
        strictness="medium",
    )
    assert block_fallback == "BLOCK-2099"
    assert pass_fallback == "OK-0000"


# ── ENTITY_TO_CODE table sanity ────────────────────────────────────────────
def test_entity_to_code_table_uses_real_codes() -> None:
    from app.core.codes import CODES

    for (_etype, _band), code in ENTITY_TO_CODE.items():
        assert code in CODES, f"{code} not in CODES catalog"
