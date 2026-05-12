"""Strictness 임계값 + (entity_type, band) → 응답 코드 매핑 (§2.4 / §1.2).

Phase 9D 정리: WARN 등급은 폐기되어 모든 "임계값 이상" 탐지는 BLOCK 으로
흡수된다 (이전 PASS / WARN / BLOCK 3단계 → PASS / BLOCK 2단계). WARN 코드는
audit/legacy 호환을 위해 카탈로그에 남아 있지만 신규 응답에는 발생하지
않는다.

두 가지 책임:

  1. ``score_to_band(score, strictness)`` — 분석기가 산출한 0.0~1.0 score 를
     보고 PASS / BLOCK 중 어느 밴드인지 판정. 임계값은 strictness 별로 다름.
  2. ``map_detection_to_code(entity_type, score, field, strictness)`` —
     ``(entity_type, band)`` 를 ``app/core/codes.py`` 의 카탈로그 코드로
     매핑. attachment.* field 는 entity 종류 무관 BLOCK-2010 으로 통합.

Strictness 의미:

  - **low**    — score ≥ 0.65 면 BLOCK. 오탐 ↓ / 미탐 ↑ — 자유게시판 등 게시
                 자유도 우선 환경.
  - **medium** — score ≥ 0.78 (기본값). 일반 게시판 권장.
  - **high**   — score ≥ 0.88. 오탐 ↑ / 미탐 ↓ — 민원/법무 게시판 등 보호
                 우선 환경. `KR_BANK_ACCOUNT_WEAK` 같은 약한 패턴은 임계
                 미만으로 떨어져 PASS 로 분류된다.

`ENTITY_TO_CODE` 매핑은 단일 진실 원천 — 새 인식기 추가 시 이 테이블에
한 행 추가하면 즉시 전체 정책 매핑에 반영된다.
"""

from __future__ import annotations

from typing import Literal

from app.core.codes import FALLBACK_BLOCK, FALLBACK_PASS

Band = Literal["pass", "block"]
Strictness = Literal["low", "medium", "high"]


# Score thresholds per strictness: score >= block_at  ⇒ block, otherwise pass.
# Phase 9D — 단일 BLOCK 임계값으로 단순화.
_BLOCK_THRESHOLD: dict[Strictness, float] = {
    "low": 0.65,
    "medium": 0.78,
    "high": 0.88,
}


def score_to_band(score: float, strictness: Strictness) -> Band:
    """Map a detector score to a verdict band according to strictness."""
    if score >= _BLOCK_THRESHOLD[strictness]:
        return "block"
    return "pass"


# Per-entity codes for the BLOCK band. Entities not in this table fall
# back to ``FALLBACK_BLOCK`` (BLOCK-2099).
ENTITY_TO_CODE: dict[tuple[str, Band], str] = {
    ("KR_RRN", "block"): "BLOCK-2001",
    ("KR_DRIVERLICENSE", "block"): "BLOCK-2002",
    ("KR_PASSPORT", "block"): "BLOCK-2003",
    ("CREDIT_CARD", "block"): "BLOCK-2005",
    ("KR_BANK_ACCOUNT", "block"): "BLOCK-2006",
    ("INTERNAL_NAME", "block"): "BLOCK-2007",
    ("KR_PHONE", "block"): "BLOCK-2099",
    ("EMAIL_ADDRESS", "block"): "BLOCK-2099",
    ("LOCATION", "block"): "BLOCK-2099",
    ("PERSON", "block"): "BLOCK-2099",
    ("KR_BUSINESS_NUM", "block"): "BLOCK-2099",
    ("KR_BANK_ACCOUNT_WEAK", "block"): "BLOCK-2099",
    # PASS band falls through to FALLBACK_PASS in map_detection_to_code.
}


def map_detection_to_code(
    *,
    entity_type: str,
    score: float,
    field: str,
    strictness: Strictness,
) -> str:
    """Resolve a single detection to its response code.

    Attachment hits are uniformly mapped to BLOCK-2010 when the band is
    block, since the user-facing message references the filename.
    """
    band = score_to_band(score, strictness)

    if field.startswith("attachment"):
        if band == "block":
            return "BLOCK-2010"
        return FALLBACK_PASS

    if band == "pass":
        return FALLBACK_PASS

    code = ENTITY_TO_CODE.get((entity_type, band))
    if code is not None:
        return code

    # Unknown entity_type — fall back to category default.
    return FALLBACK_BLOCK
