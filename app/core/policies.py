"""Strictness → band thresholds + entity→code mapping (§2.4, §1.2).

Phase 9D — WARN 등급이 폐기되었다. 모든 임계값 이상 탐지는 BLOCK 으로 흡수
된다. 이전 PASS/WARN/BLOCK 3-단계 → PASS/BLOCK 2-단계.

Two responsibilities:
  1. ``score_to_band`` turns a confidence score into a verdict band
     ("pass" | "block") given the requested strictness.
  2. ``map_detection_to_code`` resolves (entity_type, band, field) into
     the canonical response code from ``app/core/codes.py``.

Strictness semantics:
  - "low":    lenient — even moderate scores raise BLOCK
  - "medium": balanced default
  - "high":   strict — only very high scores raise BLOCK; weak
              patterns (e.g., bare 10-14 digit "loose" bank accounts)
              are pushed to PASS and dropped from the output.
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
