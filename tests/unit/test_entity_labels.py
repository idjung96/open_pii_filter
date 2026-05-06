# SYNTHETIC DATA - NOT REAL PII
"""Phase 4b/C — Korean entity-label mapping helpers."""

from __future__ import annotations

from app.core.entity_labels import (
    ENTITY_LABELS_KR,
    detected_summary_kr,
    label_for,
)


class _DetStub:
    def __init__(self, entity_type: str) -> None:
        self.entity_type = entity_type


def test_label_for_known_kr_entities() -> None:
    assert label_for("KR_RRN") == "주민등록번호"
    assert label_for("KR_PHONE") == "전화번호"
    assert label_for("EMAIL_ADDRESS") == "이메일"
    assert label_for("CREDIT_CARD") == "신용카드번호"


def test_label_for_unknown_returns_generic_label() -> None:
    assert label_for("MYSTERY_ENTITY") == "개인정보"


def test_label_table_covers_every_recognizer_we_emit() -> None:
    # Sanity: every entity_type the body analyzer can ship surfaces a
    # human label. If a new recognizer is added, the table must grow
    # alongside it; this test surfaces the omission.
    expected_kr = {
        "KR_RRN",
        "KR_DRIVERLICENSE",
        "KR_PASSPORT",
        "KR_PHONE",
        "KR_BUSINESS_NUM",
        "KR_BANK_ACCOUNT",
    }
    assert expected_kr.issubset(ENTITY_LABELS_KR.keys())


def test_summary_dedupes_and_preserves_first_seen_order() -> None:
    summary = detected_summary_kr(
        [
            _DetStub("KR_RRN"),
            _DetStub("KR_PHONE"),
            _DetStub("KR_RRN"),  # duplicate — should not repeat
            _DetStub("EMAIL_ADDRESS"),
        ]
    )
    assert summary == "주민등록번호, 전화번호, 이메일"


def test_summary_handles_dict_inputs() -> None:
    summary = detected_summary_kr(
        [
            {"entity_type": "KR_RRN"},
            {"entity_type": "KR_PHONE"},
        ]
    )
    assert summary == "주민등록번호, 전화번호"


def test_summary_returns_empty_when_no_detections() -> None:
    assert detected_summary_kr([]) == ""
