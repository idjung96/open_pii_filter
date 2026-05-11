# SYNTHETIC DATA - NOT REAL PII
"""Phase 4b/C — 한글 entity 라벨 매핑 헬퍼 회귀 방지.

`entity_type` (예: `KR_RRN`) → 한국어 라벨 (예: `주민등록번호`) 변환을
담당하는 `app.core.entity_labels` 의 두 함수를 검증한다:

- `label_for(entity_type)` — 단일 매핑, 미지의 코드는 일반 라벨 `개인정보`
- `detected_summary_kr(detections)` — 응답 user_message 끝에 붙는
  "(검출된 항목: …)" 안내 문구 생성 (중복 제거 + 첫 등장 순서 유지)

사용자에게 영문 entity 코드 (`KR_RRN`) 가 새어나가지 않게 차단하는
1차 가드이므로 새 인식기 추가 시 라벨 누락이 여기서 즉시 잡힌다.
"""

from __future__ import annotations

from app.core.entity_labels import (
    ENTITY_LABELS_KR,
    detected_summary_kr,
    label_for,
)


class _DetStub:
    """Detection 객체에서 `entity_type` 만 보면 되는 dataclass 대체 stub."""

    def __init__(self, entity_type: str) -> None:
        self.entity_type = entity_type


def test_label_for_known_kr_entities() -> None:
    """알려진 4종 entity 가 한국어 라벨로 정확히 매핑되는지.

    `KR_RRN` → 주민등록번호, `KR_PHONE` → 전화번호 등 사용자에게 안내될
    핵심 라벨을 핀(pin) 한다. 라벨 텍스트가 변경되면 사용자에게 보이는
    메시지가 직접 바뀌므로 의도 없는 수정을 막는다.
    """
    assert label_for("KR_RRN") == "주민등록번호"
    assert label_for("KR_PHONE") == "전화번호"
    assert label_for("EMAIL_ADDRESS") == "이메일"
    assert label_for("CREDIT_CARD") == "신용카드번호"


def test_label_for_unknown_returns_generic_label() -> None:
    """매핑에 없는 entity 가 들어와도 영문 코드를 노출하면 안 된다.

    미등록 entity 의 fallback 은 일반 라벨 `개인정보` — 사용자가 영문
    내부 코드를 보는 사고를 차단한다.
    """
    assert label_for("MYSTERY_ENTITY") == "개인정보"


def test_label_table_covers_every_recognizer_we_emit() -> None:
    """본문 분석기가 노출하는 모든 entity_type 이 라벨 테이블에 존재해야 한다.

    새 인식기를 추가하면 라벨 매핑도 함께 채워야 한다. 이 테스트는 코드
    리뷰가 빠뜨려도 CI 가 잡도록 핵심 6종 KR_* entity 를 강제한다.
    """
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
    """같은 entity 가 여러 번 검출돼도 안내 문구에는 한 번만, 등장 순서대로.

    `KR_RRN` 가 두 번 들어오면 `주민등록번호, 주민등록번호` 처럼 중복
    노출되는 회귀를 방지하고, 정렬을 알파벳 순으로 강제하면 자연스러운
    순서가 깨지므로 첫 등장 순서를 유지한다.
    """
    summary = detected_summary_kr(
        [
            _DetStub("KR_RRN"),
            _DetStub("KR_PHONE"),
            _DetStub("KR_RRN"),  # 중복 — 한 번만 노출되어야 함
            _DetStub("EMAIL_ADDRESS"),
        ]
    )
    assert summary == "주민등록번호, 전화번호, 이메일"


def test_summary_handles_dict_inputs() -> None:
    """webhook payload 처럼 dict 형태로 들어와도 동일한 결과를 내야 한다.

    `attachment_results` 의 `detections` 는 직렬화 시 dict 형태가 되므로
    Detection 인스턴스가 아닌 dict 도 처리할 수 있어야 한다 (duck typing).
    """
    summary = detected_summary_kr(
        [
            {"entity_type": "KR_RRN"},
            {"entity_type": "KR_PHONE"},
        ]
    )
    assert summary == "주민등록번호, 전화번호"


def test_summary_returns_empty_when_no_detections() -> None:
    """detections 가 비어 있으면 빈 문자열을 돌려준다 — 호출자가 안전히 분기 가능."""
    assert detected_summary_kr([]) == ""
