# SYNTHETIC DATA - NOT REAL PII
"""Entity labels + body-size 미들웨어 잔여 경계 회귀 방지 (Phase 4 + 3).

기존 `test_entity_labels.py` 가 다루는 영역 외 추가 가드:

Entity labels:
  - 혼합 입력 (dict + 객체) 동시 처리
  - 비-문자열 entity_type 안전 skip (dict / object 양쪽)
  - 한국어 라벨 12 종 완전성 (모든 운영 entity 가 라벨 보유)
  - 빈 라벨 / 공백 라벨 비포함
  - 라벨 매핑이 §2.5 안전 (entity 코드 자체가 라벨로 노출되지 않음)

Body size:
  - DEFAULT_MAX_BODY_BYTES = 1 MiB
  - _too_large_response 가 REQ-4030 / HTTP 413 / valid envelope 생성
  - BodySizeLimitMiddleware 인스턴스화 가능
  - 커스텀 max_bytes 인자 동작
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

from app.core.entity_labels import (
    _FALLBACK_LABEL,
    ENTITY_LABELS_KR,
    detected_summary_kr,
    label_for,
)
from app.security.body_size import (
    DEFAULT_MAX_BODY_BYTES,
    BodySizeLimitMiddleware,
    _too_large_response,
)


# ── Entity labels 완전성 ─────────────────────────────────────────────────
def test_entity_labels_table_has_all_block_entities() -> None:
    """`ENTITY_TO_CODE` 의 BLOCK 카테고리 entity 가 모두 한국어 라벨 보유."""
    from app.core.policies import ENTITY_TO_CODE

    for (etype, band), _code in ENTITY_TO_CODE.items():
        if band != "block":
            continue
        # KR_BANK_ACCOUNT 와 _WEAK 는 동일 라벨 매핑.
        assert etype in ENTITY_LABELS_KR, f"{etype} 라벨 누락"


def test_entity_labels_are_korean() -> None:
    """모든 라벨이 한글 — entity 코드가 영문으로 노출되는 사고 방지."""
    for etype, label in ENTITY_LABELS_KR.items():
        # 한국어 라벨은 한글 음절 포함.
        assert any("가" <= c <= "힣" for c in label), f"{etype} 라벨에 한글 없음: {label!r}"


def test_entity_labels_no_empty_or_whitespace() -> None:
    """라벨이 빈 문자열 / 공백만 인 경우 없음."""
    for etype, label in ENTITY_LABELS_KR.items():
        assert label.strip(), f"{etype} 라벨이 비어있음"
        assert label == label.strip(), f"{etype} 라벨 앞뒤 공백: {label!r}"


def test_entity_labels_no_entity_code_in_label() -> None:
    """라벨이 entity 코드 자체 (KR_RRN 등) 를 포함하지 않음 — §2.5 가드."""
    for etype, label in ENTITY_LABELS_KR.items():
        assert "KR_" not in label
        assert etype not in label  # 본인 코드도 포함 안 됨


def test_fallback_label_is_generic() -> None:
    """fallback 라벨은 일반 명사 — 알 수 없는 entity 도 안전."""
    assert _FALLBACK_LABEL == "개인정보"
    assert label_for("UNKNOWN_ENTITY") == _FALLBACK_LABEL
    assert label_for("") == _FALLBACK_LABEL


def test_label_for_known_entities_returns_specific() -> None:
    """등록된 entity_type 은 fallback 이 아닌 전용 라벨 반환."""
    assert label_for("KR_RRN") != _FALLBACK_LABEL
    assert label_for("KR_RRN") == "주민등록번호"
    assert label_for("EMAIL_ADDRESS") == "이메일"


def test_label_for_bank_account_weak_is_same_as_strong() -> None:
    """`_WEAK` variant 도 동일 사용자 라벨 — 사용자는 strong/weak 구분 안 봄."""
    assert label_for("KR_BANK_ACCOUNT") == label_for("KR_BANK_ACCOUNT_WEAK")


# ── detected_summary_kr — 혼합 입력 ─────────────────────────────────────
def test_summary_mixed_dict_and_object_inputs() -> None:
    """dict 와 object 가 섞인 detections 도 통일 처리."""

    class Det:
        def __init__(self, entity_type: str) -> None:
            self.entity_type = entity_type

    detections: list[Any] = [
        Det("KR_RRN"),
        {"entity_type": "KR_PHONE"},
        Det("EMAIL_ADDRESS"),
    ]
    summary = detected_summary_kr(detections)
    assert "주민등록번호" in summary
    assert "전화번호" in summary
    assert "이메일" in summary


def test_summary_dict_without_entity_type_key_is_skipped() -> None:
    """dict 에 entity_type 키가 없으면 silent skip — partial 입력 안전."""
    detections: list[Any] = [
        {"entity_type": "KR_RRN"},
        {"other_key": "value"},  # entity_type 누락
        {"entity_type": "KR_PHONE"},
    ]
    summary = detected_summary_kr(detections)
    assert "주민등록번호" in summary
    assert "전화번호" in summary


def test_summary_dict_with_non_string_entity_type_skipped() -> None:
    """entity_type 값이 문자열 아니면 skip — defensive."""
    detections: list[Any] = [
        {"entity_type": None},
        {"entity_type": 42},
        {"entity_type": "KR_RRN"},
    ]
    summary = detected_summary_kr(detections)
    assert summary == "주민등록번호"


def test_summary_object_without_entity_type_attr_skipped() -> None:
    """객체에 entity_type 속성 없으면 skip."""

    class NoAttr:
        pass

    detections = [NoAttr(), NoAttr()]
    summary = detected_summary_kr(detections)
    assert summary == ""


def test_summary_object_with_non_string_entity_type_skipped() -> None:
    """객체의 entity_type 이 문자열 아니면 skip."""

    class Bad:
        entity_type = 42

    class Good:
        entity_type = "KR_RRN"

    detections = [Bad(), Good()]
    summary = detected_summary_kr(detections)
    assert summary == "주민등록번호"


def test_summary_empty_list_returns_empty_string() -> None:
    assert detected_summary_kr([]) == ""


def test_summary_iterator_input_consumed_correctly() -> None:
    """generator 도 정상 처리 — Iterable contract."""

    def gen():
        yield {"entity_type": "KR_RRN"}
        yield {"entity_type": "KR_PHONE"}

    assert detected_summary_kr(gen()) == "주민등록번호, 전화번호"


def test_summary_preserves_first_seen_order() -> None:
    """중복 entity 는 첫 등장 순서로만 라벨 추가."""
    detections: list[Any] = [
        {"entity_type": "KR_PHONE"},
        {"entity_type": "KR_RRN"},
        {"entity_type": "KR_PHONE"},  # 중복 — 무시
    ]
    summary = detected_summary_kr(detections)
    parts = [p.strip() for p in summary.split(",")]
    assert parts == ["전화번호", "주민등록번호"]


def test_summary_unknown_entity_uses_fallback_only_once() -> None:
    """다양한 unknown entity 가 fallback 라벨로 deduplicate."""
    detections: list[Any] = [
        {"entity_type": "MYSTERY_1"},
        {"entity_type": "MYSTERY_2"},
        {"entity_type": "MYSTERY_3"},
    ]
    summary = detected_summary_kr(detections)
    # 모두 fallback → dedupe 후 단일 라벨.
    assert summary == _FALLBACK_LABEL


def test_summary_bank_account_strong_and_weak_dedupe_to_one_label() -> None:
    """strong/weak 두 entity 가 같은 라벨이므로 한 번만 나온다."""
    detections: list[Any] = [
        {"entity_type": "KR_BANK_ACCOUNT"},
        {"entity_type": "KR_BANK_ACCOUNT_WEAK"},
    ]
    summary = detected_summary_kr(detections)
    assert summary == "계좌번호"


# ── Body size 미들웨어 ──────────────────────────────────────────────────
def test_default_max_body_bytes_is_1mib() -> None:
    """스펙 T3.9: 1 MiB 기본 한도."""
    assert DEFAULT_MAX_BODY_BYTES == 1 * 1024 * 1024


def test_too_large_response_returns_req_4030() -> None:
    """`_too_large_response` 가 REQ-4030 envelope + HTTP 413."""
    resp = _too_large_response()
    assert resp.status_code == 413
    body = resp.body.decode("utf-8")
    assert "REQ-4030" in body


def test_too_large_response_envelope_has_zero_uuid() -> None:
    """body 가 사용자가 보낸 request_id 를 모를 때 zero UUID 사용."""
    import json

    resp = _too_large_response()
    body = json.loads(resp.body)
    assert body["request_id"] == "00000000-0000-0000-0000-000000000000"
    assert body["code"] == "REQ-4030"
    # ERROR 카테고리 + developer_message 채워짐.
    assert body["verdict"] == "ERROR"


def test_too_large_response_user_message_is_korean() -> None:
    """사용자 메시지가 한국어."""
    import json

    resp = _too_large_response()
    body = json.loads(resp.body)
    assert "본문" in body["user_message"]


def test_body_size_middleware_default_capacity() -> None:
    """기본 인스턴스화 시 ``_max_bytes == DEFAULT_MAX_BODY_BYTES``."""
    mw = BodySizeLimitMiddleware(MagicMock())
    assert mw._max_bytes == DEFAULT_MAX_BODY_BYTES


def test_body_size_middleware_custom_max_bytes() -> None:
    """``max_bytes`` 인자가 그대로 반영."""
    custom = 4 * 1024 * 1024  # 4 MiB
    mw = BodySizeLimitMiddleware(MagicMock(), max_bytes=custom)
    assert mw._max_bytes == custom


def test_body_size_middleware_zero_max_bytes_allowed() -> None:
    """0 byte 한도 — 모든 본문 거절. 의도된 disable 시나리오."""
    mw = BodySizeLimitMiddleware(MagicMock(), max_bytes=0)
    assert mw._max_bytes == 0


def test_too_large_response_json_parseable() -> None:
    """response body 가 valid JSON — 클라이언트 파싱 가능."""
    import json

    resp = _too_large_response()
    parsed = json.loads(resp.body)
    assert isinstance(parsed, dict)
    # envelope 의 필수 필드 모두 존재.
    for key in ("request_id", "verdict", "code", "user_message", "processing_ms"):
        assert key in parsed, f"필드 누락: {key}"


def test_too_large_response_has_developer_message() -> None:
    """REQ-4030 은 ERROR 카테고리이므로 developer_message 채워짐."""
    import json

    resp = _too_large_response()
    body = json.loads(resp.body)
    assert body.get("developer_message") is not None


def test_max_body_bytes_threshold_value() -> None:
    """1 MiB 정확 — `1024 * 1024 = 1,048,576`."""
    assert DEFAULT_MAX_BODY_BYTES == 1_048_576
