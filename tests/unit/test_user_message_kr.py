# SYNTHETIC DATA - NOT REAL PII
"""Phase 4b/C — `build_response` 가 한글 entity 라벨을 안전하게 덧붙이는가.

`detections` 에 잡힌 PII 종류를 사용자에게 친절히 안내하기 위해 BLOCK
응답의 `user_message` 끝에 ``(검출된 항목: 주민등록번호 등)`` 형태의
한글 접미사를 붙인다. 다음 4가지 회귀를 핀(pin) 한다:

  - BLOCK + detections → 한글 라벨 접미사 추가됨
  - 같은 케이스에서 §2.5 (raw entity code 누출) 필터는 여전히 통과
  - PASS 응답에는 detections 가 있어도 접미사가 붙지 않음
  - BLOCK 이지만 detections 가 비어 있으면 템플릿 그대로 유지
"""

from __future__ import annotations

from uuid import uuid4

from app.api.responses import build_response, user_message_safety_violations
from app.api.schemas import Detection


def _det(et: str, *, score: float = 0.95) -> Detection:
    """테스트용 Detection 객체 생성 헬퍼 — `entity_type` 만 다르게 줄 수 있게."""
    return Detection(
        field="post.body",
        entity_type=et,
        code="BLOCK-2099",
        score=score,
        start=0,
        end=5,
    )


def test_block_response_appends_korean_summary() -> None:
    """BLOCK + 2개 entity → "(검출된 항목: 주민등록번호, 전화번호)" 가 붙는다.

    `KR_RRN` 과 `KR_PHONE` 두 종이 잡힌 응답의 `user_message` 에 한글
    라벨이 빠짐없이 등장하는지 확인. 영문 entity 코드가 그대로 노출되면
    사용자 친화성이 무너지므로 회귀 방지가 중요하다.
    """
    resp = build_response(
        request_id=uuid4(),
        code="BLOCK-2001",
        detections=[_det("KR_RRN"), _det("KR_PHONE")],
        processing_ms=42,
    )
    assert "검출된 항목" in resp.user_message
    assert "주민등록번호" in resp.user_message
    assert "전화번호" in resp.user_message


def test_block_response_does_not_leak_raw_entity_codes() -> None:
    """접미사가 붙은 뒤에도 §2.5 금지어 필터가 통과해야 한다.

    `user_message_safety_violations` 는 `KR_RRN`, `EMAIL_ADDRESS` 같은
    raw entity 코드가 사용자 메시지에 새어나가는지를 점검한다. 한글
    라벨로 치환되었으므로 위반 0건이어야 한다.
    """
    resp = build_response(
        request_id=uuid4(),
        code="BLOCK-2001",
        detections=[_det("KR_RRN"), _det("EMAIL_ADDRESS")],
        processing_ms=42,
    )
    # §2.5 필터는 라벨 접미사 추가 후에도 여전히 green 이어야 한다.
    assert user_message_safety_violations(resp.user_message) == []


def test_pass_response_does_not_get_summary_suffix() -> None:
    """PASS 응답에는 detections 가 있어도 접미사를 붙이면 안 된다.

    exception-IP audit-only 경로에서는 본문에 PII 가 검출되어도 응답은
    PASS 로 강제되며, 이때 사용자에게 "검출된 항목" 을 안내하면 정책과
    모순된다.
    """
    resp = build_response(
        request_id=uuid4(),
        code="OK-0000",
        detections=[_det("KR_RRN")],  # 예외 IP audit-only 경로
        processing_ms=42,
    )
    assert "검출된 항목" not in resp.user_message


def test_block_with_no_detections_keeps_template_only() -> None:
    """BLOCK 이지만 detections 가 비어 있으면 템플릿 그대로 유지.

    deny-list 같은 메타 차단은 BLOCK 응답이지만 entity 단위 매치가 없을
    수 있다. 이때 "(검출된 항목: )" 처럼 비어 있는 접미사를 붙이면 안 된다.
    """
    resp = build_response(
        request_id=uuid4(),
        code="BLOCK-2001",
        detections=[],
        processing_ms=42,
    )
    assert "검출된 항목" not in resp.user_message
