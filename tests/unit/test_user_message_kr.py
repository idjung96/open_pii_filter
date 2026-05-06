# SYNTHETIC DATA - NOT REAL PII
"""Phase 4b/C — `build_response` Korean entity-label suffix.

Verifies:
  - BLOCK code with detections gets a "(검출된 항목: …)" suffix
  - PASS code never gets the suffix even if detections present
  - the §2.5 forbidden filter still passes (no raw entity codes leak)
  - WARN/ERROR codes are unaffected
"""

from __future__ import annotations

from uuid import uuid4

from app.api.responses import build_response, user_message_safety_violations
from app.api.schemas import Detection


def _det(et: str, *, score: float = 0.95) -> Detection:
    return Detection(
        field="post.body",
        entity_type=et,
        code="BLOCK-2099",
        score=score,
        start=0,
        end=5,
    )


def test_block_response_appends_korean_summary() -> None:
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
    resp = build_response(
        request_id=uuid4(),
        code="BLOCK-2001",
        detections=[_det("KR_RRN"), _det("EMAIL_ADDRESS")],
        processing_ms=42,
    )
    # The §2.5 filter must stay green even after the suffix is appended.
    assert user_message_safety_violations(resp.user_message) == []


def test_pass_response_does_not_get_summary_suffix() -> None:
    resp = build_response(
        request_id=uuid4(),
        code="OK-0000",
        detections=[_det("KR_RRN")],  # exception-IP audit-only path
        processing_ms=42,
    )
    assert "검출된 항목" not in resp.user_message


def test_block_with_no_detections_keeps_template_only() -> None:
    resp = build_response(
        request_id=uuid4(),
        code="BLOCK-2001",
        detections=[],
        processing_ms=42,
    )
    assert "검출된 항목" not in resp.user_message
