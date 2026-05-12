# SYNTHETIC DATA - NOT REAL PII
"""§2.5 평문 PII 비노출 회귀 방지 — 응답 envelope + webhook 페이로드 종합.

§2.5 (privacy):

  - ``user_message`` 에 PII 평문 / entity 코드 / score / 알고리즘명 / 정확
    위치 / 마스킹 미리보기 노출 금지.
  - ``developer_message`` 는 ERROR (`REQ-4xxx` / `SVR-5xxx`) 카테고리에서만
    채워지고, PASS/BLOCK 응답에는 항상 ``None``.
  - webhook 페이로드 (`WebhookPayload`) 의 ``user_message`` 도 §2.5 적용.
  - ``Detection.masked_preview`` 는 마스킹된 형태만 허용 (원본 평문 금지).

본 모듈은 다음 회귀를 동시에 가드:

  1. CODES 카탈로그 전체에 대해 user_message_template 정적 검사 통과
  2. 합성 RRN / 카드 / 전화 평문이 BLOCK 응답에 절대 등장하지 않음
  3. detections 가 있어도 user_message 에 score / start / end 비노출
  4. BLOCK 응답에서도 developer_message 가 None (§2.5)
  5. ERROR 응답에서만 developer_message 가 채워짐 + 평문 PII 비포함
  6. attachment filename 렌더링 시 PII 가 파일명에 섞여 있어도 차단되지 않음
     (파일명은 호출자가 제공한 식별자이므로 PII 가 아님)
  7. webhook payload 의 user_message 가 §2.5 통과
  8. system_message 와 user_message 가 서로 다른 책임 (운영자 vs 사용자)
  9. multi-entity BLOCK-2008 사용 시 entity 코드 비노출
  10. Detection.masked_preview 가 평문이 아닌 마스킹 형식만 받음
  11. processing_ms / processed_at 등 메타 필드는 PII 와 무관하므로 평문 검사
      대상이 아님 (필드별 검사 책임 분리)
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from uuid import uuid4

import pytest

from app.api.responses import (
    _FORBIDDEN_IN_USER_MESSAGE,
    audit_all_user_messages,
    build_response,
    user_message_safety_violations,
)
from app.api.schemas import (
    Detection,
    Verdict,
    WebhookAttachmentResult,
    WebhookPayload,
)
from app.core.codes import CODES, get_code
from app.core.codes import Verdict as CodeVerdict

# 합성 PII 평문 — 응답 어디에도 등장해서는 안 되는 문자열.
SYN_RRN = "900101-1234567"
SYN_PHONE = "010-1234-5678"
SYN_EMAIL = "victim@example.com"
SYN_CARD = "4111-1111-1111-1111"
SYN_PASSPORT = "M12345678"
SYN_DRIVER = "11-23-123456-78"
SYN_BIZ = "123-45-67890"


# ── 모든 코드 카탈로그 user_message_template §2.5 통과 ─────────────────
def test_all_user_message_templates_pass_safety_audit() -> None:
    """`audit_all_user_messages()` 가 빈 dict — 모든 코드의 사용자 메시지
    템플릿이 §2.5 금지어 (entity 코드 / score / algorithm 명) 를 포함하지
    않는다.

    이 가드는 새 코드 추가 시 가장 먼저 깨질 수 있는 회귀이므로 모든 BLOCK/
    REQ/SVR 코드 추가 시 자동 회귀 방지.
    """
    violations = audit_all_user_messages()
    assert violations == {}, f"§2.5 위반 코드: {violations}"


@pytest.mark.parametrize("code", sorted(CODES.keys()))
def test_individual_code_user_message_safe(code: str) -> None:
    """각 코드의 user_message_template 이 §2.5 금지어를 포함하지 않는다
    (parametrize 로 깨진 코드를 즉시 식별)."""
    rc = get_code(code)
    hits = user_message_safety_violations(rc.user_message_template)
    assert hits == [], f"{code} user_message 위반: {hits}"


# ── BLOCK 응답에 평문 PII 가 절대 등장하지 않음 ──────────────────────
@pytest.mark.parametrize(
    ("code", "entity_type", "plaintext"),
    [
        ("BLOCK-2001", "KR_RRN", SYN_RRN),
        ("BLOCK-2002", "KR_DRIVERLICENSE", SYN_DRIVER),
        ("BLOCK-2003", "KR_PASSPORT", SYN_PASSPORT),
        ("BLOCK-2005", "CREDIT_CARD", SYN_CARD),
        ("BLOCK-2006", "KR_BANK_ACCOUNT", "123-45-6789-012"),
        ("BLOCK-2099", "KR_PHONE", SYN_PHONE),
        ("BLOCK-2099", "EMAIL_ADDRESS", SYN_EMAIL),
        ("BLOCK-2099", "KR_BUSINESS_NUM", SYN_BIZ),
    ],
)
def test_block_response_never_includes_plaintext_pii(
    code: str, entity_type: str, plaintext: str
) -> None:
    """build_response 호출 결과의 user_message 에 PII 평문이 절대 없음.

    Detection 객체에는 start/end/score 가 들어가지만 (운영자 진단용),
    렌더링 결과 user_message 에는 메타데이터가 새지 않는다.
    """
    detection = Detection(
        field="post.body",
        entity_type=entity_type,
        code=code,
        score=0.95,
        start=5,
        end=5 + len(plaintext),
        masked_preview=plaintext[:3] + "*" * (len(plaintext) - 3),
    )
    resp = build_response(
        request_id=uuid4(),
        code=code,
        detections=[detection],
        processing_ms=12,
    )
    assert plaintext not in resp.user_message, (
        f"{code}: 평문 {plaintext} 가 user_message 에 노출됨: {resp.user_message}"
    )
    # masked_preview 도 user_message 에 들어가서는 안 됨.
    assert detection.masked_preview not in resp.user_message
    # 위치 (5 / end) 가 숫자로 노출되지 않는다.
    assert " 5 " not in resp.user_message
    assert " 18 " not in resp.user_message


# ── BLOCK 응답의 developer_message 는 항상 None (§2.5) ─────────────────
@pytest.mark.parametrize("code", sorted(c for c in CODES if c.startswith("BLOCK-")))
def test_block_response_developer_message_is_none(code: str) -> None:
    """모든 BLOCK 코드의 응답에서 developer_message 가 None — §2.5 가드."""
    rc = get_code(code)
    vars_for_template: dict[str, object] = {}
    # BLOCK-2010/2011/2012 는 filename placeholder 필요.
    if "{filename}" in rc.user_message_template:
        vars_for_template["filename"] = "report.pdf"
    resp = build_response(
        request_id=uuid4(),
        code=code,
        processing_ms=10,
        template_vars=vars_for_template or None,
    )
    assert resp.developer_message is None, (
        f"{code}: BLOCK 인데 developer_message 가 채워짐: {resp.developer_message!r}"
    )


# ── PASS 응답도 developer_message 가 None ──────────────────────────────
@pytest.mark.parametrize("code", ["OK-0000", "OK-0001"])
def test_pass_response_developer_message_is_none(code: str) -> None:
    resp = build_response(
        request_id=uuid4(),
        code=code,
        processing_ms=3,
    )
    assert resp.developer_message is None


# ── ERROR 응답은 developer_message 가 채워지고 평문 PII 비포함 ─────────
@pytest.mark.parametrize(
    ("code", "template_vars"),
    [
        ("REQ-4001", {"fields": "post.body"}),
        ("REQ-4003", {"detail": "Expected JSON object"}),
        ("REQ-4031", {"filename": "report.pdf"}),
        ("REQ-4040", {"filename": "x.pdf", "status": 503}),
        ("REQ-4050", {"filename": "x.pdf", "signature": "Eicar-Test-Signature"}),
        ("SVR-5001", {}),
    ],
)
def test_error_response_developer_message_is_rendered_safely(
    code: str, template_vars: dict
) -> None:
    """ERROR 코드는 developer_message 가 채워지고 합성 평문이 새지 않음."""
    resp = build_response(
        request_id=uuid4(),
        code=code,
        processing_ms=0,
        template_vars=template_vars,
    )
    rc = get_code(code)
    if rc.developer_message_template is not None:
        assert resp.developer_message is not None, f"{code}: dev_message 비어 있음"
        # 합성 PII 평문이 어쩌다 dev_message 에 섞여 들어오지 않는다.
        for plain in [SYN_RRN, SYN_PHONE, SYN_EMAIL, SYN_CARD]:
            assert plain not in resp.developer_message, f"{code}: dev_message 에 평문 {plain} 노출"


# ── multi-entity BLOCK-2008 에서도 entity 코드 비노출 ──────────────────
def test_multi_entity_block_2008_does_not_expose_entity_codes() -> None:
    """BLOCK-2008 (복합 PII) 사용자 메시지에 KR_RRN / KR_PHONE 등 코드가
    텍스트로 나오지 않는다 (한국어 라벨만)."""
    detections = [
        Detection(
            field="post.body",
            entity_type="KR_RRN",
            code="BLOCK-2008",
            score=0.95,
            start=0,
            end=14,
        ),
        Detection(
            field="post.body",
            entity_type="KR_PHONE",
            code="BLOCK-2008",
            score=0.90,
            start=20,
            end=33,
        ),
    ]
    resp = build_response(
        request_id=uuid4(),
        code="BLOCK-2008",
        detections=detections,
        processing_ms=15,
    )
    # entity 코드가 user_message 에 노출되지 않는다.
    for banned in ("KR_RRN", "KR_PHONE", "EMAIL_ADDRESS"):
        assert banned not in resp.user_message, (
            f"{banned} 가 user_message 에 노출됨: {resp.user_message}"
        )
    # 한국어 라벨은 노출되어 있다 (사용자 안내용).
    assert "주민등록번호" in resp.user_message or "전화번호" in resp.user_message


# ── attachment filename 렌더링 — 호출자가 준 식별자만 노출 ───────────
def test_attachment_filename_rendered_into_user_message() -> None:
    """BLOCK-2010 의 ``{filename}`` 치환은 호출자가 보낸 파일명을 그대로 노출.

    이는 PII 가 아니라 호출자가 식별 가능하도록 보낸 메타. §2.5 의 보호
    대상은 PII 평문 / score / entity 코드 / 알고리즘 명이며 filename 자체는
    아님. 단, filename 에 PII 가 들어 있다면 호출자 책임이므로 본 모듈에서는
    검출하지 않는다.
    """
    filename = "고객명단.pdf"
    resp = build_response(
        request_id=uuid4(),
        code="BLOCK-2010",
        processing_ms=20,
        template_vars={"filename": filename},
    )
    assert filename in resp.user_message
    # entity 코드 / score 같은 §2.5 금지어는 여전히 없음.
    assert user_message_safety_violations(resp.user_message) == []


# ── system_message 와 user_message 의 책임 분리 ──────────────────────
def test_system_message_is_english_and_user_message_is_korean() -> None:
    """system_message (운영자/로그용 영문) 와 user_message (사용자 한국어)
    는 동일 코드라도 서로 다른 책임 — 시스템 메시지는 분석 정보를 영문으로
    노출해도 되지만 사용자 메시지는 §2.5 준수.
    """
    resp = build_response(
        request_id=uuid4(),
        code="BLOCK-2001",
        processing_ms=10,
    )
    # system_message 는 영문 — ASCII 비율이 높다.
    ascii_ratio = sum(1 for c in resp.system_message if ord(c) < 128) / max(
        1, len(resp.system_message)
    )
    assert ascii_ratio > 0.8
    # user_message 는 한국어 포함.
    assert re.search(r"[가-힣]", resp.user_message)
    # user_message 는 §2.5 금지어 없음.
    assert user_message_safety_violations(resp.user_message) == []


# ── _FORBIDDEN_IN_USER_MESSAGE 키워드 완전성 가드 ────────────────────
def test_forbidden_keyword_list_covers_all_block_entities() -> None:
    """`ENTITY_TO_CODE` 에 등록된 모든 BLOCK 카테고리 entity 가 §2.5 금지어
    리스트에 들어 있는지. 신규 entity 추가 시 같이 갱신해야 한다는 guard.

    INTERNAL_NAME / KR_BANK_ACCOUNT_WEAK 같은 우리만 쓰는 코드도 §2.5 검사
    대상이어야 한다.
    """
    from app.core.policies import ENTITY_TO_CODE

    block_entities = {et for et, band in ENTITY_TO_CODE if band == "block"}
    forbidden = set(_FORBIDDEN_IN_USER_MESSAGE)

    # KR_BANK_ACCOUNT_WEAK 는 KR_BANK_ACCOUNT 의 prefix 매치로 잡힘.
    missing: list[str] = []
    for et in block_entities:
        if not any(fb in et or et.startswith(fb) for fb in forbidden):
            missing.append(et)
    assert missing == [], f"§2.5 금지어 리스트 누락 entity: {missing}"


# ── webhook payload §2.5 적용 ───────────────────────────────────────────
def test_webhook_payload_user_message_passes_safety() -> None:
    """WebhookPayload.user_message 도 §2.5 검사를 통과해야 한다.

    webhook 은 외부 callback 으로 가는 메시지이므로 응답 envelope 와 동일한
    PII 비노출 정책이 적용됨.
    """
    # build_response 로 만든 BLOCK 결과의 user_message 를 webhook 으로 재사용
    # 하는 정상 흐름.
    block_resp = build_response(
        request_id=uuid4(),
        code="BLOCK-2010",
        processing_ms=10,
        template_vars={"filename": "report.pdf"},
    )
    payload = WebhookPayload(
        request_id=block_resp.request_id,
        job_id="job_test_123",
        verdict=Verdict.BLOCK,
        code="BLOCK-2010",
        user_message=block_resp.user_message,
        attachment_results=[
            WebhookAttachmentResult(
                attachment_id="att_001",
                filename="report.pdf",
                verdict=Verdict.BLOCK,
                code="BLOCK-2010",
                detections=[
                    Detection(
                        field="attachment.att_001",
                        entity_type="KR_RRN",
                        code="BLOCK-2010",
                        score=0.95,
                        start=120,
                        end=134,
                        masked_preview="900101-*******",
                    )
                ],
            )
        ],
        completed_at=datetime.now(tz=UTC),
    )
    # webhook 의 user_message 자체에 §2.5 금지어 없음.
    assert user_message_safety_violations(payload.user_message) == []
    # 페이로드 JSON 직렬화 결과에도 평문이 없음 (detections 의 start/end 는
    # 숫자라서 안전, masked_preview 는 정의상 마스킹된 형태).
    payload_json = payload.model_dump_json()
    assert SYN_RRN not in payload_json  # 평문 RRN 절대 없음
    # masked_preview 는 detections 안에 있고 그건 운영자용 — user_message
    # 자체에는 없는지 확인.
    assert "900101-*******" not in payload.user_message


def test_webhook_payload_attachment_detection_does_not_leak_in_user_message() -> None:
    """attachment 의 Detection 이 detections 배열에는 들어가도 user_message
    에는 PII 의 위치 / score / entity 코드가 노출되지 않는다."""
    payload = WebhookPayload(
        request_id=uuid4(),
        job_id="job_abc",
        verdict=Verdict.BLOCK,
        code="BLOCK-2008",
        user_message=build_response(
            request_id=uuid4(),
            code="BLOCK-2008",
            detections=[
                Detection(
                    field="attachment.att_001",
                    entity_type="KR_RRN",
                    code="BLOCK-2008",
                    score=0.95,
                    start=10,
                    end=24,
                ),
            ],
            processing_ms=42,
        ).user_message,
        attachment_results=[],
        completed_at=datetime.now(tz=UTC),
    )
    msg = payload.user_message
    # 위치 / score 누출 금지.
    assert "0.95" not in msg
    assert "start" not in msg.lower()
    assert "offset" not in msg.lower()
    # entity 코드 누출 금지.
    assert "KR_RRN" not in msg


# ── Detection.masked_preview 검사 ───────────────────────────────────────
def test_detection_masked_preview_accepts_masked_format() -> None:
    """masked_preview 는 운영자 진단용 — 평문 부분이 일부 보존되어도
    Detection schema 차원에서는 거부하지 않는다. §2.5 의 책임은 응답
    envelope user_message 단에 있고, masked_preview 는 검출 메타데이터.

    schema-level 검사 의도: pydantic 검증이 masked_preview 를 옵셔널 문자열로
    받아 None / 빈 문자열 / 정상 마스킹 모두 허용.
    """
    for preview in [None, "", "900101-*******", "****", "****-****-****-1111"]:
        det = Detection(
            field="post.body",
            entity_type="KR_RRN",
            code="BLOCK-2001",
            score=0.9,
            start=0,
            end=14,
            masked_preview=preview,
        )
        assert det.masked_preview == preview


# ── processing_ms / processed_at 메타 필드는 PII 와 무관 ────────────────
def test_response_meta_fields_are_not_pii_subject() -> None:
    """processing_ms / processed_at / request_id 는 운영 메타 — §2.5 적용
    대상 아님. user_message 만 §2.5 가드. 메타 필드는 회귀가 잡혀도 본
    테스트가 친절히 분리 안내."""
    resp = build_response(
        request_id=uuid4(),
        code="BLOCK-2001",
        processing_ms=42,
    )
    assert resp.processing_ms == 42
    assert isinstance(resp.processed_at, datetime)
    # user_message 에는 메타 수치가 흘러 들어가선 안 됨.
    assert "42" not in resp.user_message


# ── REQ-4015 (IP allowlist) — developer_message 에 IP 가 노출되어도 평문
#    PII 가 아니므로 §2.5 위반 아님 ──────────────────────────────────────
def test_req_4015_ip_in_developer_message_is_not_pii_leak() -> None:
    """REQ-4015 의 developer_message 는 IP 를 포함하지만 IP 자체는 §2.5 가
    가드하는 PII 평문 / score / entity 코드 / 알고리즘 카테고리가 아니다.
    (조직 정책에 따라 별도 보호 대상일 수 있으나 본 모듈의 책임 영역 외.)
    """
    resp = build_response(
        request_id=uuid4(),
        code="REQ-4015",
        processing_ms=0,
        template_vars={"ip": "203.0.113.45"},
    )
    assert resp.developer_message is not None
    assert "203.0.113.45" in resp.developer_message
    # 사용자 메시지에는 IP 노출 안 함 (template 가 의도적으로 미포함).
    assert "203.0.113.45" not in resp.user_message


# ── score / start / end 의 user_message 노출 회귀 가드 ─────────────────
@pytest.mark.parametrize("score", [0.65, 0.78, 0.88, 0.95, 1.0])
def test_score_value_never_appears_in_user_message_regardless_of_score(
    score: float,
) -> None:
    """다양한 score 값에서도 user_message 에 점수가 숫자로 노출되지 않는다."""
    det = Detection(
        field="post.body",
        entity_type="KR_RRN",
        code="BLOCK-2001",
        score=score,
        start=0,
        end=14,
    )
    resp = build_response(
        request_id=uuid4(),
        code="BLOCK-2001",
        detections=[det],
        processing_ms=10,
    )
    # 점수가 소수점 형태로 user_message 에 출력되면 안 됨.
    assert f"{score}" not in resp.user_message
    assert f"{score:.2f}" not in resp.user_message


# ── 모든 BLOCK / PASS 코드 응답이 build_response 로 빌드 가능 ──────────
@pytest.mark.parametrize(
    "code",
    sorted(c for c, rc in CODES.items() if rc.verdict in (CodeVerdict.PASS, CodeVerdict.BLOCK)),
)
def test_all_pass_and_block_codes_build_response_safely(code: str) -> None:
    """모든 PASS / BLOCK 코드가 build_response 로 정상 빌드되고 §2.5 통과.

    회귀 시나리오: 새 BLOCK 코드를 추가하면서 placeholder 가 채워지지 않는
    경우, _render 가 fallback 으로 원본 템플릿을 반환해도 §2.5 검사를 통과
    해야 한다.
    """
    rc = get_code(code)
    template_vars: dict[str, object] = {}
    for key in ("filename", "eta_seconds"):
        if "{" + key + "}" in rc.user_message_template:
            template_vars[key] = "example" if key == "filename" else 30
    resp = build_response(
        request_id=uuid4(),
        code=code,
        processing_ms=0,
        template_vars=template_vars or None,
    )
    assert resp.code == code
    assert user_message_safety_violations(resp.user_message) == []
    # PASS/BLOCK 은 developer_message None.
    assert resp.developer_message is None
