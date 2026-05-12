# SYNTHETIC DATA - NOT REAL PII
"""KR PII end-to-end 회귀 방지 — POST /v1/detect/post 통합.

기존 통합 테스트는 Case C (첨부) / 첨부 정책 / 인증을 다룬다. 본 모듈은
*본문 단독* 시나리오에서 한국 PII 인식기 각각이:

  - 정확한 BLOCK 코드 (`BLOCK-2001` ~ `BLOCK-2099`) 로 매핑되는지
  - 사용자 메시지가 §2.5 안전 (entity 코드 / score / 평문 PII 비노출)
  - `detections` 배열에 entity_type 가 정확히 채워지는지
  - HTTP 200 (PASS/BLOCK 모두 통합 200)

검사 대상 (Korean recognizers):
  - KR_RRN     → BLOCK-2001
  - KR_DRIVERLICENSE → BLOCK-2002
  - KR_PASSPORT → BLOCK-2003
  - CREDIT_CARD → BLOCK-2005
  - KR_BANK_ACCOUNT (strong) → BLOCK-2006
  - KR_PHONE   → BLOCK-2099
  - KR_BUSINESS_NUM → BLOCK-2099
  - EMAIL_ADDRESS → BLOCK-2099

`client` fixture 가 auth 를 stub 으로 우회하므로 HMAC 서명 없이 바로
바디 검사 흐름을 검증한다.
"""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING

import pytest

from app.api.responses import user_message_safety_violations

if TYPE_CHECKING:
    from httpx import AsyncClient


def _make_post_payload(*, body: str, board_id: str = "free", strictness: str = "medium") -> dict:
    """요청 envelope 헬퍼."""
    return {
        "request_id": str(uuid.uuid4()),
        "author": {"name": "익명123", "ip": "203.0.113.5"},
        "post": {"board_id": board_id, "title": "문의", "body": body},
        "options": {"strictness": strictness},
    }


# ── 각 KR 인식기 단독 → BLOCK ────────────────────────────────────────────
@pytest.mark.parametrize(
    ("body", "expected_code", "expected_entity"),
    [
        # KR_RRN — 합성 generator 가 만든 체크섬 통과 RRN.
        ("주민등록번호 900201-2320987 입니다.", "BLOCK-2001", "KR_RRN"),
        # KR_DRIVERLICENSE — RR-YY-NNNNNN-CC
        ("운전면허번호 11-23-123456-78 입니다.", "BLOCK-2002", "KR_DRIVERLICENSE"),
        # KR_PASSPORT — M + 8 digits
        ("여권번호 M12345678 입니다.", "BLOCK-2003", "KR_PASSPORT"),
        # KR_BANK_ACCOUNT (strong 3-2-4-3 형식)
        ("계좌번호 123-45-6789-012 입니다.", "BLOCK-2006", "KR_BANK_ACCOUNT"),
        # KR_PHONE — 010 mobile
        ("연락처 010-1234-5678 입니다.", "BLOCK-2099", "KR_PHONE"),
    ],
)
async def test_each_kr_recognizer_blocks_body_e2e(
    client: AsyncClient,
    body: str,
    expected_code: str,
    expected_entity: str,
) -> None:
    """각 한국 PII 인식기가 본문 단독 BLOCK 흐름에서 정확한 코드 / verdict."""
    resp = await client.post(
        "/v1/detect/post",
        json=_make_post_payload(body=body),
    )
    assert resp.status_code == 200, f"unexpected status {resp.status_code}: {resp.text}"
    data = resp.json()
    assert data["verdict"] == "BLOCK", f"{body} → {data}"
    assert data["code"] == expected_code, f"{body} → {data}"
    # detections 안에 expected_entity 가 들어 있어야 함.
    entity_types = {d["entity_type"] for d in data.get("detections", [])}
    assert expected_entity in entity_types, (
        f"detections 에 {expected_entity} 없음: {entity_types}"
    )


async def test_email_body_blocks_with_block_2099(client: AsyncClient) -> None:
    """이메일 단독 BLOCK — 강한 신호 (score ≥ 0.85) 라 medium BLOCK 진입."""
    resp = await client.post(
        "/v1/detect/post",
        json=_make_post_payload(body="문의 시 victim@example.com 으로 회신 부탁드립니다."),
    )
    data = resp.json()
    assert data["verdict"] == "BLOCK"
    assert data["code"] == "BLOCK-2099"


async def test_credit_card_body_blocks_with_block_2005(
    client: AsyncClient,
) -> None:
    """신용카드 단독 BLOCK → BLOCK-2005 + CREDIT_CARD detection."""
    # Stripe test 카드 4242 4242 4242 4242 (Luhn-valid).
    resp = await client.post(
        "/v1/detect/post",
        json=_make_post_payload(
            body="카드번호 4242-4242-4242-4242 결제 부탁드립니다.",
        ),
    )
    data = resp.json()
    assert data["verdict"] == "BLOCK"
    assert data["code"] == "BLOCK-2005"


async def test_business_num_body_blocks_with_block_2099(
    client: AsyncClient,
) -> None:
    """사업자등록번호 단독 BLOCK → BLOCK-2099."""
    from tests.fixtures.synthetic_pii_generator import SyntheticPIIGenerator

    g = SyntheticPIIGenerator(seed=42)
    biz = g.gen_business_num(valid=True)
    resp = await client.post(
        "/v1/detect/post",
        json=_make_post_payload(body=f"사업자등록번호 {biz} 로 발행 부탁드립니다."),
    )
    data = resp.json()
    assert data["verdict"] == "BLOCK"
    assert data["code"] == "BLOCK-2099"


# ── PASS 시나리오 ───────────────────────────────────────────────────────
async def test_clean_body_passes_with_ok_0000(client: AsyncClient) -> None:
    """PII 없는 일반 게시글 → OK-0000."""
    resp = await client.post(
        "/v1/detect/post",
        json=_make_post_payload(body="안녕하세요. 일반 문의사항 입니다."),
    )
    data = resp.json()
    assert data["verdict"] == "PASS"
    assert data["code"] in ("OK-0000", "OK-0001")


# ── §2.5 평문 비노출 통합 검증 ──────────────────────────────────────────
@pytest.mark.parametrize(
    "body",
    [
        "주민 900201-2320987",
        "전화 010-1234-5678",
        "이메일 victim@example.com",
        "카드 4242-4242-4242-4242",
        "여권 M12345678",
    ],
)
async def test_user_message_does_not_leak_plaintext_pii(
    client: AsyncClient, body: str
) -> None:
    """BLOCK 응답의 user_message 에 원본 평문 PII 가 절대 등장하지 않음."""
    resp = await client.post(
        "/v1/detect/post",
        json=_make_post_payload(body=body),
    )
    data = resp.json()
    user_message = data.get("user_message", "")
    # 평문 PII 가 응답 message 에 그대로 들어가면 §2.5 위반.
    plaintext_parts = body.split()
    for part in plaintext_parts:
        if any(c.isdigit() for c in part) or "@" in part:
            assert part not in user_message, (
                f"평문 {part!r} 가 user_message 에 노출: {user_message}"
            )
    # §2.5 금지어도 비포함.
    assert user_message_safety_violations(user_message) == []


# ── developer_message 는 BLOCK 응답에서 None ───────────────────────────
async def test_block_response_has_no_developer_message(
    client: AsyncClient,
) -> None:
    """BLOCK 응답에서 developer_message 가 None (§2.5)."""
    resp = await client.post(
        "/v1/detect/post",
        json=_make_post_payload(body="주민 900201-2320987"),
    )
    data = resp.json()
    assert data["verdict"] == "BLOCK"
    assert data.get("developer_message") is None


# ── HTTP 200 통합 — PASS/BLOCK 모두 200 ────────────────────────────────
async def test_block_response_uses_http_200(client: AsyncClient) -> None:
    """BLOCK 도 HTTP 200 (envelope 안에 verdict 명시 — REST 패턴)."""
    resp = await client.post(
        "/v1/detect/post",
        json=_make_post_payload(body="주민 900201-2320987"),
    )
    assert resp.status_code == 200


# ── detection 메타데이터 포맷 ─────────────────────────────────────────
async def test_detection_object_contains_required_fields(
    client: AsyncClient,
) -> None:
    """detections[*] 가 field / entity_type / code / score / start / end 포함."""
    resp = await client.post(
        "/v1/detect/post",
        json=_make_post_payload(body="주민 900201-2320987"),
    )
    data = resp.json()
    assert data["detections"], "detections 비어 있음"
    det = data["detections"][0]
    for key in ("field", "entity_type", "code", "score", "start", "end"):
        assert key in det, f"detection 필드 누락: {key}"
    # field 는 post.body / post.title 패턴.
    assert det["field"].startswith("post.")
    # score 는 0~1 범위.
    assert 0.0 <= det["score"] <= 1.0


# ── request_id echo ────────────────────────────────────────────────────
async def test_request_id_echoed_in_response(client: AsyncClient) -> None:
    """request_id 가 응답에 그대로 echo (멱등성 키 추적용)."""
    rid = str(uuid.uuid4())
    payload = _make_post_payload(body="안녕하세요")
    payload["request_id"] = rid
    resp = await client.post("/v1/detect/post", json=payload)
    data = resp.json()
    assert data["request_id"] == rid


# ── title PII 도 검출 ──────────────────────────────────────────────────
async def test_title_pii_also_blocks(client: AsyncClient) -> None:
    """제목에 PII 가 있어도 동일하게 BLOCK."""
    payload = _make_post_payload(body="문의입니다.")
    payload["post"]["title"] = "본인 010-1234-5678"
    resp = await client.post("/v1/detect/post", json=payload)
    data = resp.json()
    assert data["verdict"] == "BLOCK"
    # detection.field 가 post.title 인 것이 하나 이상.
    title_dets = [d for d in data["detections"] if d["field"] == "post.title"]
    assert title_dets, f"title detection 없음: {data['detections']}"
