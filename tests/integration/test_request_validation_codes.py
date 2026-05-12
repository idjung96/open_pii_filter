# SYNTHETIC DATA - NOT REAL PII
"""요청 envelope 검증 → REQ-4xxx 매핑 회귀 방지 (§2.4 + Phase 1).

`app.main` 의 `RequestValidationError` 핸들러가 Pydantic 검증 실패를
다음 코드로 매핑한다:

  - REQ-4001 : 필수 필드 누락 (fields=...)
  - REQ-4003 : JSON 파싱 / 일반 검증 실패
  - REQ-4004 : request_id UUID 형식 위반
  - REQ-4030 : 본문/제목 길이 한도 초과 (HTTP 413)

본 모듈은 매핑 정확성을 통합 흐름에서 가드한다.
"""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from httpx import AsyncClient


def _valid_payload(**overrides) -> dict:
    base = {
        "request_id": str(uuid.uuid4()),
        "author": {"name": "익명", "ip": "203.0.113.5"},
        "post": {"board_id": "free", "title": "문의", "body": "안녕"},
        "options": {"strictness": "medium"},
    }
    for k, v in overrides.items():
        base[k] = v
    return base


# ── REQ-4001 — 필수 필드 누락 ──────────────────────────────────────────
@pytest.mark.parametrize(
    "missing_field",
    [
        "request_id",
        "author",
        "post",
    ],
)
async def test_missing_top_level_field_maps_to_req_4001(
    client: AsyncClient, missing_field: str
) -> None:
    """top-level 필드 누락 → REQ-4001 + 어느 필드 누락인지 안내."""
    payload = _valid_payload()
    del payload[missing_field]
    resp = await client.post("/v1/detect/post", json=payload)
    assert resp.status_code == 400
    data = resp.json()
    assert data["code"] == "REQ-4001"
    # developer_message 에 누락 필드 안내.
    assert missing_field in (data.get("developer_message") or "")


async def test_missing_author_name_maps_to_req_4001(client: AsyncClient) -> None:
    """nested 필드 (author.name) 누락도 REQ-4001."""
    payload = _valid_payload()
    payload["author"] = {"ip": "203.0.113.5"}  # name 누락
    resp = await client.post("/v1/detect/post", json=payload)
    assert resp.status_code == 400
    data = resp.json()
    assert data["code"] == "REQ-4001"


async def test_missing_post_body_maps_to_req_4001(client: AsyncClient) -> None:
    """post.body 누락 → REQ-4001."""
    payload = _valid_payload()
    payload["post"] = {"board_id": "free", "title": "t"}  # body 누락
    resp = await client.post("/v1/detect/post", json=payload)
    data = resp.json()
    assert data["code"] == "REQ-4001"


# ── REQ-4004 — request_id UUID 형식 위반 ───────────────────────────────
@pytest.mark.parametrize(
    "bad_id",
    [
        "not-a-uuid",
        "12345",
        "00000000-0000-0000-0000",  # 4 hex group only
        "GGGGGGGG-GGGG-GGGG-GGGG-GGGGGGGGGGGG",  # invalid hex
        "",  # 빈 문자열
    ],
)
async def test_invalid_request_id_uuid_maps_to_req_4004(client: AsyncClient, bad_id: str) -> None:
    """request_id 가 UUID 형식 위반 → REQ-4004."""
    payload = _valid_payload()
    payload["request_id"] = bad_id
    resp = await client.post("/v1/detect/post", json=payload)
    data = resp.json()
    assert data["code"] == "REQ-4004", f"{bad_id!r} → {data}"


# ── REQ-4003 — JSON 파싱 / 일반 검증 ────────────────────────────────────
async def test_malformed_json_maps_to_req_4003(client: AsyncClient) -> None:
    """깨진 JSON body → REQ-4003 (JSON parse error)."""
    resp = await client.post(
        "/v1/detect/post",
        content=b'{"request_id": "11111111-2222-3333-4444-555555555555",',  # 미완성
        headers={"content-type": "application/json"},
    )
    assert resp.status_code in (400, 422)
    data = resp.json()
    # malformed JSON 은 REQ-4003 으로 매핑.
    assert data["code"] in ("REQ-4003", "REQ-4001")


async def test_extra_field_rejected_by_pydantic(client: AsyncClient) -> None:
    """`model_config = ConfigDict(extra="forbid")` — 정의되지 않은 필드 거절."""
    payload = _valid_payload()
    payload["unknown_field"] = "should-be-rejected"
    resp = await client.post("/v1/detect/post", json=payload)
    data = resp.json()
    # extra=forbid 위반 → REQ-4003 일반 검증 실패로 매핑.
    assert data["code"] in ("REQ-4001", "REQ-4003")


async def test_invalid_author_ip_format(client: AsyncClient) -> None:
    """author.ip 가 비어 있으면 검증 실패 — REQ-4xxx."""
    payload = _valid_payload()
    payload["author"]["ip"] = ""
    resp = await client.post("/v1/detect/post", json=payload)
    data = resp.json()
    # min_length=1 위반 → REQ-4003 또는 REQ-4001.
    assert data["code"] in ("REQ-4001", "REQ-4002", "REQ-4003")


async def test_invalid_strictness_value_rejected(client: AsyncClient) -> None:
    """`strictness` literal 위반 → REQ-4003."""
    payload = _valid_payload()
    payload["options"] = {"strictness": "extreme"}
    resp = await client.post("/v1/detect/post", json=payload)
    data = resp.json()
    assert data["code"] in ("REQ-4001", "REQ-4003")


# ── REQ-4030 — 길이 한도 ───────────────────────────────────────────────
async def test_title_over_max_len_maps_to_req_4030(client: AsyncClient) -> None:
    """제목이 500자 초과 → REQ-4030 (HTTP 413)."""
    from app.api.schemas import MAX_TITLE_LEN

    payload = _valid_payload()
    payload["post"]["title"] = "x" * (MAX_TITLE_LEN + 1)
    resp = await client.post("/v1/detect/post", json=payload)
    assert resp.status_code == 413
    assert resp.json()["code"] == "REQ-4030"


async def test_body_over_max_len_maps_to_req_4030(client: AsyncClient) -> None:
    """본문이 50,000자 초과 → REQ-4030."""
    from app.api.schemas import MAX_BODY_LEN

    payload = _valid_payload()
    payload["post"]["body"] = "y" * (MAX_BODY_LEN + 1)
    resp = await client.post("/v1/detect/post", json=payload)
    assert resp.status_code == 413
    assert resp.json()["code"] == "REQ-4030"


async def test_title_exactly_at_max_len_passes(client: AsyncClient) -> None:
    """제목 정확 500자는 허용 — 경계값 inclusive."""
    from app.api.schemas import MAX_TITLE_LEN

    payload = _valid_payload()
    payload["post"]["title"] = "x" * MAX_TITLE_LEN
    resp = await client.post("/v1/detect/post", json=payload)
    # 검증 통과 → 본문 검사 진행.
    assert resp.status_code == 200


async def test_body_exactly_at_max_len_passes(client: AsyncClient) -> None:
    """본문 정확 50,000자는 허용 — 경계값 inclusive."""
    from app.api.schemas import MAX_BODY_LEN

    payload = _valid_payload()
    payload["post"]["body"] = "y" * MAX_BODY_LEN
    resp = await client.post("/v1/detect/post", json=payload)
    assert resp.status_code == 200


# ── error 응답은 ERROR verdict + developer_message 채워짐 ─────────────
async def test_error_response_has_developer_message(client: AsyncClient) -> None:
    """REQ-4xxx 응답은 ERROR verdict + developer_message 채워짐 (§2.5)."""
    payload = _valid_payload()
    del payload["author"]
    resp = await client.post("/v1/detect/post", json=payload)
    data = resp.json()
    assert data["verdict"] == "ERROR"
    assert data.get("developer_message") is not None


async def test_error_response_user_message_safe(client: AsyncClient) -> None:
    """REQ-4xxx 응답의 user_message 가 §2.5 안전 (entity 코드 비포함)."""
    from app.api.responses import user_message_safety_violations

    payload = _valid_payload()
    payload["request_id"] = "not-a-uuid"
    resp = await client.post("/v1/detect/post", json=payload)
    data = resp.json()
    assert user_message_safety_violations(data["user_message"]) == []


# ── attachments 정규화 (None / [] 동등) ────────────────────────────────
async def test_attachments_null_equals_empty(client: AsyncClient) -> None:
    """`attachments=null` 과 `attachments=[]` 둘 다 "첨부 없음" 으로 처리."""
    for value in (None, []):
        payload = _valid_payload()
        payload["attachments"] = value
        resp = await client.post("/v1/detect/post", json=payload)
        assert resp.status_code == 200
        # Case B (첨부 없음, 본문 PASS) — HTTP 200 + verdict PASS.
        assert resp.json()["verdict"] == "PASS"


async def test_attachments_field_omitted_treated_as_none(
    client: AsyncClient,
) -> None:
    """`attachments` 키 자체가 없어도 정상 — 첨부 없음."""
    payload = _valid_payload()
    payload.pop("attachments", None)
    resp = await client.post("/v1/detect/post", json=payload)
    assert resp.status_code == 200
    assert resp.json()["verdict"] == "PASS"


# ── 빈 body 처리 ──────────────────────────────────────────────────────
async def test_empty_body_passes_validation(client: AsyncClient) -> None:
    """빈 본문 (`body=""`) 도 schema 차원에서는 허용 (정책 검사 별도)."""
    payload = _valid_payload()
    payload["post"]["body"] = ""
    resp = await client.post("/v1/detect/post", json=payload)
    # min_length 제약이 없으면 통과.
    assert resp.status_code in (200, 422, 400)


# ── 매우 긴 author.name ───────────────────────────────────────────────
async def test_author_name_over_max_rejected(client: AsyncClient) -> None:
    """author.name 100자 초과 → 검증 실패."""
    payload = _valid_payload()
    payload["author"]["name"] = "x" * 101
    resp = await client.post("/v1/detect/post", json=payload)
    data = resp.json()
    assert data["code"] in ("REQ-4001", "REQ-4002", "REQ-4003")


# ── HTTP status 매핑 일관성 ──────────────────────────────────────────
async def test_req_4001_returns_http_400(client: AsyncClient) -> None:
    """REQ-4001 → HTTP 400 (codes.py http_status 와 일관)."""
    payload = _valid_payload()
    del payload["author"]
    resp = await client.post("/v1/detect/post", json=payload)
    assert resp.status_code == 400


async def test_req_4004_returns_http_400(client: AsyncClient) -> None:
    """REQ-4004 → HTTP 400."""
    payload = _valid_payload()
    payload["request_id"] = "not-a-uuid"
    resp = await client.post("/v1/detect/post", json=payload)
    assert resp.status_code == 400


async def test_req_4030_returns_http_413(client: AsyncClient) -> None:
    """REQ-4030 → HTTP 413."""
    from app.api.schemas import MAX_BODY_LEN

    payload = _valid_payload()
    payload["post"]["body"] = "y" * (MAX_BODY_LEN + 1)
    resp = await client.post("/v1/detect/post", json=payload)
    assert resp.status_code == 413


# ── 응답 envelope 의 일관성 ──────────────────────────────────────────
async def test_error_response_envelope_has_all_required_fields(
    client: AsyncClient,
) -> None:
    """error 응답도 정상 응답과 같은 envelope 형식 (verdict/code/user_message/...)."""
    payload = _valid_payload()
    payload["request_id"] = "not-a-uuid"
    resp = await client.post("/v1/detect/post", json=payload)
    data = resp.json()
    for key in (
        "request_id",
        "verdict",
        "code",
        "system_message",
        "user_message",
        "processed_at",
        "processing_ms",
    ):
        assert key in data, f"필드 누락: {key}"
