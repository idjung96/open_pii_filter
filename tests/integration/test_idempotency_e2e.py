# SYNTHETIC DATA - NOT REAL PII
"""멱등성 캐시 end-to-end 회귀 방지 (§2.6 + Phase 1).

`POST /v1/detect/post` 의 24h 멱등성:

  - 같은 ``request_id`` 재전송 → 원본 응답 byte-for-byte 동일 (캐시 hit)
  - 다른 ``request_id`` → 독립 호출
  - cache 가 빈 상태에서 시작 → 첫 호출 NEW, 두 번째 COMPLETED
  - cache.release() 후 같은 request_id → 다시 NEW 처럼 처리

REQ-4005 (in-progress 동시 호출) 의 *진정한* race condition 은 메인 스레드
한 개로는 재현 불가하므로 unit-level (`test_hmac_idempotency_boundary.py`) 의
IdempotencyCache reserve / IN_PROGRESS 분기로 검증된다.
"""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from httpx import AsyncClient


def _payload(*, request_id: str, body: str = "안녕하세요") -> dict:
    return {
        "request_id": request_id,
        "author": {"name": "익명", "ip": "203.0.113.5"},
        "post": {"board_id": "free", "title": "문의", "body": body},
        "options": {"strictness": "medium"},
    }


@pytest.fixture(autouse=True)
def _clear_idempotency_cache() -> None:
    """각 테스트마다 깨끗한 cache 시작."""
    from app.security.idempotency import get_cache

    get_cache().clear()
    yield
    get_cache().clear()


# ── 기본 멱등성 ──────────────────────────────────────────────────────────
async def test_same_request_id_returns_same_response(client: AsyncClient) -> None:
    """동일 request_id 재전송 → byte-for-byte 동일 응답."""
    rid = str(uuid.uuid4())
    payload = _payload(request_id=rid, body="주민 900201-2320987")

    resp1 = await client.post("/v1/detect/post", json=payload)
    resp2 = await client.post("/v1/detect/post", json=payload)

    data1 = resp1.json()
    data2 = resp2.json()

    # request_id / verdict / code / detections 모두 동일.
    assert data1["request_id"] == data2["request_id"]
    assert data1["verdict"] == data2["verdict"]
    assert data1["code"] == data2["code"]
    # detections 도 동일 (분석 미반복 — 캐시 hit).
    assert data1["detections"] == data2["detections"]


async def test_same_request_id_with_different_body_returns_cached(
    client: AsyncClient,
) -> None:
    """같은 request_id 면 body 가 달라도 첫 응답이 반환된다 (멱등 정책).

    클라이언트 측에서 같은 request_id 로 다른 body 를 보내면 안 되지만,
    실수로 그런 일이 일어나면 처음 호출의 결과만 유효 — 두 번째 body 의
    PII 검사는 수행되지 않는다는 핀(pin).
    """
    rid = str(uuid.uuid4())
    first = await client.post(
        "/v1/detect/post",
        json=_payload(request_id=rid, body="안녕"),
    )
    second = await client.post(
        "/v1/detect/post",
        json=_payload(request_id=rid, body="주민 900201-2320987"),  # PII 들어옴
    )
    # 첫 응답이 PASS 였으면 두 번째도 PASS 로 캐시 hit.
    assert first.json()["verdict"] == second.json()["verdict"]
    assert first.json()["code"] == second.json()["code"]


async def test_different_request_ids_independent(client: AsyncClient) -> None:
    """서로 다른 request_id 는 독립 호출 — cache miss."""
    rid_a = str(uuid.uuid4())
    rid_b = str(uuid.uuid4())
    body_clean = "안녕하세요"
    body_pii = "주민 900201-2320987"

    a = await client.post("/v1/detect/post", json=_payload(request_id=rid_a, body=body_clean))
    b = await client.post("/v1/detect/post", json=_payload(request_id=rid_b, body=body_pii))

    assert a.json()["verdict"] == "PASS"
    assert b.json()["verdict"] == "BLOCK"


async def test_cache_persists_block_response(client: AsyncClient) -> None:
    """BLOCK 응답도 동일하게 캐시됨 — 재전송 시 같은 BLOCK 코드 반환."""
    rid = str(uuid.uuid4())
    payload = _payload(request_id=rid, body="주민 900201-2320987")

    resp1 = await client.post("/v1/detect/post", json=payload)
    resp2 = await client.post("/v1/detect/post", json=payload)

    assert resp1.json()["code"] == "BLOCK-2001"
    assert resp2.json()["code"] == "BLOCK-2001"


async def test_cache_persists_error_response(client: AsyncClient) -> None:
    """validation error 응답도 캐시 동작 — 동일 request_id 재전송 시 같은 코드.

    단, validation error 가 발생하면 cache 에 안 들어갈 수도 있음 (정책상
    유효 응답만 캐시). 회귀 가드: 적어도 두 호출의 결과 일관성.
    """
    rid = str(uuid.uuid4())
    payload = _payload(request_id=rid)
    payload["post"] = {"board_id": "free"}  # body / title 누락

    resp1 = await client.post("/v1/detect/post", json=payload)
    resp2 = await client.post("/v1/detect/post", json=payload)

    # 둘 다 같은 error 코드.
    assert resp1.json()["code"] == resp2.json()["code"]


# ── cache clear 후 동작 ────────────────────────────────────────────────
async def test_cache_clear_releases_request_id(client: AsyncClient) -> None:
    """cache 를 비우면 같은 request_id 재호출이 새 분석 — clear 가 효과 있음."""
    from app.security.idempotency import get_cache

    rid = str(uuid.uuid4())
    payload = _payload(request_id=rid, body="안녕")

    resp1 = await client.post("/v1/detect/post", json=payload)
    get_cache().clear()
    resp2 = await client.post("/v1/detect/post", json=payload)

    # 둘 다 PASS 지만 processed_at 시각이 다를 것 (재분석).
    assert resp1.json()["processed_at"] != resp2.json()["processed_at"]


# ── request_id 가 UUID 인지만 검증 (멱등 키 형식) ─────────────────────
async def test_request_id_zero_uuid_works(client: AsyncClient) -> None:
    """`00000000-...` 형태도 유효한 UUID — 멱등 키로 동작."""
    rid = "00000000-0000-0000-0000-000000000001"
    payload = _payload(request_id=rid)
    resp = await client.post("/v1/detect/post", json=payload)
    assert resp.status_code == 200
    assert resp.json()["request_id"] == rid


async def test_request_id_case_insensitive_uuid(client: AsyncClient) -> None:
    """UUID 의 hex 부분이 대문자여도 동일하게 처리."""
    rid_lower = "11111111-2222-3333-4444-555555555555"
    rid_upper = rid_lower.upper()

    a = await client.post("/v1/detect/post", json=_payload(request_id=rid_lower))
    # 대문자 UUID 도 lower-case 와 동일 키로 인식 → 캐시 hit.
    b = await client.post("/v1/detect/post", json=_payload(request_id=rid_upper))
    # 같은 응답 반환.
    assert a.json()["request_id"] == b.json()["request_id"]


# ── 멱등 캐시 + multi-PII ────────────────────────────────────────────
async def test_multi_pii_block_2008_is_cached(client: AsyncClient) -> None:
    """multi-PII BLOCK-2008 응답도 캐시되어 재호출 시 동일."""
    rid = str(uuid.uuid4())
    payload = _payload(
        request_id=rid,
        body="주민 900201-2320987 / 카드 4242-4242-4242-4242",
    )
    a = await client.post("/v1/detect/post", json=payload)
    b = await client.post("/v1/detect/post", json=payload)

    assert a.json()["code"] == "BLOCK-2008"
    assert b.json()["code"] == "BLOCK-2008"
    # detections 도 동일하게 반환.
    assert a.json()["detections"] == b.json()["detections"]


# ── processed_at 캐시 hit 시 동일 ──────────────────────────────────────
async def test_cached_response_keeps_original_processed_at(
    client: AsyncClient,
) -> None:
    """캐시 hit 시 processed_at 도 원본 응답 그대로 — 시각이 재계산되지 않음.

    이 검증으로 "캐시가 동작" vs "재분석 + 같은 결과 우연" 을 구분.
    """
    rid = str(uuid.uuid4())
    payload = _payload(request_id=rid, body="안녕")

    a = await client.post("/v1/detect/post", json=payload)
    # 작은 시간 차이 후 재호출 — 캐시 동작 시 processed_at 동일.
    b = await client.post("/v1/detect/post", json=payload)

    assert a.json()["processed_at"] == b.json()["processed_at"]


# ── 24h TTL 정상 동작 ─────────────────────────────────────────────────
async def test_idempotency_default_ttl_is_24h_in_module() -> None:
    """캐시 TTL 이 정확히 24시간 (§2.6)."""
    from datetime import timedelta

    from app.security.idempotency import DEFAULT_TTL

    assert timedelta(hours=24) == DEFAULT_TTL


# ── concurrent invocation pattern ──────────────────────────────────────
async def test_repeated_calls_with_same_id_return_same_payload(
    client: AsyncClient,
) -> None:
    """10회 반복 호출에서도 모두 첫 호출과 같은 응답이 나오는지."""
    rid = str(uuid.uuid4())
    payload = _payload(request_id=rid, body="주민 900201-2320987")

    first = await client.post("/v1/detect/post", json=payload)
    first_data = first.json()

    for _ in range(9):
        resp = await client.post("/v1/detect/post", json=payload)
        data = resp.json()
        assert data["processed_at"] == first_data["processed_at"], (
            "캐시 hit 가 아니라 재분석된 듯 — processed_at 변동"
        )
        assert data["code"] == first_data["code"]
