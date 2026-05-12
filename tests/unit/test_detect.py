"""Phase 1d — `POST /v1/detect/post` 핸들러 회귀 방지 (T1.18~T1.28).

ASGI 인-프로세스 클라이언트 (`client` fixture) 로 실제 미들웨어 체인을
거쳐 검사 엔드포인트를 호출한다. 검증 영역:

- Case A/B 분기 (본문 BLOCK 즉시 거절 / 본문 PASS 즉시 응답)
- 본문 BLOCK 시 user_message 가 §2.5 금지어 (entity 코드 / score) 를
  노출하지 않음
- 첨부 필드 형태 (`null` / `[]` / 누락) 가 모두 Case B 로 안전 분기
- 본문 / 제목 길이 한도 (REQ-4030)
- 분석 처리 시간 한도 (SVR-5006)
- 멱등성 (`request_id` 재전송 시 원본 응답 캐시 반환)
- 검증 envelope (UUID 형식 위반 / 필수 필드 누락 → REQ-4004 / REQ-4001)
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any
from uuid import uuid4

import pytest

from app.security.idempotency import get_cache
from tests.fixtures.synthetic_pii_generator import SyntheticPIIGenerator

if TYPE_CHECKING:
    from httpx import AsyncClient


def _payload(
    *,
    title: str = "문의드립니다",
    body: str = "안녕하세요. 단순 문의입니다.",
    strictness: str = "medium",
    attachments: object = None,
    callback_url: str | None = None,
) -> dict[str, Any]:
    base: dict[str, Any] = {
        "request_id": str(uuid4()),
        "author": {
            "name": "테스트사용자",
            "user_id": "u-001",
            "ip": "203.0.113.7",
            "is_anonymous": False,
        },
        "post": {"board_id": "qna", "title": title, "body": body},
        "options": {"strictness": strictness},
    }
    if attachments is not None:
        base["attachments"] = attachments
    if callback_url is not None:
        base["callback_url"] = callback_url
    return base


@pytest.fixture(autouse=True)
def _clear_idempotency_cache() -> None:
    """Reset the in-memory cache between tests."""
    get_cache().clear()


# ── T1.18: 본문 BLOCK + 첨부 없음 → HTTP 200 + BLOCK (Case A) ───────────
async def test_t1_18_block_no_attachments(client: AsyncClient) -> None:
    """본문에 유효 RRN 이 있으면 즉시 BLOCK-2001 응답하고, user_message 에는
    entity 코드 (`kr_rrn`) 나 score 같은 내부 디테일이 새지 않아야 한다.

    Case A (BLOCK + 첨부 없음) — 첨부 워커를 띄우지 않고 동기 응답.
    """
    g = SyntheticPIIGenerator(seed=101)
    rrn = g.gen_rrn(valid=True)
    payload = _payload(body=f"주민등록번호 {rrn} 입니다.")

    r = await client.post("/v1/detect/post", json=payload)
    assert r.status_code == 200
    data = r.json()
    assert data["verdict"] == "BLOCK"
    assert data["code"] == "BLOCK-2001"
    # user_message §2.5 안전성: entity 코드/score 누출 금지
    msg = data["user_message"].lower()
    assert "kr_rrn" not in msg
    assert "score" not in msg


# ── T1.19: 본문 PASS + 첨부 없음 → HTTP 200 + PASS (Case B) ──────────────
async def test_t1_19_pass_no_attachments(client: AsyncClient) -> None:
    """평범한 문의글 → 즉시 OK-0000 + PASS 응답 (Case B).

    가장 흔한 happy path. 게시판 트래픽의 대부분이 이 경로를 탄다.
    """
    payload = _payload(body="안녕하세요. 도서관 운영 시간이 어떻게 되는지 문의드립니다.")
    r = await client.post("/v1/detect/post", json=payload)
    assert r.status_code == 200
    data = r.json()
    assert data["verdict"] == "PASS"
    assert data["code"] == "OK-0000"


# ── T1.20 (Phase 9D): 전화번호 단독 — WARN 폐기 후 BLOCK 또는 PASS ──────
async def test_t1_20_phone_blocks_in_phase9d(client: AsyncClient) -> None:
    """전화번호만 본문에 있을 때 verdict 가 BLOCK 또는 PASS 두 중 하나여야 한다.

    Phase 9D 이전엔 WARN-1001 로 분류되던 케이스가 임계값 이상이면 BLOCK,
    미만이면 PASS 로 흡수된다. 결과 코드가 `OK-0000` 또는 `BLOCK-2099` 외의
    값으로 떨어지면 회귀.
    """
    g = SyntheticPIIGenerator(seed=103)
    phone = g.gen_phone()
    payload = _payload(body=f"연락처는 {phone} 입니다.")

    r = await client.post("/v1/detect/post", json=payload)
    assert r.status_code == 200
    data = r.json()
    # phone score 가 임계값 미만이면 PASS, 이상이면 BLOCK 만 허용.
    assert data["verdict"] in {"BLOCK", "PASS"}
    assert data["code"] in {"OK-0000", "BLOCK-2099"}


# ── T1.21: 여러 entity 동시 검출 → 가장 강한 verdict 가 이긴다 ──────────
async def test_t1_21_strongest_verdict_wins(client: AsyncClient) -> None:
    """RRN (BLOCK) + 전화번호 (PASS 또는 BLOCK) → 최종 verdict 는 BLOCK.

    혼합 입력에서 PASS 가 BLOCK 을 가리지 않도록 (가장 강한 verdict 채택)
    하는 우선순위 로직을 검증.
    """
    g = SyntheticPIIGenerator(seed=107)
    rrn = g.gen_rrn(valid=True)
    phone = g.gen_phone()
    payload = _payload(body=f"주민등록번호 {rrn}, 연락처 {phone} 입니다.")

    r = await client.post("/v1/detect/post", json=payload)
    assert r.status_code == 200
    data = r.json()
    # RRN 은 BLOCK, 전화번호는 PASS/WARN — 최종 verdict 는 BLOCK
    assert data["verdict"] == "BLOCK"


# ── T1.22: 서로 다른 BLOCK entity 가 2종 이상 → BLOCK-2008 (복합 PII) ───
async def test_t1_22_multi_block_uses_2008(client: AsyncClient) -> None:
    """RRN + 신용카드 동시 검출 → 복합 PII 전용 코드 `BLOCK-2008` 응답.

    단일 entity 의 전용 코드 (예: BLOCK-2001 - RRN) 대신 복합 PII 를 알리는
    `BLOCK-2008` 이 떨어져야 함. 운영자가 "단일 PII" 와 "복합 PII" 사고를
    구분 집계할 때 이 코드 차이를 사용한다.
    """
    g = SyntheticPIIGenerator(seed=109)
    rrn = g.gen_rrn(valid=True)
    card = g.gen_credit_card(brand="visa")
    payload = _payload(body=f"주민등록번호 {rrn}, 카드번호 {card} 입니다.")

    r = await client.post("/v1/detect/post", json=payload)
    assert r.status_code == 200
    data = r.json()
    assert data["verdict"] == "BLOCK"
    assert data["code"] == "BLOCK-2008"


# ── T1.23: `attachments` 키 자체가 빠진 경우 → 동기 (Case B) ─────────────
async def test_t1_23_attachments_absent(client: AsyncClient) -> None:
    """payload 에 `attachments` 키가 아예 없으면 첨부 없음으로 간주.

    `has_attachments` 가 False 가 되어 Case B 동기 응답으로 떨어져야 한다.
    실수로 KeyError 가 나면 즉시 회귀.
    """
    payload = _payload()
    payload.pop("attachments", None)  # 키 부재 보장
    r = await client.post("/v1/detect/post", json=payload)
    assert r.status_code == 200
    assert r.json()["verdict"] == "PASS"


# ── T1.24: `attachments: null` → 동기 (Case B) ──────────────────────────
async def test_t1_24_attachments_null(client: AsyncClient) -> None:
    """`attachments: null` 도 첨부 없음과 동일하게 취급한다 (§2.8 edge case).

    pydantic field_validator 의 `_normalize_attachments` 가 `None` 을
    그대로 통과시키고, `has_attachments` 가 False 가 되어 Case B 분기.
    """
    payload = _payload(attachments=None)
    payload["attachments"] = None  # 명시
    r = await client.post("/v1/detect/post", json=payload)
    assert r.status_code == 200
    assert r.json()["verdict"] == "PASS"


# ── T1.25: `attachments: []` (빈 리스트) → 동기 (Case B) ────────────────
async def test_t1_25_attachments_empty(client: AsyncClient) -> None:
    """빈 리스트도 첨부 없음 — null / 누락과 동일 (§2.8 edge case).

    클라이언트가 어떤 형태로 보내든 (`null`, `[]`, 누락) 결과가 같아야
    멱등성 이슈 / 클라이언트 호환 문제를 일으키지 않는다.
    """
    payload = _payload(attachments=[])
    r = await client.post("/v1/detect/post", json=payload)
    assert r.status_code == 200
    assert r.json()["verdict"] == "PASS"


# ── T1.26: 제목 길이 초과 (>500) → REQ-4030 (HTTP 413) ──────────────────
async def test_t1_26_title_too_long(client: AsyncClient) -> None:
    """501자 제목을 보내면 pydantic 검증보다 우선해서 REQ-4030 으로 떨어진다.

    pydantic 의 422 가 아닌 의도된 413 코드 (`REQ-4030`) 로 매핑되어
    클라이언트가 "본문/제목이 너무 김" 을 즉시 식별 가능해야 한다.
    """
    payload = _payload(title="가" * 501)
    r = await client.post("/v1/detect/post", json=payload)
    assert r.status_code == 413
    assert r.json()["code"] == "REQ-4030"


# ── T1.27: 본문 길이 초과 (>50,000) → REQ-4030 (HTTP 413) ───────────────
async def test_t1_27_body_too_long(client: AsyncClient) -> None:
    """50,001자 본문도 동일하게 REQ-4030 / HTTP 413.

    한도값이 바뀌면 이 테스트가 즉시 잡아낸다 (구현과 스펙의 sync 가드).
    """
    payload = _payload(body="가" * 50_001)
    r = await client.post("/v1/detect/post", json=payload)
    assert r.status_code == 413
    assert r.json()["code"] == "REQ-4030"


# ── T1.28: 본문 분석 처리 시간 초과 → SVR-5006 (HTTP 504) ───────────────
async def test_t1_28_processing_timeout(
    client: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """분석기를 일부러 느리게 만들고 5초 예산 초과 시 SVR-5006 매핑되는지.

    실제 5초를 기다리지 않도록 `BODY_TIMEOUT_SECONDS` 를 0.2초로 줄이고
    `asyncio.to_thread` 를 1초 대기 stub 으로 교체. 시간 예산이 깨지면
    `SVR-5006` (HTTP 504) 으로 떨어져 클라이언트가 retry 분기를 탈 수
    있어야 한다.
    """
    from app.api import detect as detect_module

    def slow_analyze(text: str, *, field: str, strictness: str) -> list[Any]:
        # Block longer than the 5 s timeout to trip asyncio.timeout
        import time as _t

        _t.sleep(6.0)
        return []

    monkeypatch.setattr(detect_module, "_analyze_field", slow_analyze)
    # Tighten the timeout so the test doesn't actually take 6 s.
    monkeypatch.setattr(detect_module, "BODY_TIMEOUT_SECONDS", 0.2)

    async def fast_sleep(text: str, *, field: str, strictness: str) -> list[Any]:
        await asyncio.sleep(1.0)  # > 0.2 s timeout
        return []

    # Replace the threaded analyze with one that triggers timeout reliably.
    async def patched_to_thread(func: object, *args: object, **kwargs: object) -> Any:
        await asyncio.sleep(1.0)
        return []

    monkeypatch.setattr(asyncio, "to_thread", patched_to_thread)

    payload = _payload(body="안녕하세요.")
    r = await client.post("/v1/detect/post", json=payload)
    assert r.status_code == 504
    assert r.json()["code"] == "SVR-5006"


# ── 멱등성: 동일 `request_id` 재전송 시 캐시된 원본 응답 반환 ─────────────
async def test_idempotency_replay_returns_cached(client: AsyncClient) -> None:
    """같은 payload 를 두 번 보내면 두 응답이 동일해야 한다 (request_id 단위 캐시).

    네트워크 오류로 클라이언트가 재시도해도 중복 검사·중복 차단이 일어
    나지 않도록 24시간 idempotency 캐시가 첫 응답을 그대로 돌려준다.
    """
    g = SyntheticPIIGenerator(seed=131)
    rrn = g.gen_rrn(valid=True)
    payload = _payload(body=f"주민등록번호 {rrn} 입니다.")

    r1 = await client.post("/v1/detect/post", json=payload)
    r2 = await client.post("/v1/detect/post", json=payload)
    assert r1.status_code == r2.status_code == 200
    assert r1.json()["request_id"] == r2.json()["request_id"]
    assert r1.json()["code"] == r2.json()["code"]


# ── 검증 envelope: 잘못된 UUID → REQ-4004 ────────────────────────────────
async def test_invalid_uuid_returns_req_4004(client: AsyncClient) -> None:
    """`request_id` 가 UUID 형식이 아니면 즉시 REQ-4004 (HTTP 400).

    내부 멱등성 캐시 키가 UUID 라는 점을 외부에 안내. pydantic 의 일반
    422 가 아닌 의도된 REQ-4004 로 매핑되어야 한다.
    """
    payload = _payload()
    payload["request_id"] = "not-a-uuid"
    r = await client.post("/v1/detect/post", json=payload)
    assert r.status_code == 400
    assert r.json()["code"] == "REQ-4004"


# ── 검증 envelope: 필수 필드 누락 → REQ-4001 ─────────────────────────────
async def test_missing_required_field_returns_req_4001(client: AsyncClient) -> None:
    """`post` 처럼 필수 필드를 빠뜨리면 REQ-4001 (필수 필드 누락) 로 응답.

    어떤 필드가 빠졌는지 클라이언트 입장에서 즉시 진단할 수 있도록
    422 대신 의미가 분명한 REQ-4001 코드로 매핑.
    """
    payload = _payload()
    payload.pop("post")
    r = await client.post("/v1/detect/post", json=payload)
    assert r.status_code == 400
    assert r.json()["code"] == "REQ-4001"
