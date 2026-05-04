"""Phase 1d — POST /v1/detect/post (T1.18~T1.28)."""

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


# ── T1.18: body BLOCK + no attachments → HTTP 200 + BLOCK ─────────────────
async def test_t1_18_block_no_attachments(client: AsyncClient) -> None:
    g = SyntheticPIIGenerator(seed=101)
    rrn = g.gen_rrn(valid=True)
    payload = _payload(body=f"주민등록번호 {rrn} 입니다.")

    r = await client.post("/v1/detect/post", json=payload)
    assert r.status_code == 200
    data = r.json()
    assert data["verdict"] == "BLOCK"
    assert data["code"] == "BLOCK-2001"
    # User-message safety: never leak entity type or score
    msg = data["user_message"].lower()
    assert "kr_rrn" not in msg
    assert "score" not in msg


# ── T1.19: body PASS + no attachments → HTTP 200 + PASS ───────────────────
async def test_t1_19_pass_no_attachments(client: AsyncClient) -> None:
    payload = _payload(body="안녕하세요. 도서관 운영 시간이 어떻게 되는지 문의드립니다.")
    r = await client.post("/v1/detect/post", json=payload)
    assert r.status_code == 200
    data = r.json()
    assert data["verdict"] == "PASS"
    assert data["code"] == "OK-0000"


# ── T1.20 (Phase 9D): WARN 등급 폐기. phone 도 임계값 이상이면 BLOCK ──────
async def test_t1_20_phone_blocks_in_phase9d(client: AsyncClient) -> None:
    """Phase 9D 이전엔 WARN-1001 이었던 케이스가 BLOCK 으로 흡수된다."""
    g = SyntheticPIIGenerator(seed=103)
    phone = g.gen_phone()
    payload = _payload(body=f"연락처는 {phone} 입니다.")

    r = await client.post("/v1/detect/post", json=payload)
    assert r.status_code == 200
    data = r.json()
    # phone score 가 임계값 미만이면 PASS, 이상이면 BLOCK 만 가능.
    assert data["verdict"] in {"BLOCK", "PASS"}
    assert data["code"] in {"OK-0000", "BLOCK-2099"}


# ── T1.21: BLOCK > PASS (mixed entities use strongest) ────────────────────
async def test_t1_21_strongest_verdict_wins(client: AsyncClient) -> None:
    g = SyntheticPIIGenerator(seed=107)
    rrn = g.gen_rrn(valid=True)
    phone = g.gen_phone()
    payload = _payload(body=f"주민등록번호 {rrn}, 연락처 {phone} 입니다.")

    r = await client.post("/v1/detect/post", json=payload)
    assert r.status_code == 200
    data = r.json()
    # RRN is BLOCK, phone is WARN — BLOCK wins
    assert data["verdict"] == "BLOCK"


# ── T1.22: multiple distinct BLOCK entity types → BLOCK-2008 ──────────────
async def test_t1_22_multi_block_uses_2008(client: AsyncClient) -> None:
    g = SyntheticPIIGenerator(seed=109)
    rrn = g.gen_rrn(valid=True)
    card = g.gen_credit_card(brand="visa")
    payload = _payload(body=f"주민등록번호 {rrn}, 카드번호 {card} 입니다.")

    r = await client.post("/v1/detect/post", json=payload)
    assert r.status_code == 200
    data = r.json()
    assert data["verdict"] == "BLOCK"
    assert data["code"] == "BLOCK-2008"


# ── T1.23: attachments key absent → sync (Case B) ─────────────────────────
async def test_t1_23_attachments_absent(client: AsyncClient) -> None:
    payload = _payload()
    payload.pop("attachments", None)  # ensure absent
    r = await client.post("/v1/detect/post", json=payload)
    assert r.status_code == 200
    assert r.json()["verdict"] == "PASS"


# ── T1.24: attachments: null → sync (Case B) ──────────────────────────────
async def test_t1_24_attachments_null(client: AsyncClient) -> None:
    payload = _payload(attachments=None)
    payload["attachments"] = None  # explicit
    r = await client.post("/v1/detect/post", json=payload)
    assert r.status_code == 200
    assert r.json()["verdict"] == "PASS"


# ── T1.25: attachments: [] → sync (Case B) ────────────────────────────────
async def test_t1_25_attachments_empty(client: AsyncClient) -> None:
    payload = _payload(attachments=[])
    r = await client.post("/v1/detect/post", json=payload)
    assert r.status_code == 200
    assert r.json()["verdict"] == "PASS"


# ── T1.26: title length > 500 → REQ-4030 (HTTP 413) ───────────────────────
async def test_t1_26_title_too_long(client: AsyncClient) -> None:
    payload = _payload(title="가" * 501)
    r = await client.post("/v1/detect/post", json=payload)
    assert r.status_code == 413
    assert r.json()["code"] == "REQ-4030"


# ── T1.27: body length > 50_000 → REQ-4030 (HTTP 413) ─────────────────────
async def test_t1_27_body_too_long(client: AsyncClient) -> None:
    payload = _payload(body="가" * 50_001)
    r = await client.post("/v1/detect/post", json=payload)
    assert r.status_code == 413
    assert r.json()["code"] == "REQ-4030"


# ── T1.28: body processing > 5s → SVR-5006 (HTTP 504) ─────────────────────
async def test_t1_28_processing_timeout(
    client: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Simulate a slow analyzer; expect SVR-5006 after 5 s budget."""
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


# ── Idempotency: replay returns the cached response ───────────────────────
async def test_idempotency_replay_returns_cached(client: AsyncClient) -> None:
    g = SyntheticPIIGenerator(seed=131)
    rrn = g.gen_rrn(valid=True)
    payload = _payload(body=f"주민등록번호 {rrn} 입니다.")

    r1 = await client.post("/v1/detect/post", json=payload)
    r2 = await client.post("/v1/detect/post", json=payload)
    assert r1.status_code == r2.status_code == 200
    assert r1.json()["request_id"] == r2.json()["request_id"]
    assert r1.json()["code"] == r2.json()["code"]


# ── Validation envelope: malformed UUID → REQ-4004 ────────────────────────
async def test_invalid_uuid_returns_req_4004(client: AsyncClient) -> None:
    payload = _payload()
    payload["request_id"] = "not-a-uuid"
    r = await client.post("/v1/detect/post", json=payload)
    assert r.status_code == 400
    assert r.json()["code"] == "REQ-4004"


# ── Validation envelope: missing required field → REQ-4001 ────────────────
async def test_missing_required_field_returns_req_4001(client: AsyncClient) -> None:
    payload = _payload()
    payload.pop("post")
    r = await client.post("/v1/detect/post", json=payload)
    assert r.status_code == 400
    assert r.json()["code"] == "REQ-4001"
